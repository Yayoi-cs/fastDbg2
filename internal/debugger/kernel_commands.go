package debugger

import (
	"context"
	"fmt"
	"strings"

	"fastdbg2/display"
	"fastdbg2/qemu"
	qamd64 "fastdbg2/qemu/amd64"
	"fastdbg2/target"
)

type QEMUOptions struct {
	Address, VMLinux string
	Slide            uint64
	SlideSet         bool
}

func (c *Controller) ConnectQEMU(ctx context.Context, options QEMUOptions) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	if options.SlideSet && options.VMLinux == "" {
		return fmt.Errorf("kernel slide requires vmlinux: %w", target.ErrInvalidArgument)
	}
	if c.session != nil {
		return target.ErrInvalidState
	}
	if options.VMLinux != "" && !options.SlideSet {
		return fmt.Errorf("--vmlinux requires explicit --kernel-slide (0 for nokaslr): %w", target.ErrInvalidArgument)
	}
	var image *kernelImage
	var err error
	if options.VMLinux != "" {
		image, err = openKernelImage(ctx, options.VMLinux, options.Slide)
		if err != nil {
			return err
		}
	}
	var remote *qemu.Session
	if strings.HasPrefix(options.Address, "unix:") {
		remote, err = qemu.ConnectUnix(strings.TrimPrefix(options.Address, "unix:"))
	} else {
		remote, err = qemu.Connect(options.Address)
	}
	if err != nil {
		if image != nil {
			image.Close()
		}
		return err
	}
	session, err := newQemuSession(remote, image)
	if err != nil {
		remote.Close()
		if image != nil {
			image.Close()
		}
		return err
	}
	c.session = session
	c.arch = target.AMD64
	c.path = options.VMLinux
	c.selected = target.ThreadRef{Session: session.id, ID: session.cpu}
	c.owned = false
	_, err = c.refresh()
	return err
}

func (s *qemuSession) paging(token target.ThreadToken) (qamd64.Paging, error) {
	registers, err := s.ReadThreadRegisters(token)
	if err != nil {
		return qamd64.Paging{}, err
	}
	var values [4]uint64
	for i, name := range []string{"cr0", "cr3", "cr4", "efer"} {
		values[i], err = contextRegisterValue(registers, name)
		if err != nil {
			return qamd64.Paging{}, err
		}
	}
	return qamd64.Paging{CR0: values[0], CR3: values[1], CR4: values[2], EFER: values[3]}, nil
}
func (s *qemuSession) addressWalkMaps(ctx context.Context, snapshot target.Snapshot, thread target.ThreadInfo) ([]procMap, error) {
	s.mu.Lock()
	if err := s.requireMemory(snapshot.Memory); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	cached := s.mapRevision == snapshot.Memory.Revision && s.maps != nil
	maps := s.maps
	s.mu.Unlock()
	if cached {
		return maps, ctx.Err()
	}
	paging, err := s.paging(thread.Token)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireMemory(snapshot.Memory); err != nil {
		return nil, err
	}
	pages, err := paging.Mappings(ctx, s.remote.ReadPhysicalMemory)
	if err != nil {
		return nil, err
	}
	maps = make([]procMap, 0, len(pages))
	for _, p := range pages {
		name := "[supervisor]"
		if p.User {
			name = "[user]"
		}
		maps = append(maps, procMap{Start: target.Address(p.Virtual), End: target.Address(p.Virtual + p.Size), Offset: p.Physical, Read: true, Write: p.Write, Execute: p.Execute, Path: name})
	}
	s.maps = maps
	s.mapRevision = snapshot.Memory.Revision
	return maps, nil
}

var kernelCommandSpecs = []commandSpec{
	{"pagetable", "EXPR", "Walk the selected vCPU's actual AMD64 page tables.", []string{"pt", "PT", "PAGETABLE"}},
	{"kbase", "", "Show the explicit vmlinux image base and relocation slide.", []string{"KBASE"}},
}

func (c *Controller) showPageTable(ctx context.Context, args string) error {
	s, ok := c.session.(*qemuSession)
	if !ok {
		return fmt.Errorf("pagetable requires QEMU system debugging: %w", target.ErrUnsupported)
	}
	snapshot, thread, err := c.stopped()
	if err != nil {
		return err
	}
	address, err := c.evaluate(ctx, args, snapshot, thread)
	if err != nil {
		return err
	}
	paging, err := s.paging(thread.Token)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if err = s.requireMemory(snapshot.Memory); err != nil {
		s.mu.Unlock()
		return err
	}
	result, walkErr := paging.Translate(ctx, uint64(address), s.remote.ReadPhysicalMemory)
	s.mu.Unlock()
	if err := c.verifyProcSnapshot(snapshot, thread); err != nil {
		return err
	}
	if err := c.writef("%s\nVirtual: %s  CR3: %#x\n", c.renderer.Section("pagetable", display.OutputWidth(c.out)), c.renderer.Text(display.StyleCyan, fmt.Sprintf("0x%016x", address)), paging.CR3); err != nil {
		return err
	}
	for _, entry := range result.Entries {
		if err := c.writef("  L%d 0x%016x: 0x%016x\n", entry.Level, entry.Address, entry.Value); err != nil {
			return err
		}
	}
	if walkErr != nil {
		return walkErr
	}
	return c.writef("Physical: %s  Page: %#x  RW=%t US=%t NX=%t\n", c.renderer.Text(display.StyleCyan, fmt.Sprintf("0x%016x", result.Physical)), result.Page.Size, result.Page.Write, result.Page.User, !result.Page.Execute)
}
func (c *Controller) showKernelBase(args string) error {
	s, ok := c.session.(*qemuSession)
	if !ok {
		return target.ErrUnsupported
	}
	if strings.TrimSpace(args) != "" {
		return target.ErrInvalidArgument
	}
	if s.image == nil {
		return fmt.Errorf("kbase requires --vmlinux and explicit --kernel-slide: %w", target.ErrUnavailable)
	}
	if err := s.image.validate(); err != nil {
		return err
	}
	return c.writef("kbase = %s\n", c.renderer.Text(display.StyleCyan, fmt.Sprintf("0x%016x", s.image.base)))
}

func (c *Controller) kernelScope(ctx context.Context, snapshot target.Snapshot, thread target.ThreadInfo) (*stoppedSymbolScope, error) {
	s := c.session.(*qemuSession)
	if err := c.verifyProcSnapshot(snapshot, thread); err != nil {
		return nil, err
	}
	if s.image == nil {
		return &stoppedSymbolScope{}, nil
	}
	if err := s.image.validate(); err != nil {
		return nil, err
	}
	facts := s.image.facts()
	return &stoppedSymbolScope{modules: []moduleSymbolFacts{facts}, displaySymbols: s.image.symbols}, facts.err
}

func (c *Controller) showKernelMaps(ctx context.Context, snapshot target.Snapshot, thread target.ThreadInfo, maps []procMap, filter string) error {
	var output strings.Builder
	fmt.Fprintln(&output, c.renderer.Section("vmmap", display.OutputWidth(c.out)))
	fmt.Fprintln(&output, c.renderer.Text(display.StyleHeading, display.Wrap("Virtual start      Virtual end        Physical start     Size               Perm  Mode", display.OutputWidth(c.out), 4)))
	for _, m := range maps {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !strings.Contains(m.Path, filter) {
			continue
		}
		permissions := "r"
		if m.Write {
			permissions += "w"
		} else {
			permissions += "-"
		}
		if m.Execute {
			permissions += "x"
		} else {
			permissions += "-"
		}
		line := fmt.Sprintf("0x%016x 0x%016x 0x%016x 0x%016x %s   %s", m.Start, m.End, m.Offset, m.End-m.Start, permissions, m.Path)
		fmt.Fprintln(&output, c.renderer.PermissionText(display.Wrap(line, display.OutputWidth(c.out), 4), m.Read, m.Write, m.Execute))
	}
	return c.publishVMMap(ctx, snapshot, thread, output.String())
}

func (c *Controller) showQemuInfo(ctx context.Context) error {
	snapshot, thread, err := c.stopped()
	if err != nil {
		return err
	}
	if err := c.writef("%s\nBackend: QEMU system / amd64\nvCPUs: %d  Selected: %d\n", c.renderer.Section("proc-info", display.OutputWidth(c.out)), len(snapshot.Threads), thread.Ref.ID); err != nil {
		return err
	}
	return c.showRegisters(ctx, "-s cr0 cr2 cr3 cr4 cr8 efer")
}

func (c *Controller) showQemuSIMD(ctx context.Context, name string, index int, thread target.ThreadInfo) error {
	session := c.session.(*qemuSession)
	session.mu.Lock()
	if err := session.require(thread.Token); err != nil {
		session.mu.Unlock()
		return err
	}
	registers, err := session.remote.ReadRegisters()
	session.mu.Unlock()
	if err != nil {
		return err
	}
	values := make(map[string]target.Register)
	for _, reg := range registers {
		values[reg.Name] = reg
	}
	write := func(i int, wide bool) error {
		xmm, ok := values[fmt.Sprintf("xmm%d", i)]
		if !ok || !xmm.Available || len(xmm.Data) != 16 {
			return target.ErrUnavailable
		}
		if !wide {
			return c.writeXMM(ctx, i, xmm.Data)
		}
		upper, ok := values[fmt.Sprintf("ymm%dh", i)]
		if !ok || !upper.Available || len(upper.Data) != 16 {
			return fmt.Errorf("YMM upper lanes are not exposed by the remote XML: %w", target.ErrUnavailable)
		}
		return c.writeYMM(ctx, i, xmm.Data, upper.Data)
	}
	if index >= 0 {
		return write(index, name == "ymm")
	}
	if err := c.writef("%s\n", c.renderer.Section("XMM Registers", display.OutputWidth(c.out))); err != nil {
		return err
	}
	for i := 0; i < 16; i++ {
		if err := write(i, false); err != nil {
			return err
		}
	}
	if _, ok := values["ymm0h"]; ok {
		if err := c.writef("%s\n", c.renderer.Section("YMM Registers", display.OutputWidth(c.out))); err != nil {
			return err
		}
		for i := 0; i < 16; i++ {
			if err := write(i, true); err != nil {
				return err
			}
		}
	}
	if err := c.writef("%s\n", c.renderer.Section("x87 FPU Registers", display.OutputWidth(c.out))); err != nil {
		return err
	}
	for _, reg := range registers {
		if strings.HasPrefix(reg.Name, "st") || strings.HasPrefix(reg.Name, "f") && reg.Name != "fs" && reg.Name != "fs_base" {
			if !reg.Available {
				continue
			}
			if err := c.writef("%-6s: %s\n", reg.Name, simdHex(reg.Data)); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

func (c *Controller) qemuMode() bool { _, ok := c.session.(*qemuSession); return ok }

func kernelCommandAvailable(name string) bool {
	switch name {
	case "file", "attach", "kill", "fd", "stdio", "arena", "bins", "visual-heap":
		return false
	}
	return true
}

var kernelCommandDetails = map[string]string{
	"start":      "Display the current stopped VM context. This does not launch or reset QEMU.",
	"run":        "Alias for continuing the connected VM; no restart or guest arguments.",
	"continue":   "Resume the selected vCPU or all vCPUs according to scheduler-locking. Ctrl-C stops the VM. Guest exceptions are not injected as host signals.",
	"step":       "Execute one instruction on the selected vCPU; scheduler-locking controls peer execution. QEMU's configured single-step IRQ/timer mask is preserved.",
	"break":      "Use a numeric address, $register expression or exact vmlinux symbol. Breakpoint resume performs a selected-vCPU step-over and reinstalls the remote breakpoint. No native loader rendezvous is used.",
	"backtrace":  "Uses the explicitly supplied vmlinux: recognized ORC format first, DWARF CFI only when ORC is absent. Stops at missing metadata; no inferred frame-pointer or stack-scan fallback. --abi controls DWARF implicit register rules only; ORC rules are explicit.",
	"stackframe": "Show the actual ORC or DWARF recovery rules for one frame. Requires --vmlinux and --kernel-slide.",
	"vmmap":      "Enumerate actual present leaf mappings for the selected vCPU's CR3. Physical start is not a file offset. R/W/X are accumulated page-table permissions, not a promise that CPL/SMEP/SMAP/PKU permits access. Supports 4/5 levels and 4 KiB, 2 MiB, 1 GiB pages. FILTER matches [user] or [supervisor].",
	"proc-info":  "Show remote vCPU and paging-register information. No host /proc data or inferred guest task metadata.",
	"pagetable":  "Translate EXPR using CR0/CR3/CR4/EFER and physical page-table reads. Shows every entry and the final physical address. Physical memory mode is restored even after read failure.",
	"kbase":      "Show the lowest vmlinux PT_LOAD virtual address plus the explicitly supplied --kernel-slide. --kernel-slide 0 means linked/nokaslr addresses; the base is never guessed by probing memory.",
	"wp":         "Remote watchpoints apply to all vCPUs. Slots 0..3 are debugger-owned logical handles, not guest DR register allocations. Availability depends on the QEMU accelerator.",
	"simd":       "Show the selected vCPU's actual XML-described XMM/YMM and x87 registers. Missing remote registers are reported as unavailable, not synthesized as zero.",
	"detach":     "Remove debugger-owned remote breakpoints/watchpoints, detach and resume the VM. QEMU is not terminated.",
	"quit":       "Detach cleanly and leave QEMU running; EOF has the same cleanup behavior.",
}

func kernelCommandDescription(command commandSpec) commandSpec {
	switch command.name {
	case "start":
		command.description = "Display the current stopped VM context."
		command.arguments = ""
	case "run":
		command.description = "Continue the connected VM without restarting it."
		command.arguments = ""
	case "vmmap":
		command.description = "Show virtual-to-physical page-table mappings."
	case "proc-info":
		command.description = "Show remote vCPU and paging state."
	case "wp":
		command.description = "Manage VM-wide remote watchpoints."
	case "backtrace":
		command.description = "Unwind kernel frames using exact ORC or DWARF metadata."
	case "sym":
		command.description = "List symbols from the explicitly supplied vmlinux."
	}
	return command
}
