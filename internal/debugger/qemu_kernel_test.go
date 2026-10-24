package debugger

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fastdbg2/display"
	"fastdbg2/internal/cli"
	"fastdbg2/target"
)

func kernelFixture(t *testing.T) (*Controller, *bytes.Buffer) {
	t.Helper()
	for _, tool := range []string{"qemu-system-x86_64", "as", "ld"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " unavailable")
		}
	}
	dir := t.TempDir()
	for _, part := range []string{"boot", "kernel"} {
		mode := "--64"
		emulation := "elf_x86_64"
		if part == "boot" {
			mode = "--32"
			emulation = "elf_i386"
		}
		object := filepath.Join(dir, part+".o")
		image := filepath.Join(dir, part+".elf")
		for _, args := range [][]string{{"as", mode, "-g", "-o", object, "testdata/qemu/" + part + ".S"}, {"ld", "-m", emulation, "--build-id", "-T", "testdata/qemu/" + part + ".ld", "-o", image, object}} {
			if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
				t.Fatalf("%v: %v\n%s", args, err, out)
			}
		}
	}
	socket := kernelTestSocket(t)
	ctx, cancel := context.WithCancel(context.Background())
	command := exec.CommandContext(ctx, "qemu-system-x86_64", "-accel", "tcg", "-cpu", "max", "-m", "32M", "-smp", "2", "-S", "-display", "none", "-nodefaults", "-no-reboot", "-kernel", filepath.Join(dir, "boot.elf"), "-device", "loader,file="+filepath.Join(dir, "kernel.elf"), "-chardev", "socket,path="+socket+",server=on,wait=off,id=gdb0", "-gdb", "chardev:gdb0")
	var log bytes.Buffer
	command.Stderr = &log
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); command.Wait() })
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("QEMU socket unavailable")
		}
		time.Sleep(time.Millisecond)
	}
	var output bytes.Buffer
	controller := New(&output, display.Renderer{})
	if err := controller.ConnectQEMU(context.Background(), QEMUOptions{Address: "unix:" + socket, VMLinux: filepath.Join(dir, "kernel.elf"), SlideSet: true}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := controller.Close(); err != nil {
			t.Error(err)
		}
	})
	return controller, &output
}

func TestQEMUKernelLegacyCommands(t *testing.T) {
	c, out := kernelFixture(t)
	covered := make(map[string]bool)
	run := func(command string) string {
		t.Helper()
		out.Reset()
		name, args := cli.SplitCommand(command)
		spec, ok := canonicalCommand(name)
		if !ok {
			t.Fatal(command)
		}
		covered[spec.name] = true
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := c.Execute(ctx, name, args)
		if err != nil {
			t.Fatalf("%s: %v\n%s", command, err, out.String())
		}
		return out.String()
	}
	if _, err := c.Execute(context.Background(), "disass", ""); !errors.Is(err, target.ErrUnsupported) {
		t.Fatalf("firmware decoded as amd64: %v", err)
	}
	run("context off")
	run("start")
	run("b checkpoint")
	run("run")
	snapshot, thread, err := c.stopped()
	if err != nil {
		t.Fatal(err)
	}
	before, err := c.session.ReadCodeLocation(thread.Token)
	if err != nil {
		t.Fatal(err)
	}
	if before.Breakpoint == nil {
		t.Fatal("software stop not classified")
	}
	for _, command := range []string{
		"help", "help pagetable", "p $rip", "memory --count 16 scratch", "x/2gx scratch", "hexdump byte --count 16 scratch", "dw --count 4 scratch", "info registers rip rsp", "color", "! printf kernel-audit", "set scheduler-locking step", "show scheduler-locking", "set scheduler-locking replay", "disable 1", "enable 1", "db --count 16 scratch", "xxd scratch 16", "dd --count 4 scratch", "xxd dword scratch 4", "dq --count 4 scratch", "xxd qword scratch 4", "disass", "disass func checkpoint",
		"set scratch 0x8877665544332211", "set32 scratch+8 0x1234", "set16 scratch+12 0x5678", "set8 scratch+14 0x41", "set $rax 0x1234", "xor scratch+16 0x1234",
		"tel chain 1", "stack 4", "bt", "stackframe 1", "pt $rip", "PAGETABLE $rsp", "regs", "regs -s cr0 cr3 cr4 efer", "kbase", "search-string QEMU message message+16", "search-value --size 8 0x8877665544332211 scratch scratch+32",
		"vmmap", "sym checkpoint", "checksec", "got", "proc-info", "fs_base", "gs_base", "simd", "xmm 0", "ymm", "asm \"nop; ret\"", "cyclic 16", "findruction -n nop checkpoint checkpoint+2", "threads", "thread 2", "regs -s rip", "thread 1", "thread apply all regs -s rip", "context on", "context", "context off",
	} {
		run(command)
		t.Log(command)
	}
	if output := run("tel chain 1"); !strings.Contains(output, "QEMU-KERNEL-TEST") {
		t.Fatal(output)
	}
	if output := run("bt"); !strings.Contains(output, "<parent+") || !strings.Contains(output, "<_start+") {
		t.Fatal(output)
	}
	if output := run("kbase"); !strings.Contains(output, "0xffff800000200000") {
		t.Fatal(output)
	}
	if output := run("pt checkpoint"); !strings.Contains(output, "Page: 0x200000") {
		t.Fatal(output)
	}
	if output := run("pt 0x100000"); !strings.Contains(output, "Page: 0x1000") {
		t.Fatal(output)
	}
	if output := run("pt 0x40001234"); !strings.Contains(output, "Physical: 0x0000000040001234") || !strings.Contains(output, "Page: 0x40000000") {
		t.Fatal(output)
	}
	run("set scratch 0")
	run("set scratch+8 0x21")
	run("chunk --layout glibc-amd64 scratch")
	run("step")
	_, thread, err = c.stopped()
	if err != nil {
		t.Fatal(err)
	}
	after, err := c.session.ReadCodeLocation(thread.Token)
	if err != nil || after.RawPC != before.RawPC+1 {
		t.Fatalf("step-over: %+v %v", after, err)
	}
	if _, err := c.session.ReadSpaceMemory(snapshot.Memory, 0, make([]byte, 1)); !errors.Is(err, target.ErrStale) {
		t.Fatalf("stale memory: %v", err)
	}
	run("c")
	_, thread, err = c.stopped()
	if err != nil {
		t.Fatal(err)
	}
	again, err := c.session.ReadCodeLocation(thread.Token)
	if err != nil || again.RawPC != before.RawPC {
		t.Fatalf("second breakpoint: %+v %v", again, err)
	}
	run("wp scratch --size 8 --access write")
	run("wp list")
	run("b idle")
	run("c")
	if c.session.LastStop().Reason != target.StopWatchpoint {
		t.Fatalf("watchpoint stop: %+v", c.session.LastStop())
	}
	run("thread 2")
	run("wp d 0")
	run("thread 1")
	run("c")
	run("delete all")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := c.Execute(ctx, "continue", ""); err != nil {
		t.Fatal(err)
	}
	if c.session.State() != target.StateStopped || c.active != nil {
		t.Fatal("interrupt did not complete")
	}

	snapshot, _, err = c.stopped()
	if err != nil {
		t.Fatal(err)
	}
	op, err := c.session.Run(target.RunRequest{Threads: target.ThreadSet{Scope: target.ProcessThreads, Process: snapshot.Process}})
	if err != nil {
		t.Fatal(err)
	}
	c.active = op
	run("interrupt")
	for _, name := range []string{"fd", "stdio", "arena", "bins", "visual-heap", "kill"} {
		_, err := c.Execute(context.Background(), name, "")
		if !errors.Is(err, target.ErrUnsupported) {
			t.Fatalf("kernel %s: %v", name, err)
		}
	}
	run("detach")
	run("quit")
	for _, spec := range append(append([]commandSpec{}, commandSpecs...), kernelCommandSpecs...) {
		if kernelCommandAvailable(spec.name) && !covered[spec.name] {
			t.Errorf("kernel command not executed: %s", spec.name)
		}
	}
	t.Log(fmt.Sprintf("%d kernel-applicable commands executed", len(covered)))
}

func TestQEMULinuxKernelORC(t *testing.T) {
	kernel, image := os.Getenv("FASTDBG2_TEST_KERNEL"), os.Getenv("FASTDBG2_TEST_VMLINUX")
	if kernel == "" && image == "" {
		t.Skip("set FASTDBG2_TEST_KERNEL and FASTDBG2_TEST_VMLINUX for the Linux ORC test")
	}
	if kernel == "" || image == "" {
		t.Fatal("both Linux image paths are required")
	}
	socket := kernelTestSocket(t)
	ctx, cancel := context.WithCancel(context.Background())
	q := exec.CommandContext(ctx, "qemu-system-x86_64", "-accel", "tcg", "-cpu", "max", "-m", "512M", "-smp", "2", "-S", "-display", "none", "-nodefaults", "-no-reboot", "-kernel", kernel, "-append", "nokaslr console=ttyS0 panic=-1", "-chardev", "socket,path="+socket+",server=on,wait=off,id=gdb0", "-gdb", "chardev:gdb0")
	if err := q.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); q.Wait() })
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Linux QEMU startup timeout")
		}
		time.Sleep(time.Millisecond)
	}
	var output bytes.Buffer
	c := New(&output, display.Renderer{})
	if err := c.ConnectQEMU(context.Background(), QEMUOptions{Address: "unix:" + socket, VMLinux: image, SlideSet: true}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	run := func(line string) string {
		t.Helper()
		output.Reset()
		name, args := cli.SplitCommand(line)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := c.Execute(ctx, name, args); err != nil {
			t.Fatalf("%s: %v\n%s", line, err, output.String())
		}
		return output.String()
	}
	run("context off")
	run("b start_kernel")
	run("continue")
	if out := run("bt"); !strings.Contains(out, "<start_kernel>") || !strings.Contains(out, "x86_64_start_kernel") {
		t.Fatal(out)
	}
	if out := run("stackframe"); !strings.Contains(out, "ORC record") {
		t.Fatal(out)
	}
	run("pt $rip")
	run("vmmap")
	run("regs -s cr3 cr4 efer")
	run("context on")
	run("context")
	run("context off")
	snapshot, thread, err := c.stopped()
	if err != nil {
		t.Fatal(err)
	}
	s := c.session.(*qemuSession)
	paging, err := s.paging(thread.Token)
	if err != nil {
		t.Fatal(err)
	}
	loc, err := s.ReadCodeLocation(thread.Token)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := paging.Translate(context.Background(), uint64(loc.InstructionPC), s.remote.ReadPhysicalMemory)
	if err != nil {
		t.Fatal(err)
	}
	var virtual, physical [16]byte
	if n, err := s.ReadSpaceMemory(snapshot.Memory, loc.InstructionPC, virtual[:]); err != nil || n != len(virtual) {
		t.Fatal(n, err)
	}
	if n, err := s.remote.ReadPhysicalMemory(target.Address(tr.Physical), physical[:]); err != nil || n != len(physical) {
		t.Fatal(n, err)
	}
	if virtual != physical {
		t.Fatalf("page translation mismatch: %x %x", virtual, physical)
	}
	run("step")
	run("regs -s rip")
	run("bt")
}

func TestQEMUStepOverPreservesOtherStops(t *testing.T) {
	for _, watch := range []bool{false, true} {
		t.Run(fmt.Sprintf("watch_%t", watch), func(t *testing.T) {
			c, out := kernelFixture(t)
			run := func(line string) {
				t.Helper()
				out.Reset()
				name, args := cli.SplitCommand(line)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				if _, err := c.Execute(ctx, name, args); err != nil {
					t.Fatalf("%s: %v %s", line, err, out.String())
				}
			}
			run("context off")
			if watch {
				run("b write_checkpoint")
			} else {
				run("b checkpoint")
				run("b checkpoint+1")
			}
			run("c")
			if watch {
				run("wp scratch --size 8 --access write")
			}
			run("c")
			stop := c.session.LastStop()
			if watch {
				if stop.Reason != target.StopWatchpoint || len(stop.Watchpoints) != 1 {
					t.Fatalf("swallowed watchpoint during step-over: %+v", stop)
				}
			} else {
				snapshot, thread, err := c.stopped()
				if err != nil {
					t.Fatal(err)
				}
				address, err := c.evaluate(context.Background(), "checkpoint+1", snapshot, thread)
				if err != nil {
					t.Fatal(err)
				}
				if stop.Reason != target.StopBreakpoint || stop.Breakpoint == nil || *stop.Breakpoint != address {
					t.Fatalf("swallowed adjacent breakpoint: %+v", stop)
				}
			}
		})
	}
}

func kernelTestSocket(t *testing.T) string {
	t.Helper()
	root := filepath.Join("..", "..", ".cache")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(root, "qk-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return filepath.Join(dir, "gdb.sock")
}
