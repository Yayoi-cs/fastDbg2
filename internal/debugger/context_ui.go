package debugger

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"

	"fastdbg2/display"
	"fastdbg2/inspect"
	"fastdbg2/target"
	"golang.org/x/arch/x86/x86asm"
)

type addressWalkSymbolSource interface {
	addressWalkSymbols(context.Context, target.Snapshot, target.ThreadInfo) ([]inspect.Symbol, error)
}

type uiRegisterIdentity struct {
	thread target.ThreadRef
	space  target.SpaceRef
}

type uiRegisterHistory struct {
	stop     uint64
	revision uint64
	current  map[string]uint64
	previous map[string]uint64
}

func (c *Controller) addAddressSymbols(ctx context.Context, snapshot target.Snapshot, thread target.ThreadInfo, walker *addressWalker) error {
	source, ok := c.session.(addressWalkSymbolSource)
	if !ok || walker == nil {
		return nil
	}
	symbols, err := source.addressWalkSymbols(ctx, snapshot, thread)
	if uiDisplayFatal(err) {
		return err
	}
	walker.symbol = func(address target.Address) string {
		var exact, containing []string
		seen := make(map[string]bool)
		for i := range symbols {
			symbol := &symbols[i]
			if !symbol.AddressKnown || symbol.Section == elf.SHN_ABS || symbol.Name == "" || address < symbol.Address ||
				address != symbol.Address && uint64(address-symbol.Address) >= symbol.Size {
				continue
			}
			label := symbol.Name
			if address != symbol.Address {
				label += fmt.Sprintf("+0x%x", address-symbol.Address)
			}
			if seen[label] {
				continue
			}
			seen[label] = true
			if address == symbol.Address {
				exact = append(exact, label)
			} else {
				containing = append(containing, label)
			}
		}
		if len(seen) == 0 {
			return ""
		}
		slices.SortFunc(exact, uiCompareSymbolLabels)
		slices.SortFunc(containing, uiCompareSymbolLabels)
		labels := append(exact, containing...)
		text := strings.Join(labels[:min(3, len(labels))], " | ")
		if len(labels) > 3 {
			text += fmt.Sprintf(" | +%d more", len(labels)-3)
		}
		return text
	}
	return nil
}

func uiCompareSymbolLabels(a, b string) int {
	widthA, widthB := display.VisibleWidth(contextEscapedText(a)), display.VisibleWidth(contextEscapedText(b))
	if widthA < widthB {
		return -1
	}
	if widthA > widthB {
		return 1
	}
	return strings.Compare(a, b)
}

func uiDisplayFatal(err error) bool {
	return errors.Is(err, target.ErrStale) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func (c *Controller) displaySnapshotCurrent(ctx context.Context, snapshot target.Snapshot, thread target.ThreadInfo) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	if _, ok := c.session.(addressWalkMapSource); !ok && !c.contextScreen {
		return nil
	}
	current, err := c.session.Snapshot()
	if err != nil {
		return err
	}
	if !sameContextSnapshot(current, snapshot) {
		return fmt.Errorf("display snapshot changed: %w", target.ErrStale)
	}
	return validateImageSnapshot(current, thread)
}

func uiRegisterValues(registers []target.Register) map[string]uint64 {
	values := make(map[string]uint64, len(registers))
	duplicates := make(map[string]bool)
	for _, register := range registers {
		value, err := contextScalar(register)
		if err != nil || duplicates[register.Name] {
			continue
		}
		if _, exists := values[register.Name]; exists {
			delete(values, register.Name)
			duplicates[register.Name] = true
			continue
		}
		values[register.Name] = value
	}
	return values
}

func (c *Controller) changedRegisters(snapshot target.Snapshot, thread target.ThreadInfo, registers []target.Register) map[string]bool {
	history, ok := c.registerHistory[uiRegisterIdentity{thread.Ref, snapshot.Memory.Space}]
	if !ok {
		return nil
	}
	previous := history.previous
	if history.stop != thread.Token.Stop || history.revision != thread.Token.Registers {
		previous = history.current
	}
	changed := make(map[string]bool)
	for name, value := range uiRegisterValues(registers) {
		if old, exists := previous[name]; exists && old != value {
			changed[name] = true
		}
	}
	return changed
}

func (c *Controller) rememberRegisters(snapshot target.Snapshot, thread target.ThreadInfo, registers []target.Register) {
	key := uiRegisterIdentity{thread.Ref, snapshot.Memory.Space}
	history, exists := c.registerHistory[key]
	if c.registerHistory == nil {
		c.registerHistory = make(map[uiRegisterIdentity]uiRegisterHistory)
	} else if !exists && len(c.registerHistory) >= 256 {
		clear(c.registerHistory)
	}
	if history.stop != thread.Token.Stop || history.revision != thread.Token.Registers {
		history.previous = history.current
		history.stop = thread.Token.Stop
		history.revision = thread.Token.Registers
	}
	history.current = uiRegisterValues(registers)
	c.registerHistory[key] = history
}

func (c *Controller) contextUIView(ctx context.Context, snapshot target.Snapshot, thread target.ThreadInfo, output *bytes.Buffer) contextOutput {
	width := display.OutputWidth(c.out)
	return contextOutput{
		writef: func(format string, values ...any) error {
			_, err := output.WriteString(display.Wrap(fmt.Sprintf(format, values...), width, 4))
			return err
		},
		renderer: c.renderer,
		width:    width,
		ctx:      ctx,
		prepare: func(registers []target.Register) (*addressWalker, error) {
			return c.newAddressView(ctx, snapshot, thread, registers)
		},
		compare: func(registers []target.Register) map[string]bool {
			return c.changedRegisters(snapshot, thread, registers)
		},
	}
}

var uiRegisterOrder = []string{
	"rax", "rbx", "rcx", "rdx", "rsp", "rbp", "rsi", "rdi", "rip",
	"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "orig_rax", "fs_base", "gs_base", "eflags",
	"cs", "ss", "ds", "es", "fs", "gs",
}

func uiOrderedRegisters(registers []target.Register) []target.Register {
	ordered := slices.Clone(registers)
	slices.SortStableFunc(ordered, func(a, b target.Register) int {
		left, right := slices.Index(uiRegisterOrder, a.Name), slices.Index(uiRegisterOrder, b.Name)
		if left < 0 {
			left = len(uiRegisterOrder)
		}
		if right < 0 {
			right = len(uiRegisterOrder)
		}
		return left - right
	})
	return ordered
}

func uiSegment(name string) bool {
	return slices.Contains([]string{"cs", "ss", "ds", "es", "fs", "gs"}, name)
}

func (view contextOutput) registerName(register target.Register) string {
	style := display.StyleRegister
	if view.changed[register.Name] {
		style = display.StyleChanged
	}
	return view.renderer.Text(style, "$"+contextEscapedText(register.Name))
}

func (view contextOutput) flags(value uint64) string {
	var flags []string
	for _, flag := range []struct {
		bit  uint
		name string
	}{
		{0, "cf"}, {2, "pf"}, {4, "af"}, {6, "zf"}, {7, "sf"}, {8, "tf"}, {9, "if"}, {10, "df"},
		{11, "of"}, {14, "nt"}, {16, "rf"}, {17, "vm"}, {18, "ac"}, {19, "vif"}, {20, "vip"}, {21, "id"},
	} {
		name, style := flag.name, display.StyleMuted
		if value&(uint64(1)<<flag.bit) != 0 {
			name, style = strings.ToUpper(name), display.StyleFlagSet
		}
		flags = append(flags, view.renderer.Text(style, name))
	}
	return "[" + strings.Join(flags, " ") + fmt.Sprintf(" IOPL=%d]", value>>12&3)
}

func (view contextOutput) legend() error {
	items := []string{
		view.renderer.PermissionText("Code", true, false, true),
		view.renderer.PermissionText("Writable", true, true, false),
		view.renderer.PermissionText("ReadOnly", true, false, false),
		view.renderer.PermissionText("RWX", true, true, true),
		view.renderer.Text(display.StyleChanged, "Modified register"),
	}
	return view.writef("[ Legend: %s ]\n", strings.Join(items, " | "))
}

func (view contextOutput) instructionText(instruction inspect.Instruction) string {
	text := contextEscapedText(instruction.Text)
	if view.walker == nil || view.walker.symbol == nil {
		return text
	}
	decoded, err := x86asm.Decode(instruction.Bytes, 64)
	if err != nil || decoded.Len != len(instruction.Bytes) {
		return text
	}
	relative, ok := decoded.Args[0].(x86asm.Rel)
	if !ok || uint64(decoded.Len) > math.MaxUint64-uint64(instruction.Address) {
		return text
	}
	address := uint64(instruction.Address) + uint64(decoded.Len)
	delta := int64(relative)
	if delta >= 0 {
		if uint64(delta) > math.MaxUint64-address {
			return text
		}
		address += uint64(delta)
	} else {
		amount := uint64(-(delta + 1)) + 1
		if amount > address {
			return text
		}
		address -= amount
	}
	if label := view.walker.symbol(target.Address(address)); label != "" {
		text += " " + view.renderer.Text(display.StyleSymbol, "<"+contextEscapedText(label)+">")
	}
	return text
}

func (view contextOutput) rawStackRows(registers []target.Register, start target.Address, data []byte) error {
	values := uiRegisterValues(registers)
	for offset := 0; offset < len(data); offset += 8 {
		address := start + target.Address(offset)
		var labels []string
		for _, name := range []string{"rsp", "rbp"} {
			if value, exists := values[name]; exists && value == uint64(address) {
				labels = append(labels, "$"+name+">")
			}
		}
		label := strings.Join(labels, ",")
		if len(labels) == 2 {
			label = "$rsp/rbp>"
		}
		where, err := view.renderer.Address(target.AMD64, address, display.AddressStack)
		if err != nil {
			return err
		}
		row := data[offset:min(offset+8, len(data))]
		value := "<partial bytes: " + display.FormatBytes(row) + ">"
		if len(row) == 8 {
			value = fmt.Sprintf("0x%016x", inspectionWord(row))
		}
		if err := view.writef("%-9s %s|+0x%04x|+%03d: %s\n", label, where, offset, offset/8, value); err != nil {
			return err
		}
	}
	return nil
}
