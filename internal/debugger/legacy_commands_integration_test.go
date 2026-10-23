package debugger

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"fastdbg2/display"
	"fastdbg2/target"

	"golang.org/x/sys/unix"
)

func legacyNativeAddress(t *testing.T, f *expansionIntegration, expression string) target.Address {
	t.Helper()
	snapshot, thread, err := f.controller.stopped()
	if err != nil {
		t.Fatal(err)
	}
	address, err := f.controller.evaluate(context.Background(), expression, snapshot, thread)
	if err != nil {
		t.Fatal(err)
	}
	return address
}

func TestLegacyCommandsNativeWrites(t *testing.T) {
	for _, pie := range []bool{false, true} {
		t.Run(fmt.Sprintf("pie_%t", pie), func(t *testing.T) {
			f := newExpansionIntegration(t, pie)
			f.breakpoint(t)
			f.command(t, "thread 2")
			_, before, err := f.controller.stopped()
			if err != nil {
				t.Fatal(err)
			}
			f.command(t, "set $r15 = 0x1122334455667788")
			if _, err := f.controller.session.ReadThreadRegisters(before.Token); !errors.Is(err, target.ErrStale) {
				t.Fatalf("register mutation retained old token: %v", err)
			}
			if output := f.command(t, "p/x $r15"); output != "0x1122334455667788\n" {
				t.Fatalf("selected register write: %s", output)
			}
			f.command(t, "thread 3")
			if output := f.command(t, "p/x $r15"); output != "0x12345002\n" {
				t.Fatalf("write changed peer register: %s", output)
			}
			f.command(t, "thread 2")
			original := f.read(t, "expansion_words", 24)
			expected := bytes.Clone(original)
			for _, test := range []struct {
				command string
				offset  int
				data    []byte
			}{
				{"set8 expansion_words 0xa5", 0, []byte{0xa5}},
				{"set16 expansion_words+2 0xb6c7", 2, []byte{0xc7, 0xb6}},
				{"set32 expansion_words+4 0xd8e9fa0b", 4, []byte{0x0b, 0xfa, 0xe9, 0xd8}},
				{"set expansion_words+8 0x0102030405060708", 8, []byte{8, 7, 6, 5, 4, 3, 2, 1}},
			} {
				f.command(t, test.command)
				copy(expected[test.offset:], test.data)
				if got := f.read(t, "expansion_words", len(expected)); !bytes.Equal(got, expected) {
					t.Fatalf("%s changed wrong bytes: got %x want %x", test.command, got, expected)
				}
			}
			f.command(t, "xor expansion_words+8 0xffffffffffffffff")
			for i := 8; i < 16; i++ {
				expected[i] ^= 0xff
			}
			if got := f.read(t, "expansion_words", 24); !bytes.Equal(got, expected) {
				t.Fatalf("XOR width or endianness: %x", got)
			}
			for _, command := range []string{"set8 expansion_words 256", "set16 expansion_words 65536", "set32 expansion_words 0x100000000", "set $not_a_register 1", "set8 expansion_point 0x90", "thread apply all set r15 0", "thread apply all xor expansion_words 1"} {
				f.reject(t, command)
				if got := f.read(t, "expansion_words", 24); !bytes.Equal(got, expected) {
					t.Fatalf("failed %s changed memory: %x", command, got)
				}
			}
			if got := f.read(t, "expansion_point", 1)[0]; got != 0xcc {
				t.Fatalf("write clobbered software breakpoint: %#x", got)
			}
			boundary := binary.LittleEndian.Uint64(f.read(t, "expansion_boundary", 8))
			snapshot, _, err := f.controller.stopped()
			if err != nil {
				t.Fatal(err)
			}
			output, err := f.execute(fmt.Sprintf("set %#x 0x1122334455667788", boundary+12))
			if !errors.Is(err, target.ErrPartial) || !strings.Contains(err.Error(), "4/8 bytes confirmed") || strings.Contains(output, "Set memory") {
				t.Fatalf("partial memory write: %v, %s", err, output)
			}
			want := append(bytes.Repeat([]byte{'Q'}, 12), 0x88, 0x77, 0x66, 0x55)
			if got := f.read(t, fmt.Sprintf("%#x", boundary), 16); !bytes.Equal(got, want) {
				t.Fatalf("partial write prefix: %x", got)
			}
			if _, err := f.controller.session.ReadSpaceMemory(snapshot.Memory, target.Address(boundary), make([]byte, 1)); !errors.Is(err, target.ErrStale) {
				t.Fatalf("partial mutation retained memory token: %v", err)
			}
			f.reject(t, fmt.Sprintf("xor %#x 1", boundary+12))
			if got := f.read(t, fmt.Sprintf("%#x", boundary), 16); !bytes.Equal(got, want) {
				t.Fatalf("short XOR read mutated prefix: %x", got)
			}
			f.command(t, "regs rip r15")
		})
	}
}

func TestLegacyCommandsNativeWatchpoints(t *testing.T) {
	for _, pie := range []bool{false, true} {
		for _, local := range []bool{false, true} {
			t.Run(fmt.Sprintf("pie_%t/peer_only_%t", pie, local), func(t *testing.T) {
				f := newExpansionIntegration(t, pie)
				f.breakpoint(t)
				if local {
					f.command(t, "thread 2")
				}
				address := legacyNativeAddress(t, f, "expansion_words")
				var firstGeneration uint64
				for slot := range 4 {
					output := f.command(t, "wp expansion_words --size 8 --access write")
					if !strings.Contains(output, fmt.Sprintf("slot=%d ", slot)) {
						t.Fatalf("watchpoint allocator: %s", output)
					}
					if slot == 0 {
						match := regexp.MustCompile(`generation=(\d+)`).FindStringSubmatch(output)
						if len(match) != 2 {
							t.Fatal(output)
						}
						firstGeneration, _ = strconv.ParseUint(match[1], 10, 64)
					}
				}
				f.reject(t, "wp expansion_words")
				for slot := 1; slot < 4; slot++ {
					f.command(t, fmt.Sprintf("wp d %d", slot))
				}
				f.reject(t, "wp expansion_words+1 --size 8")
				f.reject(t, "wp expansion_words --access read")
				f.reject(t, "thread apply all wp expansion_words")
				expectedThread := uint64(1)
				if local {
					expectedThread = 2
				}
				if output := f.command(t, "wp list"); !uiWatchpointRowMatches(output, expectedThread, 0, "write", 8, address, "installed", firstGeneration) {
					t.Fatal(output)
				}
				if local {
					f.command(t, "thread 1")
				}
				output := f.command(t, "continue")
				stop := f.controller.session.LastStop()
				if local {
					if stop.Reason != target.StopBreakpoint || !strings.Contains(output, "(breakpoint).") {
						t.Fatalf("peer-local watchpoint trapped main: %+v\n%s", stop, output)
					}
					f.command(t, "thread 3")
					f.reject(t, "wp d 0")
					f.command(t, "thread 2")
				} else if stop.Reason != target.StopWatchpoint || len(stop.Watchpoints) != 1 || stop.Watchpoints[0].Address != address || stop.Watchpoints[0].Ref.Generation != firstGeneration {
					t.Fatalf("watchpoint provenance: %+v\n%s", stop, output)
				}
				if got := binary.LittleEndian.Uint64(f.read(t, "expansion_words", 8)); got != 0x8877665544332212 {
					t.Fatalf("inferior store was not executed exactly once: %#x", got)
				}
				f.command(t, "wp d 0")
				output = f.command(t, "wp expansion_words --size 8 --access write")
				match := regexp.MustCompile(`generation=(\d+)`).FindStringSubmatch(output)
				generation, _ := strconv.ParseUint(match[1], 10, 64)
				if generation <= firstGeneration {
					t.Fatalf("slot reuse retained generation: %s", output)
				}
				f.command(t, "wp d 0")
				f.command(t, "regs rip")
			})
		}
	}
}

func legacyReverseHex(data []byte) string {
	data = bytes.Clone(data)
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
	return hex.EncodeToString(data)
}

func TestLegacyCommandsNativeSIMDSelection(t *testing.T) {
	f := newExpansionIntegration(t, true)
	f.breakpoint(t)
	backend := f.controller.session.(*nativeSession)
	for _, id := range []int{1, 2} {
		f.command(t, fmt.Sprintf("thread %d", id))
		_, thread, err := f.controller.stopped()
		if err != nil {
			t.Fatal(err)
		}
		state, err := backend.ReadExtendedRegisters(thread.Token)
		if err != nil {
			t.Fatal(err)
		}
		for index := range 16 {
			state.Data[160+index] = byte((id-1)*64 + index)
		}
		if state.Format == target.ExtendedFormatXSave {
			binary.LittleEndian.PutUint64(state.Data[512:520], binary.LittleEndian.Uint64(state.Data[512:520])|2)
			for _, component := range state.XState.ExtendedComponents {
				if component.ID == 2 {
					for index := range 16 {
						state.Data[int(component.Offset)+index] = byte((id-1)*64 + 16 + index)
					}
					binary.LittleEndian.PutUint64(state.Data[512:520], binary.LittleEndian.Uint64(state.Data[512:520])|4)
				}
			}
		}
		if _, err := backend.WriteExtendedRegisters(thread.Token, state); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []int{2, 1, 2} {
		f.command(t, fmt.Sprintf("thread %d", id))
		_, thread, err := f.controller.stopped()
		if err != nil {
			t.Fatal(err)
		}
		state, err := backend.ReadExtendedRegisters(thread.Token)
		if err != nil {
			t.Fatal(err)
		}
		var seed [32]byte
		for index := range seed {
			seed[index] = byte((id-1)*64 + index)
		}
		if !bytes.Equal(state.Data[160:176], seed[:16]) {
			t.Fatalf("native XMM seed: %x", state.Data[160:176])
		}
		needle := legacyReverseHex(seed[8:16]) + " " + legacyReverseHex(seed[:8])
		if output := f.command(t, "xmm 0"); !strings.Contains(output, needle) {
			t.Fatalf("selected XMM%d display: %s", id, output)
		}
		if state.XState != nil && state.XState.KernelFeatures&4 != 0 {
			needle := legacyReverseHex(seed[16:]) + " " + legacyReverseHex(seed[:16])
			if output := f.command(t, "ymm 0"); !strings.Contains(output, needle) {
				t.Fatalf("selected YMM%d display: %s", id, output)
			}
		} else {
			_, err := f.execute("ymm 0")
			if !errors.Is(err, target.ErrUnsupported) {
				t.Fatalf("YMM on unsupported state: %v", err)
			}
		}
		for _, command := range []string{"simd", "SIMD", "xmm", "XMM", "ymm", "YMM"} {
			if output := f.command(t, command); !strings.Contains(output, "[SIMD]") || !strings.Contains(output, needle) {
				t.Fatalf("full SIMD alias %s: %s", command, output)
			}
		}
		f.reject(t, "xmm 16")
	}
}

func TestLegacyCommandsNativeSharedHardwareSlot(t *testing.T) {
	f := newExpansionIntegration(t, true)
	f.breakpoint(t)
	backend := f.controller.session.(*nativeSession)
	point := legacyNativeAddress(t, f, "expansion_point")
	_, selected, err := f.controller.stopped()
	if err != nil {
		t.Fatal(err)
	}
	hardware, err := backend.SetHardwareBreakpoint(selected.Token, target.HardwareBreakpointRequest{Slot: 3, Address: point + 1})
	if err != nil {
		t.Fatal(err)
	}
	for slot := range 3 {
		if output := f.command(t, "wp expansion_words --size 8 --access write"); !strings.Contains(output, fmt.Sprintf("slot=%d ", slot)) {
			t.Fatalf("shared-bank slot allocation: %s", output)
		}
	}
	f.reject(t, "wp expansion_words --size 8 --access write")
	_, selected, err = f.controller.stopped()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backend.ClearHardwareBreakpoint(selected.Token, hardware.Ref); err != nil {
		t.Fatalf("CLI watchpoint overwrote independent hardware slot: %v", err)
	}
	if got := f.read(t, "expansion_point", 2); !bytes.Equal(got, []byte{0xcc, 0x90}) {
		t.Fatalf("shared hardware bank changed code bytes: %x", got)
	}
}

func TestLegacyCommandsNativePIEBreakpointRestart(t *testing.T) {
	for _, pie := range []bool{false, true} {
		t.Run(fmt.Sprintf("pie_%t", pie), func(t *testing.T) {
			f := newExpansionIntegration(t, pie)
			f.command(t, "delete 1")
			image, err := elf.Open(f.controller.path)
			if err != nil {
				t.Fatal(err)
			}
			symbols, err := image.Symbols()
			image.Close()
			if err != nil {
				t.Fatal(err)
			}
			var linked uint64
			for _, symbol := range symbols {
				if symbol.Name == "expansion_point" {
					linked = symbol.Value
				}
			}
			if linked == 0 {
				t.Fatal("fixture function symbol missing")
			}
			f.command(t, fmt.Sprintf("B PIE %#x", linked))
			for iteration := range 2 {
				if iteration != 0 {
					oldPID := f.pid
					f.command(t, "START")
					f.pid = f.controller.session.PID()
					if _, err := os.Stat(fmt.Sprintf("/proc/%d", oldPID)); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("restart retained owned target %d: %v", oldPID, err)
					}
				}
				address := legacyNativeAddress(t, f, "expansion_point")
				if output := f.command(t, "BREAK LIST"); !uiBreakpointRowMatches(output, 2, true, fmt.Sprintf("0x%016x", address), "installed", fmt.Sprintf("%#x", linked), true) {
					t.Fatalf("PIE breakpoint did not resolve current image: %s", output)
				}
				if got := f.read(t, "expansion_point", 1)[0]; got != 0xcc {
					t.Fatalf("PIE breakpoint raw byte: %#x", got)
				}
				f.command(t, "disable 2")
				if got := f.read(t, "expansion_point", 1)[0]; got != 0x90 {
					t.Fatalf("PIE breakpoint disable did not restore code: %#x", got)
				}
				f.command(t, "enable 2")
				f.breakpoint(t)
			}
		})
	}
}

func TestLegacyCommandsRegisteredAliases(t *testing.T) {
	for canonical, aliases := range map[string]string{
		"break": "b B BREAK", "start": "s S START", "run": "r R RUN", "continue": "c cont C CONTINUE CONT", "step": "STEP",
		"print": "p P PRINT", "context": "CONTEXT", "color": "COLOR", "stack": "stk STACK STK", "vmmap": "VMMAP",
		"sym": "symbol SYM SYMBOL", "got": "GOT", "chunk": "CHUNK", "stdio": "stdio-dump STDIO STDIO-DUMP",
		"proc-info": "procinfo proc.info PROC-INFO PROCINFO", "fd": "fds FD FDS", "checksec": "CHECKSEC", "fs_base": "fs",
		"visual-heap": "vis VIS VISUAL-HEAP", "telescope": "tel", "simd": "SIMD", "xmm": "XMM", "ymm": "YMM", "quit": "q exit",
	} {
		for _, alias := range append([]string{canonical}, strings.Fields(aliases)...) {
			command, ok := canonicalCommand(alias)
			if !ok || command.name != canonical {
				t.Errorf("legacy alias %q: got %q, %t; want %q", alias, command.name, ok, canonical)
			}
		}
	}
	f := &expansionIntegration{}
	f.controller = New(&f.output, display.Renderer{})
	for _, name := range []string{"break", "b", "B", "BREAK"} {
		for _, list := range []string{"l", "list", "L", "LIST"} {
			if output := f.command(t, name+" "+list); !strings.Contains(output, "No breakpoints.") {
				t.Fatal(output)
			}
		}
		for _, kind := range []string{"pie", "PIE"} {
			f.command(t, name+" "+kind+" 0x1000")
			if output := f.command(t, "break list"); !uiBreakpointRowMatches(output, f.controller.nextBreakpoint, true, "<pending>", "pending", "0x1000", true) {
				t.Fatal(output)
			}
			f.command(t, "delete all")
		}
	}
	for _, declared := range []string{"bt", "BT", "backtrace", "BACKTRACE", "stackframe", "stkf", "STACKFRAME", "STKF"} {
		if _, ok := canonicalCommand(declared); !ok {
			t.Errorf("metadata-backed command is not registered: %s", declared)
		}
		if _, err := f.controller.Execute(context.Background(), declared, ""); !errors.Is(err, target.ErrInvalidState) {
			t.Errorf("metadata-backed command without a target: %s: %v", declared, err)
		}
	}
	for _, declared := range []string{"arena", "arenas", "ARENA", "ARENAS", "bins", "BINS"} {
		if _, ok := canonicalCommand(declared); !ok {
			t.Errorf("metadata-backed command is not registered: %s", declared)
		}
		beforeOutput, beforeSelected := f.output.Len(), f.controller.selected
		quit, err := f.controller.Execute(context.Background(), declared, "")
		if quit || !errors.Is(err, target.ErrInvalidState) || errors.Is(err, target.ErrInvalidArgument) || !strings.Contains(err.Error(), "no target") ||
			f.controller.session != nil || f.controller.selected != beforeSelected || f.output.Len() != beforeOutput {
			t.Errorf("automatic heap command without a target: %s: quit=%t err=%v output=%q", declared, quit, err, f.output.String())
		}
	}
	for _, unsupported := range []string{"ReGs", "vMmAp"} {
		if _, ok := canonicalCommand(unsupported); ok {
			t.Errorf("undeclared command unexpectedly registered: %s", unsupported)
		}
	}
}

func legacyAssertDSOUnavailable(t *testing.T, f *expansionIntegration, commandErr error) {
	t.Helper()
	if !errors.Is(commandErr, target.ErrPartial) || !errors.Is(commandErr, target.ErrUnavailable) || !errors.Is(commandErr, unix.EPERM) || errors.Is(commandErr, target.ErrStale) {
		t.Fatalf("not a classified DSO identity refusal: %v", commandErr)
	}
	var filesystem unix.Statfs_t
	if err := unix.Statfs(f.controller.path, &filesystem); err != nil || filesystem.Type != unix.BTRFS_SUPER_MAGIC {
		t.Fatalf("DSO refusal without verified Btrfs filesystem: type=%#x, %v", filesystem.Type, err)
	}
	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", f.pid))
	if err != nil {
		t.Fatal(err)
	}
	mounts, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", f.pid))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(maps), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || !strings.HasPrefix(fields[5], "/") || fields[5] == f.controller.path {
			continue
		}
		majorText, minorText, found := strings.Cut(fields[3], ":")
		if !found {
			continue
		}
		major, majorErr := strconv.ParseUint(majorText, 16, 32)
		minor, minorErr := strconv.ParseUint(minorText, 16, 32)
		inode, inodeErr := strconv.ParseUint(fields[4], 10, 64)
		if majorErr != nil || minorErr != nil || inodeErr != nil || inode == 0 {
			continue
		}
		source, err := os.Open(fmt.Sprintf("/proc/%d/root%s", f.pid, fields[5]))
		if err != nil {
			continue
		}
		var stat unix.Stat_t
		var extended unix.Statx_t
		statErr := unix.Fstat(int(source.Fd()), &stat)
		extendedErr := unix.Statx(int(source.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_BASIC_STATS|unix.STATX_MNT_ID, &extended)
		image, imageErr := elf.NewFile(source)
		dynamic := imageErr == nil && image.Type == elf.ET_DYN
		source.Close()
		if !dynamic || statErr != nil || extendedErr != nil || stat.Ino != inode || uint64(unix.Major(stat.Dev)) == major && uint64(unix.Minor(stat.Dev)) == minor {
			continue
		}
		mountMatches := false
		for _, line := range strings.Split(string(mounts), "\n") {
			mount := strings.Fields(line)
			if len(mount) < 6 || mount[0] != strconv.FormatUint(extended.Mnt_id, 10) {
				continue
			}
			mountMatches = mount[2] == fmt.Sprintf("%d:%d", major, minor)
		}
		if !mountMatches {
			continue
		}
		fd, mapErr := unix.Open(fmt.Sprintf("/proc/%d/map_files/%s", f.pid, fields[0]), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if fd >= 0 {
			unix.Close(fd)
		}
		if errors.Is(mapErr, unix.EPERM) {
			t.Logf("strict DSO refusal independently verified: map_files=%s EPERM, inode=%d, maps dev=%x:%x, fstat dev=%x:%x, mount=%d; mount coordinates do not prove file identity", fields[0], inode, major, minor, unix.Major(stat.Dev), unix.Minor(stat.Dev), extended.Mnt_id)
			return
		}
	}
	t.Fatalf("DSO error had no independently confirmed map_files EPERM plus strict-device mismatch: %v", commandErr)
}

func TestLegacyCommandsNativeMetadataAndAliases(t *testing.T) {
	for _, pie := range []bool{false, true} {
		t.Run(fmt.Sprintf("pie_%t", pie), func(t *testing.T) {
			f := newExpansionIntegration(t, pie)
			f.breakpoint(t)
			point := legacyNativeAddress(t, f, "expansion_point")
			image, err := elf.Open(f.controller.path)
			if err != nil {
				t.Fatal(err)
			}
			symbols, err := image.Symbols()
			image.Close()
			if err != nil {
				t.Fatal(err)
			}
			var size uint64
			for _, symbol := range symbols {
				if symbol.Name == "expansion_point" {
					size = symbol.Size
				}
			}
			for _, alias := range []string{"func", "f", "F", "FUNC"} {
				output := f.command(t, "disass "+alias+" expansion_point")
				if metadataJoinedField(output, "Address") != fmt.Sprintf("0x%016x", point) || metadataJoinedField(output, "Extent") != fmt.Sprintf("%d bytes (ELF STT_FUNC extent)", size) || !strings.Contains(output, "ret") || !strings.Contains(output, "ud2") {
					t.Fatalf("exact ELF function extent: %s", output)
				}
			}
			for _, alias := range []string{"sym", "symbol", "SYM", "SYMBOL"} {
				output, err := f.execute(alias + " expansion_point")
				if err != nil {
					legacyAssertDSOUnavailable(t, f, err)
					if !strings.Contains(strings.ToLower(err.Error()), "mapped elf scan incomplete") {
						t.Fatalf("partial symbol listing hid incomplete discovery: %s", output)
					}
				}
				if !strings.Contains(output, fmt.Sprintf("0x%016x", point)) || !strings.Contains(output, "STT_FUNC") {
					t.Fatalf("symbol metadata: %s", output)
				}
			}
			for _, test := range []struct {
				commands []string
				argument string
				needle   string
			}{
				{[]string{"vmmap", "VMMAP"}, "", "[vmmap]"},
				{[]string{"fd", "fds", "FD", "FDS"}, " 0", "File Descriptors"},
				{[]string{"proc-info", "procinfo", "proc.info", "PROC-INFO", "PROCINFO"}, "", "Process Information"},
				{[]string{"got", "GOT"}, "", "[got]"},
				{[]string{"checksec", "CHECKSEC"}, "", "[checksec]"},
				{[]string{"stdio", "stdio-dump", "STDIO", "STDIO-DUMP"}, "", "Raw object bytes; FILE member offsets are not inferred."},
				{[]string{"tel", "telescope"}, " expansion_words 1", "0x8877665544332211"},
				{[]string{"db"}, " --count 8 expansion_words", "11 22 33 44 55 66 77 88"},
				{[]string{"xxd"}, " expansion_words 8", "11 22 33 44 55 66 77 88"},
				{[]string{"dd"}, " --count 1 expansion_words", "0x44332211"},
				{[]string{"xxd dword"}, " expansion_words 1", "0x44332211"},
				{[]string{"dq"}, " --count 1 expansion_words", "0x8877665544332211"},
				{[]string{"xxd qword"}, " expansion_words 1", "0x8877665544332211"},
			} {
				for _, command := range test.commands {
					output, commandErr := f.execute(command + test.argument)
					if commandErr != nil {
						if test.commands[0] != "stdio" {
							t.Fatalf("%s: %v\n%s", command, commandErr, output)
						}
						legacyAssertDSOUnavailable(t, f, commandErr)
						if !strings.Contains(output, "Stdio symbol scan incomplete") || strings.Contains(output, "[stdio]") {
							t.Fatalf("unverified stdio object was fabricated or not disclosed: %s", output)
						}
						continue
					}
					if strings.ContainsRune(output, '\x1b') {
						t.Fatalf("unescaped terminal data: %q", output)
					}
					if !strings.Contains(output, test.needle) {
						t.Fatalf("%s missing %q: %s", command, test.needle, output)
					}
					if command == "got" {
						slots := regexp.MustCompile(`(?m)^0x([0-9a-f]{16}) (0x[0-9a-f]{16})`).FindAllStringSubmatch(output, -1)
						if len(slots) == 0 {
							t.Fatalf("fixture relocations not displayed: %s", output)
						}
						for _, slot := range slots {
							value, _ := strconv.ParseUint(slot[2], 0, 64)
							if actual := binary.LittleEndian.Uint64(f.read(t, "0x"+slot[1], 8)); actual != value {
								t.Fatalf("GOT slot %s invented value %#x, actual %#x", slot[1], value, actual)
							}
						}
					}
					if command == "stdio" {
						objects := regexp.MustCompile(`address=(0x[0-9a-f]+) declared-size=(\d+)`).FindAllStringSubmatch(output, -1)
						if len(objects) != 3 {
							t.Fatalf("standard stream objects: %s", output)
						}
						for _, object := range objects {
							var words []string
							for _, value := range f.read(t, object[1], 16) {
								words = append(words, fmt.Sprintf("%02x", value))
							}
							if !strings.Contains(output, strings.Join(words, " ")) {
								t.Fatalf("stdio raw object prefix disagrees with native memory: %s", output)
							}
						}
					}
					if command == "vmmap" {
						maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", f.pid))
						if err != nil {
							t.Fatal(err)
						}
						found := false
						for _, line := range strings.Split(string(maps), "\n") {
							fields := strings.Fields(line)
							if len(fields) < 5 {
								continue
							}
							low, high, _ := strings.Cut(fields[0], "-")
							start, _ := strconv.ParseUint(low, 16, 64)
							end, _ := strconv.ParseUint(high, 16, 64)
							offset, _ := strconv.ParseUint(fields[2], 16, 64)
							if uint64(point) >= start && uint64(point) < end {
								found = strings.Contains(output, fmt.Sprintf("0x%016x 0x%016x 0x%08x 0x%08x %s", start, end, end-start, offset, fields[1]))
							}
						}
						if !found {
							t.Fatalf("function mapping differs from /proc oracle: %s", output)
						}
					}
				}
			}
			dataAddress := legacyNativeAddress(t, f, "expansion_words")
			for _, test := range []struct{ name, count, needle string }{{"db", "8", "11 22 33 44 55 66 77 88"}, {"dd", "1", "0x44332211"}, {"dq", "1", "0x8877665544332211"}} {
				if output := f.command(t, fmt.Sprintf("%s %#x %s", test.name, dataAddress, test.count)); !strings.Contains(output, test.needle) {
					t.Fatalf("legacy literal dump grammar: %s", output)
				}
			}
			bases := make(map[uint64]bool)
			for _, id := range []int{1, 2, 3} {
				f.command(t, fmt.Sprintf("thread %d", id))
				_, thread, err := f.controller.stopped()
				if err != nil {
					t.Fatal(err)
				}
				registers, err := f.controller.session.ReadThreadRegisters(thread.Token)
				if err != nil {
					t.Fatal(err)
				}
				base, err := contextRegisterValue(registers, "fs_base")
				if err != nil {
					t.Fatal(err)
				}
				bases[base] = true
				for _, name := range []string{"fs", "fs_base"} {
					if output := f.command(t, name); !strings.Contains(output, fmt.Sprintf("0x%016x", base)) {
						t.Fatalf("selected FS base: %s", output)
					}
				}
			}
			if len(bases) != 3 {
				t.Fatalf("fixture thread FS bases were not distinct: %v", bases)
			}
		})
	}
}

const legacySearchFixture = `#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
unsigned char legacy_bytes[131080];
int legacy_fds[4];
void *legacy_mapping;
__attribute__((naked,noinline)) void legacy_point(void) {
    __asm__ volatile("nop\n\tnop\n\tret");
}
int main(int argc, char **argv) {
    if (argc != 2) return 90;
    memcpy(legacy_bytes, "ABABA", 5);
    memcpy(legacy_bytes + 65534, "ABABA", 5);
    memcpy(legacy_bytes + 131075, "ABABA", 5);
    legacy_fds[0] = open(argv[1], O_RDWR | O_CREAT | O_EXCL, 0600);
    if (legacy_fds[0] < 0 || ftruncate(legacy_fds[0], 4096)) return 91;
    legacy_mapping = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, legacy_fds[0], 0);
    if (legacy_mapping == MAP_FAILED || unlink(argv[1])) return 92;
    legacy_fds[1] = memfd_create("legacy-probe", 0);
    if (legacy_fds[1] < 0 || pipe(legacy_fds + 2)) return 93;
    legacy_point();
    return 23;
}
`

func newLegacySearchIntegration(t *testing.T, pie bool) (*expansionIntegration, string) {
	t.Helper()
	return newLegacyFixture(t, pie, false, legacySearchFixture, "legacy_point", true)
}

func newLegacyFixture(t *testing.T, pie, static bool, source, point string, hasFile bool) (*expansionIntegration, string) {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".cache", "fastdbg-amd64-command-port", "validation", "tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(root, "legacy-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "fixture")
	if err := os.WriteFile(path+".c", []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	flags := []string{"-fno-pie", "-no-pie"}
	if pie {
		flags = []string{"-fPIE", "-pie"}
	}
	if static {
		flags = []string{"-static", "-fno-pie", "-no-pie"}
		if pie {
			flags = []string{"-static-pie", "-fPIE"}
		}
		flags = append(flags, "-Wl,-e,legacy_static_entry")
	}
	args := append([]string{"-std=gnu11", "-O0", "-g", "-fcf-protection=none", "-Wl,--build-id=none"}, flags...)
	args = append(args, "-o", path, path+".c")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, "cc", args...).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, output)
	}
	file := filepath.Join(dir, "literal space (name)\n\x1b[31m")
	f := &expansionIntegration{}
	f.controller = New(&f.output, display.Renderer{})
	t.Cleanup(func() {
		fd := -1
		if f.controller.session != nil && f.controller.session.State() != target.StateExited {
			fd, _ = unix.PidfdOpen(f.controller.session.PID(), 0)
		}
		if fd >= 0 {
			defer unix.Close(fd)
		}
		done := make(chan error, 1)
		go func() { done <- f.controller.Close() }()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			if fd >= 0 {
				_ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
			}
			t.Error("legacy fixture cleanup exceeded deadline")
		}
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", f.pid)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("legacy fixture %d remains: %v", f.pid, err)
		}
	})
	var arguments []string
	if hasFile {
		arguments = []string{file}
	}
	if err := f.controller.Configure(path, arguments); err != nil {
		t.Fatal(err)
	}
	f.command(t, "break "+point)
	f.command(t, "start")
	f.pid = f.controller.session.PID()
	f.breakpoint(t)
	return f, file
}

const legacyStaticMetadataFixture = `#include <stdint.h>
#include <stdio.h>
__asm__(".text\n.global legacy_static_entry\n.type legacy_static_entry,@function\nlegacy_static_entry:\n.rept 16\nnop\n.endr\njmp _start\n.size legacy_static_entry,.-legacy_static_entry\n");
volatile uint64_t legacy_static_words[2] = {0x8877665544332211ULL, 0};
__attribute__((naked,noinline)) void legacy_static_point(void) {
    __asm__ volatile("nop\n\tnop\n\tret");
}
int main(void) {
    FILE *streams[3] = {stdin, stdout, stderr};
    __asm__ volatile("" : : "r"(streams) : "memory");
    legacy_static_point();
    return 27;
}
`

func TestLegacyCommandsNativeStaticELFPositive(t *testing.T) {
	for _, pie := range []bool{false, true} {
		t.Run(fmt.Sprintf("pie_%t", pie), func(t *testing.T) {
			f, _ := newLegacyFixture(t, pie, true, legacyStaticMetadataFixture, "legacy_static_point", false)
			point := legacyNativeAddress(t, f, "legacy_static_point")
			for _, alias := range []string{"sym", "symbol", "SYM", "SYMBOL"} {
				output := f.command(t, alias+" legacy_static_point")
				if !strings.Contains(output, fmt.Sprintf("0x%016x", point)) || !strings.Contains(output, "STT_FUNC") || strings.Contains(strings.ToLower(output), "incomplete") {
					t.Fatalf("static ELF positive symbol facts: %s", output)
				}
			}
			for _, command := range []string{"got", "GOT", "checksec", "CHECKSEC"} {
				if output := f.command(t, command); !strings.Contains(output, `Source proof: "proc-exe+auxv"`) {
					t.Fatalf("main ELF proof missing: %s", output)
				}
			}
			for _, command := range []string{"stdio", "stdio-dump", "STDIO", "STDIO-DUMP"} {
				output := f.command(t, command+" --module main")
				objects := regexp.MustCompile(`address=(0x[0-9a-f]+) declared-size=(\d+)`).FindAllStringSubmatch(output, -1)
				if len(objects) != 3 || !strings.Contains(output, `source-proof="proc-exe+auxv"`) {
					t.Fatalf("positive static standard streams: %s", output)
				}
				for _, object := range objects {
					var words []string
					for _, value := range f.read(t, object[1], 16) {
						words = append(words, fmt.Sprintf("%02x", value))
					}
					if !strings.Contains(output, strings.Join(words, " ")) {
						t.Fatalf("static stdio raw prefix disagrees with native memory: %s", output)
					}
				}
			}
			output := f.command(t, "disass func legacy_static_point")
			if !strings.Contains(output, "ELF STT_FUNC extent") || !strings.Contains(output, "ud2") {
				t.Fatalf("static exact function did not include bytes after ret: %s", output)
			}
		})
	}
}

func TestLegacyCommandsNativeSearchAndProcIdentity(t *testing.T) {
	for _, pie := range []bool{false, true} {
		t.Run(fmt.Sprintf("pie_%t", pie), func(t *testing.T) {
			f, name := newLegacySearchIntegration(t, pie)
			address := legacyNativeAddress(t, f, "legacy_bytes")
			want := []target.Address{address, address + 2, address + 65534, address + 65536, address + 131075, address + 131077}
			for _, command := range []string{"search-string ABA legacy_bytes legacy_bytes+131080", "search-value --size 3 0x414241 legacy_bytes legacy_bytes+131080"} {
				output := f.command(t, command)
				if !strings.Contains(output, "6 confirmed byte match(es)") || !strings.Contains(output, "Status     : complete") {
					t.Fatalf("search completeness: %s", output)
				}
				var got []target.Address
				for _, match := range regexp.MustCompile(`(?m)^  0x([0-9a-f]+)$`).FindAllStringSubmatch(output, -1) {
					value, _ := strconv.ParseUint(match[1], 16, 64)
					got = append(got, target.Address(value))
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("chunk boundary/overlap matches: got %x want %x", got, want)
				}
			}
			output, err := f.execute("search-string --max-bytes 65536 ABA legacy_bytes legacy_bytes+131080")
			if !errors.Is(err, target.ErrPartial) || !strings.Contains(output, "Status     : partial") {
				t.Fatalf("bounded partial search: %v\n%s", err, output)
			}
			f.reject(t, "search-value --size 1 256 legacy_bytes legacy_bytes+16")
			f.reject(t, "search-string ABA legacy_bytes+16 legacy_bytes")
			output = f.command(t, "findruction nop legacy_point legacy_point+2")
			if !strings.Contains(output, "Source     : live-logical") || !strings.Contains(output, "2 confirmed byte match(es)") {
				t.Fatalf("code search did not use logical breakpoint bytes: %s", output)
			}
			fds := f.read(t, "legacy_fds", 16)
			for index := range 4 {
				fd := int(binary.LittleEndian.Uint32(fds[index*4:]))
				link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", f.pid, fd))
				if err != nil {
					t.Fatal(err)
				}
				output := f.command(t, fmt.Sprintf("fd %d", fd))
				if !strings.Contains(metadataJoinedField(output, fmt.Sprintf("FD %d", fd)), strconv.Quote(link)) {
					t.Fatalf("descriptor identity/escaping: %s, want %q", output, link)
				}
			}
			output = f.command(t, "vmmap")
			if !strings.Contains(output, `\033[31m`) && !strings.Contains(output, `\x1b[31m`) {
				t.Fatalf("mapped pathname escape missing: %s", output)
			}
			if !strings.Contains(output, " (deleted)") || strings.Contains(output, name) {
				t.Fatalf("deleted mapping identity or raw path escaping: %s", output)
			}
			f.command(t, "proc-info")
			f.reject(t, "fd 999999")
		})
	}
}

func TestLegacyCommandsNativeExplicitHeapLayoutAndUtilities(t *testing.T) {
	f, _ := newLegacySearchIntegration(t, true)
	for _, write := range []struct {
		offset int
		value  uint64
	}{{0, 0}, {8, 0x31}, {16, 0x1122334455667788}, {48, 0x30}, {56, 0x31}} {
		f.command(t, fmt.Sprintf("set legacy_bytes+%d %#x", write.offset, write.value))
	}
	for _, name := range []string{"chunk", "CHUNK"} {
		output := f.command(t, name+" --layout glibc-amd64 --words 1 legacy_bytes")
		for _, needle := range []string{"Layout     : glibc-amd64 (user-selected)", "size=0x30 PREV_INUSE=1", "0x1122334455667788", "allocation ownership and state are not determined"} {
			if !strings.Contains(output, needle) {
				t.Fatalf("explicit chunk missing %q: %s", needle, output)
			}
		}
	}
	for _, name := range []string{"visual-heap", "vis", "VIS", "VISUAL-HEAP"} {
		output := f.command(t, name+" --layout glibc-amd64 legacy_bytes legacy_bytes+96")
		if !strings.Contains(output, "headers=2 covered=0x60") {
			t.Fatalf("explicit heap range: %s", output)
		}
	}
	f.reject(t, "chunk legacy_bytes")
	f.reject(t, "vis legacy_bytes legacy_bytes+96")
	f.reject(t, "vis --layout glibc-amd64 legacy_bytes legacy_bytes+80")
	f.command(t, "set legacy_bytes+8 0")
	f.reject(t, "chunk --layout glibc-amd64 legacy_bytes")
	if output := f.command(t, `asm "nop; ret"`); !strings.Contains(output, "2 bytes: 90c3") {
		t.Fatalf("assembled bytes: %s", output)
	}
	f.reject(t, `asm ".byte 0x90"`)
	f.reject(t, `asm "call external_symbol"`)
	pattern := strings.TrimSuffix(f.command(t, "cyclic 32"), "\n")
	if len(pattern) != 32 {
		t.Fatalf("cyclic length: %q", pattern)
	}
	for _, flag := range []string{"-d", "-D"} {
		output := f.command(t, "cyclic "+flag+" "+pattern[12:16])
		if !strings.Contains(output, "offset: 12 ") {
			t.Fatalf("cyclic round trip: %s", output)
		}
	}
}
