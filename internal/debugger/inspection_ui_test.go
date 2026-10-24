package debugger

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"fastdbg2/display"
	"fastdbg2/inspect"
	"fastdbg2/native"
	"fastdbg2/target"

	"golang.org/x/sys/unix"
)

func inspectionUIOutput(t *testing.T, controller *Controller, width int, render func() error) (string, error) {
	t.Helper()
	master, slave := pagerTestPTY(t)
	connection, err := slave.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var resizeErr error
	if err := connection.Control(func(fd uintptr) {
		resizeErr = unix.IoctlSetWinsize(int(fd), unix.TIOCSWINSZ, &unix.Winsize{Row: 30, Col: uint16(width)})
	}); err != nil || resizeErr != nil {
		t.Fatal(errors.Join(err, resizeErr))
	}
	before := [2][2]int{pagerTestFlags(t, master), pagerTestFlags(t, slave)}
	controller.out = slave
	if err := master.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	type result struct {
		text string
		err  error
	}
	done := make(chan result, 1)
	marker := []byte("\n__INSPECTION_UI_END__\n")
	go func() {
		var output bytes.Buffer
		buffer := make([]byte, 4096)
		for {
			n, err := master.Read(buffer)
			output.Write(buffer[:n])
			text := strings.ReplaceAll(output.String(), "\r", "")
			if index := strings.Index(text, string(marker)); index >= 0 {
				done <- result{text: text[:index]}
				return
			}
			if err != nil {
				done <- result{text: text, err: err}
				return
			}
		}
	}()
	renderErr := render()
	if _, err := slave.Write(marker); err != nil {
		t.Fatal(err)
	}
	got := <-done
	if got.err != nil {
		t.Fatalf("PTY render: %v output=%q", got.err, got.text)
	}
	if after := [2][2]int{pagerTestFlags(t, master), pagerTestFlags(t, slave)}; after != before {
		t.Fatalf("display changed descriptor flags: before=%v after=%v", before, after)
	}
	return got.text, renderErr
}

var inspectionUISGR = regexp.MustCompile(`\x1b\[[0-9;]*m`)
var inspectionUIHexValue = regexp.MustCompile(`\[[0-9a-f ]+\]|0x[0-9a-f]+|[0-9a-f]{2}`)

func TestHexdumpUIWholeUnitsFitTerminalWithoutMissingBytes(t *testing.T) {
	for _, width := range []int{80, 120} {
		for _, unit := range []int{1, 2, 4, 8} {
			for _, color := range []bool{false, true} {
				t.Run(fmt.Sprintf("width=%d/unit=%d/color=%t", width, unit, color), func(t *testing.T) {
					controller, fixture, _ := newInspectionTestController()
					mode := display.ColorNever
					if color {
						mode = display.ColorAlways
					}
					controller.renderer, _ = display.NewRenderer(display.Options{Mode: mode})
					fixture.stack = make([]byte, 63)
					for index := range fixture.stack {
						fixture.stack[index] = byte(32 + index)
					}
					count := (len(fixture.stack) + unit - 1) / unit
					name := map[int]string{1: "db", 2: "dw", 4: "dd", 8: "dq"}[unit]
					output, err := inspectionUIOutput(t, controller, width, func() error {
						_, err := controller.Execute(context.Background(), name, fmt.Sprintf("--count %d $rsp", count))
						return err
					})
					if unit == 1 && err != nil || unit != 1 && !errors.Is(err, target.ErrPartial) || len(fixture.stackCalls) != 1 || fixture.stackCalls[0] != (contextMemoryCall{fixture.snapshot.Memory, 0x70000000, count * unit}) {
						t.Fatalf("formatter changed reads/count/partial: error=%v calls=%+v", err, fixture.stackCalls)
					}
					if strings.Contains(output, "\x1b") != color {
						t.Fatalf("color policy changed: %q", output)
					}
					plain := inspectionUISGR.ReplaceAllString(output, "")
					var values, ascii []byte
					rows := 0
					for _, line := range strings.Split(strings.TrimSuffix(plain, "\n"), "\n") {
						if display.VisibleWidth(line) > width {
							t.Fatalf("hex row exceeds width %d: %q", width, line)
						}
						if !strings.HasPrefix(line, "0x") {
							continue
						}
						rows++
						address, err := strconv.ParseUint(line[:18], 0, 64)
						if err != nil || address != 0x70000000+uint64(len(values)) {
							t.Fatalf("wrong address stride: %q recovered=%d", line, len(values))
						}
						body, side, ok := strings.Cut(line[20:], " |")
						if !ok || !strings.HasSuffix(side, "|") {
							t.Fatalf("missing ASCII column: %q", line)
						}
						ascii = append(ascii, strings.TrimSuffix(side, "|")...)
						for _, token := range inspectionUIHexValue.FindAllString(body, -1) {
							if token[0] == '[' {
								for _, field := range strings.Fields(token[1 : len(token)-1]) {
									value, err := strconv.ParseUint(field, 16, 8)
									if err != nil {
										t.Fatal(err)
									}
									values = append(values, byte(value))
								}
								continue
							}
							value, err := strconv.ParseUint(strings.TrimPrefix(token, "0x"), 16, 64)
							if err != nil {
								t.Fatal(err)
							}
							var word [8]byte
							binary.LittleEndian.PutUint64(word[:], value)
							values = append(values, word[:unit]...)
						}
					}
					rowBytes := 16
					if width == 80 {
						rowBytes = map[int]int{1: 14, 2: 12, 4: 12, 8: 16}[unit]
					}
					if !bytes.Equal(values, fixture.stack) || !bytes.Equal(ascii, fixture.stack) || rows != (len(fixture.stack)+rowBytes-1)/rowBytes {
						t.Fatalf("bytes missing/repeated: values=%x ascii=%x rows=%d output=%s", values, ascii, rows, plain)
					}
				})
			}
		}
	}
}

func TestSymbolUIHeadersAndRuntimeAddressProvenance(t *testing.T) {
	for _, width := range []int{80, 120} {
		for _, color := range []bool{false, true} {
			controller, _, _ := newInspectionTestController()
			mode := display.ColorNever
			if color {
				mode = display.ColorAlways
			}
			controller.renderer, _ = display.NewRenderer(display.Options{Mode: mode})
			path := "/" + strings.Repeat("long_日本語_path/", 12) + "quote\"\n\x1b]0;unsafe\a"
			module := &mappedELF{ID: "main", Path: path, MetadataPath: path, Proof: "proc-exe+auxv", Scope: "executable", BuildID: []byte{1, 2, 3}}
			longName := strings.Repeat("long_symbol_", 24)
			facts := []moduleSymbolFacts{{id: "main", path: path, proof: module.Proof, header: newMetadataModuleHeader(module), symbols: []inspect.Symbol{
				{ModuleID: "main", Name: "ordinary", Address: 0x401000, AddressKnown: true, Size: 7, Type: elf.STT_FUNC, Binding: elf.STB_GLOBAL, Section: 1, Value: 0x401000},
				{ModuleID: "main", Name: "constant", Address: 0x401000, AddressKnown: true, Type: elf.STT_NOTYPE, Section: elf.SHN_ABS, Value: 0x401000},
				{ModuleID: "main", Name: longName, Address: 0x404000, AddressKnown: true, Size: 8, Type: elf.STT_OBJECT, Section: 2, Version: "V\n\x1b", Value: 0x404000},
				{ModuleID: "main", Name: "unknown", Type: elf.STT_TLS, Section: elf.SHN_UNDEF, Value: 0x40},
			}}}
			mappings := []procMap{{Start: 0x401000, End: 0x402000, Read: true, Execute: true}, {Start: 0x404000, End: 0x405000, Read: true, Write: true}}
			output, err := inspectionUIOutput(t, controller, width, func() error {
				return controller.renderSymbolFactsMapped(context.Background(), facts, "", mappings, controller.writef)
			})
			if err != nil {
				t.Fatal(err)
			}
			plain := inspectionUISGR.ReplaceAllString(output, "")
			if strings.ContainsAny(plain, "\x1b\a") || metadataJoinedField(plain, "File") != strconv.QuoteToGraphic(path) || metadataJoinedField(plain, "Source proof") != "" || !strings.Contains(plain, "4 symbol(s)") {
				t.Fatalf("header facts lost/unsafe: %q", plain)
			}
			rows := 0
			for _, line := range strings.Split(strings.TrimSuffix(output, "\n"), "\n") {
				visible := inspectionUISGR.ReplaceAllString(line, "")
				if strings.Contains(visible, "version=") {
					rows++
					if strings.Contains(visible, longName) && display.VisibleWidth(visible) <= width {
						t.Fatal("long symbol row was prewrapped or truncated")
					}
					if strings.Contains(visible, `"constant"`) && (strings.Contains(line, "\x1b[35m0x") || !strings.Contains(visible, "absolute scalar")) {
						t.Fatalf("SHN_ABS was colored as runtime code: %q", line)
					}
					if color && strings.Contains(visible, `"ordinary"`) && (!strings.Contains(line, "\x1b[35m0x0000000000401000") || !strings.Contains(line, "\x1b[32m\"ordinary\"")) {
						t.Fatalf("typed symbol colors missing: %q", line)
					}
					continue
				}
				if display.VisibleWidth(line) > width {
					t.Fatalf("diagnostic wall remains at width %d: %q", width, line)
				}
			}
			if rows != 4 || !strings.Contains(plain, longName) || !strings.Contains(plain, "<unavailable>") || strings.Contains(output, "\x1b") != color || strings.Contains(plain, "section=SHN_UNDEF+") || !strings.Contains(plain, "section=1") {
				t.Fatalf("symbol rows/color/unknown changed: %q", output)
			}
		}
	}
}

func TestSymbolUIFilterOmitsOnlyHealthyNoMatchModules(t *testing.T) {
	controller, _, output := newInspectionTestController()
	facts := legacyFunctionFacts()
	facts = append(facts, moduleSymbolFacts{id: "hidden", path: "/healthy/path", symbols: []inspect.Symbol{{ModuleID: "hidden", Name: "irrelevant"}}})
	facts = append(facts, moduleSymbolFacts{id: "unknown", path: "/unknown/path", err: target.ErrUnavailable})
	err := controller.renderSymbolFacts(facts, "work")
	plain := output.String()
	if !errors.Is(err, target.ErrUnavailable) || strings.Contains(plain, "/healthy/path") || !strings.Contains(plain, "/unknown/path") || !strings.Contains(plain, "unavailable:") || !strings.Contains(plain, "1 symbol(s)") || strings.Contains(plain, "healthy no-match module") {
		t.Fatalf("filter hid unknown scope or retained empty module walls: %q %v", plain, err)
	}
	output.Reset()
	if err := controller.renderSymbolFacts(facts[:2], ""); err != nil || !strings.Contains(output.String(), "/healthy/path") || !strings.Contains(output.String(), `"irrelevant"`) || strings.Contains(output.String(), "healthy no-match") {
		t.Fatalf("unfiltered scope changed: %q %v", output.String(), err)
	}
	for _, test := range []struct {
		section elf.SectionIndex
		want    string
	}{{12, "12"}, {elf.SHN_UNDEF, "SHN_UNDEF"}, {elf.SHN_ABS, "SHN_ABS"}, {elf.SHN_COMMON, "SHN_COMMON"}, {elf.SHN_XINDEX + 1, "65536"}} {
		if got := symbolSectionText(test.section); got != test.want {
			t.Fatalf("section %d: %q want %q", test.section, got, test.want)
		}
	}
}

func TestDisassemblyUIFitsOrdinaryInstructionsAndKeepsBytes(t *testing.T) {
	for _, width := range []int{80, 120} {
		controller, fixture, _ := newInspectionTestController()
		fixture.code = append([]byte{0x55, 0x48, 0x89, 0xe5, 0x90, 0xc3}, bytes.Repeat([]byte{0x90}, 54)...)
		output, err := inspectionUIOutput(t, controller, width, func() error {
			return controller.showDisassemble(context.Background(), "--count 4")
		})
		if err != nil || len(fixture.codeCalls) != 1 || fixture.codeCalls[0] != (contextMemoryCall{fixture.snapshot.Memory, 0x401000, 60}) || len(fixture.stackCalls) != 0 {
			t.Fatalf("disassembly renderer changed reads: %v %+v", err, fixture.codeCalls)
		}
		for _, want := range []string{"55      push rbp", "4889e5  mov rbp, rsp", "90      nop", "c3      ret"} {
			if !strings.Contains(output, want) {
				t.Fatalf("instruction facts lost %q: %s", want, output)
			}
		}
		for _, line := range strings.Split(strings.TrimSuffix(output, "\n"), "\n") {
			if display.VisibleWidth(line) > width {
				t.Fatalf("ordinary instruction still overflows: %q", line)
			}
		}
		if strings.Count(output, "\n") != 5 {
			t.Fatalf("ordinary instructions wrapped unnecessarily: %s", output)
		}
	}
}

func TestFunctionDisassemblyUIKeepsDeclaredExtentAndEscapedHeader(t *testing.T) {
	for _, width := range []int{80, 120} {
		controller, fixture, _ := newInspectionTestController()
		fixture.code = []byte{0x55, 0x48, 0x89, 0xe5, 0x90, 0xc3}
		symbol := legacyFunctionFacts()[0].symbols[0]
		symbol.Name = strings.Repeat("long_日本語_function_", 8) + "\"\n\x1b]0;BAD\a"
		symbol.Size = 6
		location := native.CodeLocation{RawPC: symbol.Address + 1, InstructionPC: symbol.Address}
		output, err := inspectionUIOutput(t, controller, width, func() error {
			return controller.showFunctionCode(context.Background(), fixture.snapshot.Memory, symbol, location)
		})
		if err != nil || len(fixture.codeCalls) != 1 || fixture.codeCalls[0] != (contextMemoryCall{fixture.snapshot.Memory, symbol.Address, 6}) || len(fixture.stackCalls) != 0 {
			t.Fatalf("function renderer changed extent/read: %v %+v", err, fixture.codeCalls)
		}
		if metadataJoinedField(output, "Function") != strconv.QuoteToGraphic(symbol.Name) || metadataJoinedField(output, "Module") != strconv.QuoteToGraphic(symbol.ModuleID) || metadataJoinedField(output, "Address") != fmt.Sprintf("0x%016x", symbol.Address) || metadataJoinedField(output, "Extent") != "6 bytes" {
			t.Fatalf("function metadata lost: %s", output)
		}
		if strings.ContainsAny(output, "\x1b\a") || strings.Count(output, "  ret\n") != 1 || !strings.Contains(output, "4889e5  mov rbp, rsp") {
			t.Fatalf("function bytes/instructions unsafe or lost: %s", output)
		}
		for _, line := range strings.Split(strings.TrimSuffix(output, "\n"), "\n") {
			if display.VisibleWidth(line) > width {
				t.Fatalf("function metadata wall remains: %q", line)
			}
		}
	}
}
