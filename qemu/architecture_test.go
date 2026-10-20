package qemu

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"fastdbg2/target"
)

func aarch64CoreXML(pc string) string {
	var core strings.Builder
	core.WriteString(`<feature name="org.gnu.gdb.aarch64.core">`)
	for i := 0; i < 31; i++ {
		fmt.Fprintf(&core, `<reg name="x%d" bitsize="64"/>`, i)
	}
	fmt.Fprintf(&core, `<reg name="sp" bitsize="64"/><reg name="%s" bitsize="64"/><reg name="cpsr" bitsize="32"/></feature>`, pc)
	return core.String()
}

func xmlExchanges(annex, document string) []testExchange {
	var exchanges []testExchange
	for offset := 0; offset < len(document); {
		length := min(1024, len(document)-offset)
		prefix := "m"
		if offset+length == len(document) {
			prefix = "l"
		}
		exchanges = append(exchanges, testExchange{
			command: fmt.Sprintf("qXfer:features:read:%s:%x,400", annex, offset),
			reply:   prefix + document[offset:offset+length],
		})
		offset += length
	}
	return exchanges
}

func architectureHandshake(description, stop string) []testExchange {
	exchanges := []testExchange{{"qSupported:swbreak+;hwbreak+;xmlRegisters=i386,aarch64", "PacketSize=1000;qXfer:features:read+;swbreak+;hwbreak+"}}
	exchanges = append(exchanges, xmlExchanges("target.xml", description)...)
	return append(exchanges, testExchange{"vCont?", "vCont;c;C;s;S"}, testExchange{"?", stop})
}

func TestAArch64IncludedCoreAndOpaqueVectorRegister(t *testing.T) {
	description := `<target xmlns:xi="http://www.w3.org/2001/XInclude"><architecture>aarch64</architecture><xi:include href="core.xml"/><feature name="org.gnu.gdb.aarch64.sve"><reg name="z0" bitsize="128"/></feature></target>`
	exchanges := architectureHandshake(description, "T05thread:7;20:0300400000000000;swbreak:;")
	exchanges = append(exchanges[:2], append(xmlExchanges("core.xml", aarch64CoreXML("PC")), exchanges[2:]...)...)
	data := make([]byte, 33*8+4+16)
	binary.LittleEndian.PutUint64(data[32*8:], 0x400003)
	for i := range 16 {
		data[len(data)-16+i] = byte(i + 1)
	}
	exchanges = append(exchanges,
		testExchange{"Hg7", "OK"},
		testExchange{"g", hex.EncodeToString(data)},
		testExchange{"P20=0300400000000000", "OK"},
	)
	s := testSession(t, exchanges, Options{Timeout: time.Second, RegisterByteOrder: target.LittleEndian})
	if s.Architecture() != target.AArch64 || s.RegisterByteOrder() != target.LittleEndian {
		t.Fatalf("profile: %s, %s", s.Architecture(), s.RegisterByteOrder())
	}
	stop := s.LastStop()
	if stop.RawPC == nil || *stop.RawPC != 0x400003 || stop.Breakpoint == nil || *stop.Breakpoint != 0x400003 {
		t.Fatalf("raw PC was adjusted or missing: %+v", stop)
	}
	registers, err := s.ReadRegisters()
	if err != nil {
		t.Fatal(err)
	}
	if len(registers) != 35 || registers[32].Name != "PC" || registers[33].Bits != 32 || registers[34].Bits != 128 || !bytes.Equal(registers[34].Data, data[len(data)-16:]) {
		t.Fatalf("XML register data changed: %+v", registers)
	}
	if err := s.WriteRegisters([]target.Register{{Name: "PC", Bits: 64, Available: true, Data: data[32*8 : 33*8]}}); err != nil {
		t.Fatalf("raw register write was interpreted as an instruction constraint: %v", err)
	}
}

func TestAArch64BreakpointRangeAtAddressLimit(t *testing.T) {
	description := `<target><architecture>aarch64</architecture>` + aarch64CoreXML("pc") + `</target>`
	exchanges := architectureHandshake(description, "T05thread:7;")
	exchanges = append(exchanges,
		testExchange{"Z0,fffffffffffffffc,4", "OK"},
		testExchange{"z0,fffffffffffffffc,4", "OK"},
		testExchange{"Hg7", "OK"},
		testExchange{"Mffffffffffffffff,1:cc", "OK"},
	)
	s := testSession(t, exchanges, Options{Timeout: time.Second, RegisterByteOrder: target.LittleEndian})
	base := ^target.Address(0) - 3
	if err := s.AddBreakpoint(base); err != nil {
		t.Fatal(err)
	}
	generation := s.Generation()
	if err := s.AddBreakpoint(base + 1); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("unaligned breakpoint: %v", err)
	}
	for offset := target.Address(0); offset < 4; offset++ {
		if n, err := s.WriteMemory(base+offset, []byte{1}); n != 0 || !errors.Is(err, target.ErrInvalidState) {
			t.Fatalf("offset %d overlap n=%d err=%v", offset, n, err)
		}
	}
	if n, err := s.WriteMemory(base-1, []byte{1, 2}); n != 0 || !errors.Is(err, target.ErrInvalidState) {
		t.Fatalf("leading overlap n=%d err=%v", n, err)
	}
	if n, err := s.WriteMemory(base+3, nil); n != 0 || err != nil {
		t.Fatalf("empty write n=%d err=%v", n, err)
	}
	if n, err := s.WriteMemory(base+3, []byte{1, 2}); n != 0 || !errors.Is(err, target.ErrOverflow) {
		t.Fatalf("overflow write n=%d err=%v", n, err)
	}
	if s.Generation() != generation {
		t.Fatal("rejected writes changed generation")
	}
	if err := s.RemoveBreakpoint(base); err != nil {
		t.Fatal(err)
	}
	if n, err := s.WriteMemory(base+3, []byte{0xcc}); n != 1 || err != nil {
		t.Fatalf("last address write n=%d err=%v", n, err)
	}
}

func TestRegisterByteOrderPreservesAMD64Defaults(t *testing.T) {
	s := testSession(t, testHandshake("100", testXML, "S05"))
	if s.Architecture() != target.AMD64 || s.RegisterByteOrder() != target.LittleEndian {
		t.Fatalf("AMD64 defaults: %s, %s", s.Architecture(), s.RegisterByteOrder())
	}
	options, _ := normalizeOptions([]Options{{Timeout: time.Second, RegisterByteOrder: target.BigEndian}})
	if other, err := connect(testConnection(t, testHandshake("100", testXML, "S05")[:2]), options); other != nil || !errors.Is(err, target.ErrUnsupported) {
		t.Fatalf("contradictory AMD64 byte order: %v, %v", other, err)
	}
	if _, err := normalizeOptions([]Options{{RegisterByteOrder: target.ByteOrder(255)}}); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("invalid byte order accepted: %v", err)
	}
}

func TestArchitectureAndSemanticRegisterNamesAreNotGuessed(t *testing.T) {
	for _, test := range []struct {
		name string
		xml  string
		err  error
	}{
		{"aarch32", strings.Replace(testXML, "i386:x86-64", "arm", 1), target.ErrUnsupported},
		{"core casefold alias", `<target><architecture>aarch64</architecture>` + strings.Replace(aarch64CoreXML("pc"), `</feature>`, `<reg name="PC" bitsize="64"/></feature>`, 1) + `</target>`, target.ErrAmbiguous},
	} {
		t.Run(test.name, func(t *testing.T) {
			exchanges := architectureHandshake(test.xml, "S05")
			exchanges = exchanges[:len(exchanges)-2]
			options, _ := normalizeOptions([]Options{{Timeout: time.Second, RegisterByteOrder: target.LittleEndian}})
			if s, err := connect(testConnection(t, exchanges), options); s != nil || !errors.Is(err, test.err) {
				t.Fatalf("connect: %v, %v", s, err)
			}
		})
	}
}

func TestAArch64OptionalRegistersKeepExactCaseAndWidth(t *testing.T) {
	description := `<target><architecture>aarch64</architecture>` + aarch64CoreXML("pc") + `<feature name="org.gnu.gdb.aarch64.fpu"><reg name="fpcr" bitsize="32"/><reg name="fpsr" bitsize="32"/></feature><feature name="org.qemu.aarch64.system"><reg name="FPCR" bitsize="64"/><reg name="FPSR" bitsize="64"/></feature></target>`
	exchanges := architectureHandshake(description, "T05thread:1;")
	data := make([]byte, 33*8+4+4+4+8+8)
	binary.LittleEndian.PutUint32(data[268:], 0x11223344)
	binary.LittleEndian.PutUint32(data[272:], 0x55667788)
	binary.LittleEndian.PutUint64(data[276:], 0x0102030405060708)
	binary.LittleEndian.PutUint64(data[284:], 0x1112131415161718)
	exchanges = append(exchanges,
		testExchange{"Hg1", "OK"},
		testExchange{"g", hex.EncodeToString(data)},
		testExchange{"P22=44332211", "OK"},
		testExchange{"P24=0807060504030201", "OK"},
	)
	s := testSession(t, exchanges, Options{Timeout: time.Second, RegisterByteOrder: target.LittleEndian})
	registers, err := s.ReadRegisters()
	if err != nil {
		t.Fatal(err)
	}
	if len(registers) != 38 || registers[34].Name != "fpcr" || registers[34].Bits != 32 || registers[36].Name != "FPCR" || registers[36].Bits != 64 {
		t.Fatalf("optional raw register identity changed: %+v", registers)
	}
	if !bytes.Equal(registers[34].Data, data[268:272]) || !bytes.Equal(registers[36].Data, data[276:284]) {
		t.Fatal("optional raw register bytes changed")
	}
	if err := s.WriteRegisters([]target.Register{registers[34], registers[36]}); err != nil {
		t.Fatal(err)
	}
}

func TestAArch64OptionalPCDoesNotReplaceCorePC(t *testing.T) {
	description := `<target><architecture>aarch64</architecture>` + aarch64CoreXML("pc") + `<feature name="vendor.raw"><reg name="PC" bitsize="64"/></feature></target>`
	exchanges := architectureHandshake(description, "T05thread:7;20:xxxxxxxxxxxxxxxx;22:ffffffffffffffff;")
	exchanges = append(exchanges, testExchange{"vCont;s:7", "T05thread:7;20:0300400000000000;22:ffffffffffffffff;"})
	s := testSession(t, exchanges, Options{Timeout: time.Second, RegisterByteOrder: target.LittleEndian})
	if stop := s.LastStop(); stop.RawPC != nil || stop.Breakpoint != nil {
		t.Fatalf("optional PC interpreted as core PC: %+v", stop)
	}
	stop, err := s.Step(target.Signal{})
	if err != nil || stop.RawPC == nil || *stop.RawPC != 0x400003 {
		t.Fatalf("core PC replaced or altered: %+v, %v", stop, err)
	}
}
