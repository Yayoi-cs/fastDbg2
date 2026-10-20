package qemu

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"fastdbg2/qemu/amd64"
	"fastdbg2/target"
)

type testExchange struct {
	command string
	reply   string
}

const testXML = `<target><architecture>i386:x86-64</architecture><feature name="core"><reg name="rax" bitsize="64"/><reg name="rip" bitsize="64" regnum="1"/></feature></target>`

func testHandshake(packetSize, description, stop string) []testExchange {
	return []testExchange{
		{"qSupported:swbreak+;hwbreak+;xmlRegisters=i386,aarch64", "PacketSize=" + packetSize + ";qXfer:features:read+;swbreak+;hwbreak+"},
		{"qXfer:features:read:target.xml:0,400", "l" + description},
		{"vCont?", "vCont;c;C;s;S"},
		{"?", stop},
	}
}

func testSession(t *testing.T, exchanges []testExchange, values ...Options) *Session {
	t.Helper()
	conn := testConnection(t, exchanges)
	if len(values) == 0 {
		values = []Options{{Timeout: time.Second}}
	}
	options, err := normalizeOptions(values)
	if err != nil {
		t.Fatal(err)
	}
	s, err := connect(conn, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func testConnection(t *testing.T, exchanges []testExchange) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		server.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(server)
		for _, exchange := range exchanges {
			command, err := testReadPacket(r)
			if err != nil {
				done <- fmt.Errorf("waiting for %q: %w", exchange.command, err)
				return
			}
			if command != exchange.command {
				done <- fmt.Errorf("received %q, want %q", command, exchange.command)
				return
			}
			if _, err := server.Write(append([]byte{'+'}, encodePacket([]byte(exchange.reply))...)); err != nil {
				done <- err
				return
			}
			ack, err := r.ReadByte()
			if err != nil || ack != '+' {
				done <- fmt.Errorf("missing response acknowledgment: %x, %v", ack, err)
				return
			}
		}
		command, err := testReadPacket(r)
		if err == nil {
			done <- fmt.Errorf("unexpected extra command: %q", command)
		} else if !errors.Is(err, io.EOF) {
			done <- fmt.Errorf("mock did not close cleanly: %w", err)
		} else {
			done <- nil
		}
	}()
	t.Cleanup(func() {
		client.Close()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return client
}

func testReadPacket(r *bufio.Reader) (string, error) {
	b, err := r.ReadByte()
	if err != nil {
		return "", err
	}
	if b != '$' {
		return "", fmt.Errorf("expected frame start, got %x", b)
	}
	data, err := r.ReadBytes('#')
	if err != nil {
		return "", err
	}
	var checksum [2]byte
	if _, err := io.ReadFull(r, checksum[:]); err != nil {
		return "", err
	}
	data = data[:len(data)-1]
	var sum byte
	for _, b := range data {
		sum += b
	}
	decoded, err := hex.DecodeString(string(checksum[:]))
	if err != nil || decoded[0] != sum {
		return "", fmt.Errorf("invalid command checksum")
	}
	return string(data), nil
}

func TestRegistersUseXMLNumbersAndUnavailableValues(t *testing.T) {
	description := `<target xmlns:xi="http://www.w3.org/2001/XInclude"><architecture>i386:x86-64</architecture><xi:include href="core.xml"/></target>`
	feature := `<feature name="core"><reg name="rip" bitsize="64" regnum="16"/><reg name="eflags" bitsize="32"/><reg name="rax" bitsize="64" regnum="0"/></feature>`
	exchanges := testHandshake("100", description, "T05thread:2;")
	exchanges = append(exchanges[:2], append([]testExchange{{"qXfer:features:read:core.xml:0,400", "l" + feature}}, exchanges[2:]...)...)
	exchanges = append(exchanges,
		testExchange{"Hg2", "OK"},
		testExchange{"p0", "0102030405060708"},
		testExchange{"p10", "xxxxxxxxxxxxxxxx"},
		testExchange{"p11", "02020000"},
		testExchange{"P0=1100000000000000", "OK"},
		testExchange{"P10=2200000000000000", "E0a"},
	)
	s := testSession(t, exchanges)
	registers, err := s.ReadRegisters()
	if err != nil {
		t.Fatal(err)
	}
	if len(registers) != 3 || registers[0].Name != "rax" || registers[1].Name != "rip" || registers[2].Name != "eflags" {
		t.Fatalf("unexpected register order: %+v", registers)
	}
	if !bytes.Equal(registers[0].Data, []byte{1, 2, 3, 4, 5, 6, 7, 8}) || !registers[0].Available || registers[1].Available || registers[1].Data != nil {
		t.Fatalf("incorrect raw/unavailable values: %+v", registers)
	}
	before := s.Generation()
	if err := s.WriteRegisters([]target.Register{{Name: "rax", Bits: 64, Data: make([]byte, 8)}}); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("unavailable write: %v", err)
	}
	if s.Generation() != before {
		t.Fatal("invalid register write changed generation")
	}
	err = s.WriteRegisters([]target.Register{
		{Name: "rax", Bits: 64, Data: []byte{0x11, 0, 0, 0, 0, 0, 0, 0}, Available: true},
		{Name: "rip", Bits: 64, Data: []byte{0x22, 0, 0, 0, 0, 0, 0, 0}, Available: true},
	})
	var partial *target.PartialError
	var remote *RemoteError
	if !errors.As(err, &partial) || partial.Completed != 1 || partial.Total != 2 || !errors.As(err, &remote) || remote.Code != 10 {
		t.Fatalf("wrong partial register write: %v", err)
	}
}

func TestMemoryPartialReadAndWriteAndBreakpointOverlap(t *testing.T) {
	exchanges := testHandshake("40", testXML, "T05thread:1;")
	exchanges = append(exchanges,
		testExchange{"Hg1", "OK"},
		testExchange{"m1000,20", strings.Repeat("ab", 32)},
		testExchange{"m1020,20", "01020304"},
		testExchange{"Z0,1000,1", "OK"},
		testExchange{"z0,1000,1", "OK"},
		testExchange{"M1000,1b:" + strings.Repeat("01", 27), "OK"},
		testExchange{"M101b,17:" + strings.Repeat("01", 23), "E01"},
	)
	s := testSession(t, exchanges)
	buffer := bytes.Repeat([]byte{0xee}, 80)
	n, err := s.ReadMemory(0x1000, buffer)
	if n != 36 || !errors.Is(err, io.ErrUnexpectedEOF) || !errors.Is(err, target.ErrPartial) || buffer[35] != 4 || buffer[36] != 0xee {
		t.Fatalf("short read n=%d err=%v buffer=%x", n, err, buffer)
	}
	if err := s.AddBreakpoint(0x1000); err != nil {
		t.Fatal(err)
	}
	before := s.Generation()
	if n, err := s.WriteMemory(0xfff, []byte{1, 2}); n != 0 || !errors.Is(err, target.ErrInvalidState) {
		t.Fatalf("breakpoint overlap n=%d err=%v", n, err)
	}
	if s.Generation() != before {
		t.Fatal("rejected overlap changed generation")
	}
	if err := s.RemoveBreakpoint(0x1000); err != nil {
		t.Fatal(err)
	}
	n, err = s.WriteMemory(0x1000, bytes.Repeat([]byte{1}, 50))
	var partial *target.PartialError
	if n != 27 || !errors.As(err, &partial) || partial.Completed != 27 || partial.Total != 50 {
		t.Fatalf("partial write n=%d err=%v", n, err)
	}
	if n, err := s.WriteMemory(^target.Address(0), []byte{1, 2}); n != 0 || !errors.Is(err, target.ErrOverflow) {
		t.Fatalf("overflow n=%d err=%v", n, err)
	}
}

func TestCurrentThreadIsQueriedWithoutGuessing(t *testing.T) {
	exchanges := testHandshake("100", testXML, "S05")
	exchanges = append(exchanges,
		testExchange{"qC", "QC2a"},
		testExchange{"Hg2a", "OK"},
		testExchange{"g", strings.Repeat("00", 16)},
		testExchange{"vCont;s:2a", "S05"},
		testExchange{"qC", ""},
	)
	s := testSession(t, exchanges)
	if _, err := s.ReadRegisters(); err != nil {
		t.Fatal(err)
	}
	stop, err := s.Step(target.Signal{})
	if err != nil || stop.Reason != target.StopSignal || stop.ThreadID != nil || stop.Breakpoint != nil {
		t.Fatalf("step inferred information: %+v, %v", stop, err)
	}
	if _, err := s.ReadRegisters(); !errors.Is(err, target.ErrUnknown) {
		t.Fatalf("missing current thread: %v", err)
	}
}

func TestStopRepliesDoNotAdjustRegistersOrGuessReasons(t *testing.T) {
	s := &Session{
		features: map[string]string{"swbreak": "+", "hwbreak": "+"},
		profile:  amd64.Descriptor(), registerByteOrder: target.LittleEndian,
		registers: []registerDefinition{{number: 16, name: "rip", bits: 64}},
	}
	for _, raw := range []string{"S05", "T05thread:1;", "T05future-event:abc;"} {
		stop, err := s.parseStop([]byte(raw))
		if err != nil || stop.Reason != target.StopSignal || stop.Breakpoint != nil || stop.RawPC != nil || stop.Signal.Domain != target.SignalGDB || stop.Raw != raw {
			t.Fatalf("guessed stop data: %q %+v %v", raw, stop, err)
		}
	}
	stop, err := s.parseStop([]byte("T05thread:1;10:0110000000000000;swbreak:;"))
	if err != nil || stop.Reason != target.StopBreakpoint || stop.RawPC == nil || *stop.RawPC != 0x1001 || stop.Breakpoint == nil || *stop.Breakpoint != 0x1001 {
		t.Fatalf("raw PC changed: %+v %v", stop, err)
	}
	if _, err := s.parseStop([]byte("T05thread:p1.2;")); !errors.Is(err, target.ErrUnsupported) {
		t.Fatalf("multiprocess accepted: %v", err)
	}
	if _, err := s.parseStop([]byte("T05swbreak:;hwbreak:;")); !errors.Is(err, ErrProtocol) {
		t.Fatalf("conflicting stop reasons: %v", err)
	}
}

func TestTargetDescriptionRejectsMissingAndContradictoryInformation(t *testing.T) {
	cases := []struct {
		name string
		xml  string
		err  error
	}{
		{"wrong architecture", strings.Replace(testXML, "i386:x86-64", "riscv:rv64", 1), target.ErrUnsupported},
		{"missing registers", `<target><architecture>i386:x86-64</architecture></target>`, target.ErrUnknown},
		{"duplicate number", strings.Replace(testXML, `regnum="1"`, `regnum="0"`, 1), ErrProtocol},
		{"non-byte register", strings.Replace(testXML, `bitsize="64"`, `bitsize="63"`, 1), target.ErrUnsupported},
		{"trailing document", testXML + `<feature/>`, ErrProtocol},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			exchanges := testHandshake("100", item.xml, "S05")[:2]
			options, _ := normalizeOptions([]Options{{Timeout: time.Second}})
			s, err := connect(testConnection(t, exchanges), options)
			if s != nil || !errors.Is(err, item.err) {
				t.Fatalf("connect result %v, %v", s, err)
			}
		})
	}
}

func TestPacketSizeAndTargetXMLCannotBeGuessed(t *testing.T) {
	for _, feature := range []string{"qXfer:features:read+", "PacketSize=100"} {
		t.Run(feature, func(t *testing.T) {
			options, _ := normalizeOptions([]Options{{Timeout: time.Second}})
			conn := testConnection(t, []testExchange{{"qSupported:swbreak+;hwbreak+;xmlRegisters=i386,aarch64", feature}})
			if s, err := connect(conn, options); s != nil || err == nil {
				t.Fatalf("accepted incomplete features: %v, %v", s, err)
			}
		})
	}
}

func TestEmptyMutationReplyIsUnsupported(t *testing.T) {
	exchanges := testHandshake("100", testXML, "T05thread:1;")
	exchanges = append(exchanges, testExchange{"Z0,1000,1", ""})
	s := testSession(t, exchanges)
	if err := s.AddBreakpoint(0x1000); !errors.Is(err, target.ErrUnsupported) {
		t.Fatalf("empty breakpoint reply: %v", err)
	}
	if _, exists := s.breakpoints[0x1000]; exists {
		t.Fatal("unsupported breakpoint was registered")
	}
}

func TestShortGReplyIsDiscardedAndEveryRegisterIsReadByNumber(t *testing.T) {
	exchanges := testHandshake("100", testXML, "T05thread:1;")
	exchanges = append(exchanges,
		testExchange{"Hg1", "OK"},
		testExchange{"g", "aaaaaaaaaaaaaaaa"},
		testExchange{"p0", "0102030405060708"},
		testExchange{"p1", "xxxxxxxxxxxxxxxx"},
	)
	s := testSession(t, exchanges)
	registers, err := s.ReadRegisters()
	if err != nil {
		t.Fatal(err)
	}
	if len(registers) != 2 || !bytes.Equal(registers[0].Data, []byte{1, 2, 3, 4, 5, 6, 7, 8}) || registers[1].Available || registers[1].Data != nil {
		t.Fatalf("g prefix reused or unavailable value invented: %+v", registers)
	}
}
