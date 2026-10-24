package qemu

import (
	"context"
	"errors"
	"fastdbg2/target"
	"testing"
)

func TestSystemPhysicalModeRestoredAfterReadError(t *testing.T) {
	exchanges := testHandshake("400", testXML, "T05thread:1;")
	exchanges = append(exchanges, testExchange{"qqemu.PhyMemMode", "0"}, testExchange{"Qqemu.PhyMemMode:1", "OK"}, testExchange{"Hg1", "OK"}, testExchange{"m1000,8", "E14"}, testExchange{"Qqemu.PhyMemMode:0", "OK"}, testExchange{"m2000,1", "42"})
	s := testSession(t, exchanges)
	if _, err := s.ReadPhysicalMemory(0x1000, make([]byte, 8)); err == nil {
		t.Fatal("missing read error")
	}
	var data [1]byte
	if n, err := s.ReadMemory(0x2000, data[:]); err != nil || n != 1 || data[0] != 0x42 {
		t.Fatalf("%x %d %v", data, n, err)
	}
}
func TestSystemCPUSelectionAndAsyncResume(t *testing.T) {
	exchanges := testHandshake("400", testXML, "T05thread:1;")
	exchanges = append(exchanges, testExchange{"qfThreadInfo", "m1,2"}, testExchange{"qsThreadInfo", "l"}, testExchange{"Hg2", "OK"}, testExchange{"g", "01000000000000000200000000000000"}, testExchange{"vCont;s:2;c", "T05thread:2;"})
	s := testSession(t, exchanges)
	ids, err := s.Threads()
	if err != nil || len(ids) != 2 {
		t.Fatal(ids, err)
	}
	if err := s.SelectThread(2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadRegisters(); err != nil {
		t.Fatal(err)
	}
	op, err := s.StartCPU(2, true, true)
	if err != nil {
		t.Fatal(err)
	}
	stop, err := op.Wait(context.Background())
	if err != nil || stop.ThreadID == nil || *stop.ThreadID != 2 {
		t.Fatalf("%+v %v", stop, err)
	}
}
func TestSystemDuplicateCPUAndWatchCleanup(t *testing.T) {
	s := testSession(t, append(testHandshake("400", testXML, "T05thread:1;"), testExchange{"qfThreadInfo", "m1,1"}))
	if _, err := s.Threads(); !errors.Is(err, ErrProtocol) {
		t.Fatal(err)
	}
	s = testSession(t, append(testHandshake("400", testXML, "T05thread:1;"), testExchange{"Z2,1000,8", "OK"}, testExchange{"z2,1000,8", "OK"}, testExchange{"D", "OK"}))
	if err := s.AddHardwarePoint(HardwarePoint{Kind: 2, Address: 0x1000, Size: 8}); err != nil {
		t.Fatal(err)
	}
	stop, err := s.parseStop([]byte("T05thread:1;watch:1000;"))
	if err != nil || stop.Reason != target.StopWatchpoint || len(stop.Watchpoints) != 1 {
		t.Fatal(stop, err)
	}
	if err := s.Detach(); err != nil {
		t.Fatal(err)
	}
}
