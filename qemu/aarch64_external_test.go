package qemu_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fastdbg2/qemu"
	"fastdbg2/target"
)

func aarch64XML(first int) string {
	var xml strings.Builder
	xml.WriteString(`<target version="1.0"><architecture>aarch64</architecture><feature name="org.gnu.gdb.aarch64.core">`)
	for i := range 31 {
		fmt.Fprintf(&xml, `<reg name="x%d" bitsize="64" regnum="%d"/>`, i, first+i)
	}
	fmt.Fprintf(&xml, `<reg name="sp" bitsize="64" regnum="%d" type="data_ptr"/>`, first+31)
	fmt.Fprintf(&xml, `<reg name="pc" bitsize="64" regnum="%d" type="code_ptr"/>`, first+32)
	fmt.Fprintf(&xml, `<reg name="cpsr" bitsize="32" regnum="%d"/>`, first+33)
	xml.WriteString(`</feature></target>`)
	return xml.String()
}

func aarch64Wire(order target.ByteOrder, value uint64, bits int) string {
	var data [8]byte
	var byteOrder binary.ByteOrder = binary.LittleEndian
	if order == target.BigEndian {
		byteOrder = binary.BigEndian
	}
	if bits == 32 {
		byteOrder.PutUint32(data[:4], uint32(value))
	} else {
		byteOrder.PutUint64(data[:], value)
	}
	return hex.EncodeToString(data[:bits/8])
}

func aarch64Handshake(stub *externalStub, xml string) error {
	request, err := stub.request()
	if err != nil {
		return err
	}
	if !strings.HasPrefix(request, "qSupported:") {
		return fmt.Errorf("initial request = %q", request)
	}
	if err := stub.respond(externalEncode("PacketSize=1000;qXfer:features:read+;swbreak+"), true); err != nil {
		return err
	}
	for offset := 0; offset < len(xml); {
		request, err := stub.request()
		if err != nil {
			return err
		}
		var start, length int
		if n, err := fmt.Sscanf(request, "qXfer:features:read:target.xml:%x,%x", &start, &length); err != nil || n != 2 || start != offset || length <= 0 {
			return fmt.Errorf("unexpected XML request %q", request)
		}
		end := min(len(xml), offset+length)
		prefix := "m"
		if end == len(xml) {
			prefix = "l"
		}
		if err := stub.respond(externalEncode(prefix+xml[offset:end]), true); err != nil {
			return err
		}
		offset = end
	}
	return nil
}

func aarch64Connect(t *testing.T, order target.ByteOrder, xml, stop string, run func(*externalStub) error) (*qemu.Session, error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			done <- err
			return
		}
		stub := &externalStub{conn: conn, reader: bufio.NewReader(conn), ack: true}
		if err := aarch64Handshake(stub, xml); err != nil {
			done <- err
			return
		}
		if stop != "" {
			if err := stub.exchange("vCont?", "vCont;c;s;C;S"); err != nil {
				done <- err
				return
			}
			if err := stub.exchange("?", stop); err != nil {
				done <- err
				return
			}
		}
		done <- run(stub)
	}()
	t.Cleanup(func() {
		listener.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("AArch64 stub: %v", err)
			}
		case <-time.After(6 * time.Second):
			t.Error("AArch64 stub did not stop")
		}
	})
	session, err := qemu.Connect(listener.Addr().String(), qemu.Options{Timeout: time.Second, RegisterByteOrder: order})
	if session != nil {
		t.Cleanup(func() { session.Close() })
	}
	return session, err
}

func TestAArch64ExternalByteOrderAndXMLNumbers(t *testing.T) {
	for _, order := range []target.ByteOrder{target.LittleEndian, target.BigEndian} {
		t.Run(fmt.Sprint(order), func(t *testing.T) {
			const pc = uint64(0x1122334455667788)
			stop := "T05thread:1;60:" + aarch64Wire(order, pc, 64) + ";vendor:opaque;"
			session, err := aarch64Connect(t, order, aarch64XML(64), stop, func(stub *externalStub) error {
				if err := stub.exchange("Hg1", "OK"); err != nil {
					return err
				}
				for i := range 34 {
					bits := 64
					if i == 33 {
						bits = 32
					}
					value := aarch64Wire(order, uint64(i+1), bits)
					if i == 0 {
						value = strings.Repeat("x", 16)
					}
					if err := stub.exchange(fmt.Sprintf("p%x", 64+i), value); err != nil {
						return err
					}
				}
				if err := stub.exchange("P60="+aarch64Wire(order, pc+4, 64), "OK"); err != nil {
					return err
				}
				return stub.wantClosed()
			})
			if err != nil {
				t.Fatal(err)
			}
			if session.Architecture() != target.AArch64 || session.RegisterByteOrder() != order || session.LastStop().RawPC == nil || uint64(*session.LastStop().RawPC) != pc || session.LastStop().Raw != stop {
				t.Fatalf("architecture/stop = %s, %+v", session.Architecture(), session.LastStop())
			}
			registers, err := session.ReadRegisters()
			if err != nil || len(registers) != 34 {
				t.Fatalf("ReadRegisters = %d registers, %v", len(registers), err)
			}
			for i, reg := range registers {
				bits, name := 64, fmt.Sprintf("x%d", i)
				switch i {
				case 31:
					name = "sp"
				case 32:
					name = "pc"
				case 33:
					bits, name = 32, "cpsr"
				}
				if reg.Name != name || reg.Bits != bits || reg.Available != (i != 0) {
					t.Fatalf("register %d = %+v", i, reg)
				}
				if i != 0 && hex.EncodeToString(reg.Data) != aarch64Wire(order, uint64(i+1), bits) {
					t.Fatalf("register bytes were transformed: %+v", reg)
				}
			}
			value, _ := hex.DecodeString(aarch64Wire(order, pc+4, 64))
			if err := session.WriteRegisters([]target.Register{{Name: "pc", Bits: 64, Data: value, Available: true}}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAArch64ExternalRejectsMissingInformation(t *testing.T) {
	xml := aarch64XML(0)
	for _, test := range []struct {
		name  string
		order target.ByteOrder
		xml   string
		want  error
	}{
		{"byte_order", target.ByteOrderUnknown, xml, target.ErrUnknown},
		{"core_feature", target.LittleEndian, strings.Replace(xml, "org.gnu.gdb.aarch64.core", "vendor.core", 1), nil},
		{"missing_x15", target.LittleEndian, strings.Replace(xml, `<reg name="x15" bitsize="64" regnum="15"/>`, "", 1), nil},
		{"pc_width", target.LittleEndian, strings.Replace(xml, `name="pc" bitsize="64"`, `name="pc" bitsize="32"`, 1), nil},
		{"cpsr_width", target.LittleEndian, strings.Replace(xml, `name="cpsr" bitsize="32"`, `name="cpsr" bitsize="64"`, 1), nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			session, err := aarch64Connect(t, test.order, test.xml, "", (*externalStub).wantClosed)
			if err == nil || session != nil || (test.want != nil && !errors.Is(err, test.want)) {
				t.Fatalf("Connect = %v, %v", session, err)
			}
		})
	}
}

func TestAArch64ExternalShortGDoesNotSupplyRegisterValues(t *testing.T) {
	for _, response := range []string{"", "00"} {
		t.Run(fmt.Sprintf("p_reply_%d_bytes", len(response)/2), func(t *testing.T) {
			session, err := aarch64Connect(t, target.LittleEndian, aarch64XML(0), "T05thread:1;", func(stub *externalStub) error {
				if err := stub.exchange("Hg1", "OK"); err != nil {
					return err
				}
				if err := stub.exchange("g", aarch64Wire(target.LittleEndian, 99, 64)); err != nil {
					return err
				}
				if err := stub.exchange("p0", response); err != nil {
					return err
				}
				return stub.wantClosed()
			})
			if err != nil {
				t.Fatal(err)
			}
			registers, err := session.ReadRegisters()
			if err == nil || len(registers) != 0 {
				t.Fatalf("short/unknown p reply supplied guessed registers: %+v, %v", registers, err)
			}
		})
	}
}

func TestAArch64ExternalBreakpointExtentAndRawStops(t *testing.T) {
	session, err := aarch64Connect(t, target.LittleEndian, aarch64XML(0), "T05thread:1;", func(stub *externalStub) error {
		for _, exchange := range [][2]string{
			{"Z0,4000,4", "OK"},
			{"Hg1", "OK"},
			{"M4004,1:aa", "OK"},
			{"vCont;c", "T05thread:1;20:0040000000000000;swbreak:;"},
			{"z0,4000,4", "OK"},
			{"vCont;s:1", "T05thread:1;20:0440000000000000;"},
		} {
			if err := stub.exchange(exchange[0], exchange[1]); err != nil {
				return err
			}
		}
		return stub.wantClosed()
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := session.AddBreakpoint(0x4001); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("unaligned AddBreakpoint = %v", err)
	}
	if err := session.AddBreakpoint(0x4000); err != nil {
		t.Fatal(err)
	}
	for _, write := range []struct {
		addr target.Address
		size int
	}{{0x3fff, 2}, {0x4000, 1}, {0x4001, 1}, {0x4002, 1}, {0x4003, 1}} {
		if n, err := session.WriteMemory(write.addr, bytes.Repeat([]byte{0xaa}, write.size)); n != 0 || !errors.Is(err, target.ErrInvalidState) {
			t.Fatalf("overlapping WriteMemory(%#x, %d) = %d, %v", write.addr, write.size, n, err)
		}
	}
	if n, err := session.WriteMemory(0x4004, []byte{0xaa}); n != 1 || err != nil {
		t.Fatalf("adjacent WriteMemory = %d, %v", n, err)
	}
	stop, err := session.Continue(target.Signal{})
	if err != nil || stop.RawPC == nil || *stop.RawPC != 0x4000 || stop.Breakpoint == nil || *stop.Breakpoint != 0x4000 || stop.Reason != target.StopBreakpoint {
		t.Fatalf("breakpoint stop = %+v, %v", stop, err)
	}
	if err := session.RemoveBreakpoint(0x4000); err != nil {
		t.Fatal(err)
	}
	stop, err = session.Step(target.Signal{})
	if err != nil || stop.RawPC == nil || *stop.RawPC != 0x4004 || stop.Reason != target.StopSignal {
		t.Fatalf("step stop = %+v, %v", stop, err)
	}
}

func aarch64ELF(order target.ByteOrder) ([]byte, target.Address, []byte) {
	const base = 0x40200000
	const entry = base + 0x100
	file := make([]byte, 0x200)
	copy(file, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	var byteOrder binary.ByteOrder = binary.LittleEndian
	if order == target.BigEndian {
		file[5] = 2
		byteOrder = binary.BigEndian
	}
	byteOrder.PutUint16(file[16:], 2)
	byteOrder.PutUint16(file[18:], 183)
	byteOrder.PutUint32(file[20:], 1)
	byteOrder.PutUint64(file[24:], entry)
	byteOrder.PutUint64(file[32:], 64)
	byteOrder.PutUint16(file[52:], 64)
	byteOrder.PutUint16(file[54:], 56)
	byteOrder.PutUint16(file[56:], 1)
	byteOrder.PutUint32(file[64:], 1)
	byteOrder.PutUint32(file[68:], 7)
	byteOrder.PutUint64(file[80:], base)
	byteOrder.PutUint64(file[88:], base)
	byteOrder.PutUint64(file[96:], uint64(len(file)))
	byteOrder.PutUint64(file[104:], uint64(len(file)))
	byteOrder.PutUint64(file[112:], 0x1000)
	code := []uint32{0xd2800240, 0x91000400, 0x91000400, 0x17ffffff, 0xd28004a0, 0xd2800ba8, 0xd4000001}
	for i, instruction := range code {
		binary.LittleEndian.PutUint32(file[0x100+4*i:], instruction)
	}
	return file, entry, file[0x100 : 0x100+4*len(code)]
}

func aarch64ReadValue(t *testing.T, session *qemu.Session, order target.ByteOrder, name string) uint64 {
	t.Helper()
	registers, err := session.ReadRegisters()
	if err != nil {
		t.Fatal(err)
	}
	for _, reg := range registers {
		if reg.Name != name {
			continue
		}
		if !reg.Available || reg.Bits != 64 || len(reg.Data) != 8 {
			t.Fatalf("register %s = %+v", name, reg)
		}
		if order == target.BigEndian {
			return binary.BigEndian.Uint64(reg.Data)
		}
		return binary.LittleEndian.Uint64(reg.Data)
	}
	t.Fatalf("register %s missing", name)
	return 0
}

func aarch64WriteValue(t *testing.T, session *qemu.Session, order target.ByteOrder, name string, value uint64) {
	t.Helper()
	data, err := hex.DecodeString(aarch64Wire(order, value, 64))
	if err != nil {
		t.Fatal(err)
	}
	if err := session.WriteRegisters([]target.Register{{Name: name, Bits: 64, Data: data, Available: true}}); err != nil {
		t.Fatal(err)
	}
}

type aarch64StopResult struct {
	stop target.Stop
	err  error
}

func aarch64StopAsync(operation func(target.Signal) (target.Stop, error)) <-chan aarch64StopResult {
	done := make(chan aarch64StopResult, 1)
	go func() {
		stop, err := operation(target.Signal{})
		done <- aarch64StopResult{stop, err}
	}()
	return done
}

func aarch64AwaitStop(t *testing.T, done <-chan aarch64StopResult) target.Stop {
	t.Helper()
	select {
	case result := <-done:
		if result.err != nil {
			t.Fatal(result.err)
		}
		return result.stop
	case <-time.After(3 * time.Second):
		t.Fatal("QEMU did not report a stop")
		return target.Stop{}
	}
}

func aarch64Bridge(t *testing.T, socket, transcript string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(transcript)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		client, err := listener.Accept()
		if err != nil {
			return
		}
		defer client.Close()
		guest, err := net.DialTimeout("unix", socket, time.Second)
		if err != nil {
			return
		}
		defer guest.Close()
		client.SetDeadline(time.Now().Add(15 * time.Second))
		guest.SetDeadline(time.Now().Add(15 * time.Second))
		copied := make(chan struct{})
		go func() {
			io.Copy(io.MultiWriter(client, log), guest)
			client.Close()
			guest.Close()
			close(copied)
		}()
		io.Copy(io.MultiWriter(guest, log), client)
		client.Close()
		guest.Close()
		<-copied
	}()
	t.Cleanup(func() {
		listener.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("QEMU bridge did not stop")
		}
		log.Close()
	})
	return listener.Addr().String()
}

func TestAArch64ExternalLiveSmoke(t *testing.T) {
	root := os.Getenv("FASTDBG2_AARCH64_SMOKE_DIR")
	if root == "" {
		t.Skip("set FASTDBG2_AARCH64_SMOKE_DIR to a workspace directory to run live QEMU")
	}
	if !filepath.IsAbs(root) {
		t.Fatal("FASTDBG2_AARCH64_SMOKE_DIR must be absolute")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		binary string
		order  target.ByteOrder
		system bool
	}{
		{"user_le", "qemu-aarch64", target.LittleEndian, false},
		{"user_be", "qemu-aarch64_be", target.BigEndian, false},
		{"system_le", "qemu-system-aarch64", target.LittleEndian, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			tool, err := exec.LookPath(test.binary)
			if err != nil {
				t.Fatal(err)
			}
			dir, err := os.MkdirTemp(root, test.name+"-")
			if err != nil {
				t.Fatal(err)
			}
			file, entry, code := aarch64ELF(test.order)
			executable := filepath.Join(dir, "fixture.elf")
			if err := os.WriteFile(executable, file, 0o700); err != nil {
				t.Fatal(err)
			}
			socket := filepath.Join(dir, "gdb.sock")
			args := []string{"-cpu", "cortex-a57", "-g", socket, executable}
			if test.system {
				args = []string{"-machine", "virt", "-cpu", "cortex-a57", "-accel", "tcg", "-m", "64M", "-display", "none", "-monitor", "none", "-serial", "none", "-nodefaults", "-S", "-gdb", "unix:" + socket + ",server=on,wait=off", "-device", "loader,file=" + executable + ",cpu-num=0"}
			}
			log, err := os.Create(filepath.Join(dir, "qemu.log"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { log.Close() })
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, tool, args...)
			command.Stdout, command.Stderr, command.Dir = log, log, dir
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			waited := make(chan struct{})
			var waitErr error
			go func() {
				waitErr = command.Wait()
				close(waited)
			}()
			t.Cleanup(func() {
				select {
				case <-waited:
					return
				default:
					command.Process.Kill()
				}
				select {
				case <-waited:
				case <-time.After(3 * time.Second):
					t.Error("QEMU child was not reaped")
				}
			})
			for deadline := time.Now().Add(3 * time.Second); ; {
				if info, err := os.Stat(socket); err == nil && info.Mode()&os.ModeSocket != 0 {
					break
				}
				select {
				case <-waited:
					t.Fatalf("QEMU exited before listening: %v; log %s", waitErr, dir)
				default:
				}
				if time.Now().After(deadline) {
					t.Fatalf("QEMU socket did not appear; log %s", dir)
				}
				time.Sleep(time.Millisecond)
			}
			address := aarch64Bridge(t, socket, filepath.Join(dir, "rsp.log"))
			session, err := qemu.Connect(address, qemu.Options{Timeout: time.Second, RegisterByteOrder: test.order})
			if err != nil {
				t.Fatalf("Connect: %v; artifacts %s", err, dir)
			}
			t.Cleanup(func() { session.Close() })
			if session.Architecture() != target.AArch64 || session.RegisterByteOrder() != test.order {
				t.Fatalf("session profile = %s, %v", session.Architecture(), session.RegisterByteOrder())
			}
			if pc := aarch64ReadValue(t, session, test.order, "pc"); pc != uint64(entry) {
				t.Fatalf("entry PC = %#x, want %#x", pc, entry)
			}
			memory := make([]byte, len(code))
			if n, err := session.ReadMemory(entry, memory); err != nil || n != len(memory) || !bytes.Equal(memory, code) {
				t.Fatalf("code memory = %x (%d), %v", memory, n, err)
			}
			scratch := []byte{0x01, 0x23, 0x45, 0x67}
			if n, err := session.WriteMemory(entry+64, scratch); err != nil || n != len(scratch) {
				t.Fatalf("WriteMemory = %d, %v", n, err)
			}
			readback := make([]byte, len(scratch))
			if n, err := session.ReadMemory(entry+64, readback); err != nil || n != len(readback) || !bytes.Equal(readback, scratch) {
				t.Fatalf("memory bytes changed order: %x, %d, %v", readback, n, err)
			}
			aarch64WriteValue(t, session, test.order, "x7", 0x1122334455667788)
			if value := aarch64ReadValue(t, session, test.order, "x7"); value != 0x1122334455667788 {
				t.Fatalf("written x7 = %#x", value)
			}
			if err := session.AddBreakpoint(entry + 4); err != nil {
				t.Fatal(err)
			}
			stop := aarch64AwaitStop(t, aarch64StopAsync(session.Continue))
			if stop.Signal.Domain != target.SignalGDB || stop.Signal.Number != 5 {
				t.Fatalf("breakpoint signal = %+v", stop)
			}
			if pc := aarch64ReadValue(t, session, test.order, "pc"); pc != uint64(entry+4) {
				t.Fatalf("breakpoint PC = %#x", pc)
			}
			if err := session.RemoveBreakpoint(entry + 4); err != nil {
				t.Fatal(err)
			}
			aarch64AwaitStop(t, aarch64StopAsync(session.Step))
			if pc := aarch64ReadValue(t, session, test.order, "pc"); pc != uint64(entry+8) {
				t.Fatalf("stepped PC = %#x", pc)
			}
			if value := aarch64ReadValue(t, session, test.order, "x0"); value != 19 {
				t.Fatalf("stepped x0 = %d", value)
			}
			if test.system {
				continued := aarch64StopAsync(session.Continue)
				for deadline := time.Now().Add(2 * time.Second); session.State() != target.StateRunning; {
					if time.Now().After(deadline) {
						t.Fatal("Continue did not enter running state")
					}
					time.Sleep(time.Millisecond)
				}
				if err := session.Interrupt(); err != nil {
					t.Fatal(err)
				}
				stop = aarch64AwaitStop(t, continued)
				if stop.Signal.Domain != target.SignalGDB || stop.Signal.Number != 2 {
					t.Fatalf("interrupt stop = %+v", stop)
				}
				if err := session.Detach(); err != nil {
					t.Fatal(err)
				}
				t.Logf("%s: registers, memory, breakpoint, step, continue, interrupt, detach passed; artifacts %s", test.binary, dir)
			} else {
				aarch64WriteValue(t, session, test.order, "pc", uint64(entry+16))
				stop = aarch64AwaitStop(t, aarch64StopAsync(session.Continue))
				if stop.Reason != target.StopExited || stop.ExitCode == nil || *stop.ExitCode != 37 {
					t.Fatalf("exit stop = %+v", stop)
				}
				select {
				case <-waited:
					var exit *exec.ExitError
					if !errors.As(waitErr, &exit) || exit.ExitCode() != 37 {
						t.Fatalf("QEMU exit = %v", waitErr)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("QEMU did not exit")
				}
				t.Logf("%s: registers, memory, breakpoint, step, continue, exit passed; raw interrupt not covered by user smoke; artifacts %s", test.binary, dir)
			}
		})
	}
}
