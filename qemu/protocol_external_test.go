package qemu_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"fastdbg2/qemu"
	"fastdbg2/target"
)

type externalStub struct {
	conn       net.Conn
	reader     *bufio.Reader
	ack        bool
	fragmented bool
}

func externalFrame(encoded []byte) []byte {
	var sum byte
	for _, b := range encoded {
		sum += b
	}
	return []byte(fmt.Sprintf("$%s#%02x", encoded, sum))
}

func externalEncode(body string) []byte {
	encoded := make([]byte, 0, len(body))
	for _, b := range []byte(body) {
		if strings.ContainsRune("$#}*", rune(b)) {
			encoded = append(encoded, '}', b^0x20)
		} else {
			encoded = append(encoded, b)
		}
	}
	return encoded
}

func (s *externalStub) write(data []byte) error {
	for len(data) != 0 {
		n := len(data)
		if s.fragmented {
			n = min(n, 3)
		}
		written, err := s.conn.Write(data[:n])
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrNoProgress
		}
		data = data[written:]
	}
	return nil
}

func (s *externalStub) wantByte(want byte) error {
	b, err := s.reader.ReadByte()
	if err != nil {
		return err
	}
	if b != want {
		return fmt.Errorf("got byte %#x, want %#x", b, want)
	}
	return nil
}

func (s *externalStub) request() (string, error) {
	if err := s.wantByte('$'); err != nil {
		return "", err
	}
	var body []byte
	var sum byte
	for {
		b, err := s.reader.ReadByte()
		if err != nil {
			return "", err
		}
		if b == '#' {
			break
		}
		sum += b
		if b == '}' {
			b, err = s.reader.ReadByte()
			if err != nil {
				return "", err
			}
			sum += b
			b ^= 0x20
		}
		body = append(body, b)
	}
	var checksum [2]byte
	if _, err := io.ReadFull(s.reader, checksum[:]); err != nil {
		return "", err
	}
	want, err := strconv.ParseUint(string(checksum[:]), 16, 8)
	if err != nil || sum != byte(want) {
		return "", fmt.Errorf("invalid command checksum %q for %q", checksum, body)
	}
	return string(body), nil
}

func (s *externalStub) wantRequest(want string) error {
	request, err := s.request()
	if err != nil {
		return err
	}
	if request != want {
		return fmt.Errorf("got request %q, want %q", request, want)
	}
	return nil
}

func (s *externalStub) respond(encoded []byte, commandAck bool) error {
	frame := externalFrame(encoded)
	if s.ack && commandAck {
		frame = append([]byte{'+'}, frame...)
	}
	if err := s.write(frame); err != nil {
		return err
	}
	if s.ack {
		return s.wantByte('+')
	}
	return nil
}

func (s *externalStub) exchange(request, response string) error {
	if err := s.wantRequest(request); err != nil {
		return err
	}
	return s.respond(externalEncode(response), true)
}

func (s *externalStub) handshake(noAck, corruptFirst bool) error {
	request, err := s.request()
	if err != nil {
		return err
	}
	if !strings.HasPrefix(request, "qSupported:") {
		return fmt.Errorf("got initial request %q", request)
	}
	features := "PacketSize=400;qXfer:features:read+;swbreak+"
	if noAck {
		features += ";QStartNoAckMode+"
	}
	if corruptFirst {
		bad := externalFrame(externalEncode(features))
		if bad[len(bad)-1] == '0' {
			bad[len(bad)-1] = '1'
		} else {
			bad[len(bad)-1] = '0'
		}
		if err := s.write(append([]byte{'+'}, bad...)); err != nil {
			return err
		}
		if err := s.wantByte('-'); err != nil {
			return err
		}
	}
	if err := s.respond(externalEncode(features), !corruptFirst); err != nil {
		return err
	}
	if noAck {
		if err := s.exchange("QStartNoAckMode", "OK"); err != nil {
			return err
		}
		s.ack = false
	}
	request, err = s.request()
	if err != nil {
		return err
	}
	if !strings.HasPrefix(request, "qXfer:features:read:target.xml:0,") {
		return fmt.Errorf("got target description request %q", request)
	}
	xml := `l<target version="1.0"><architecture>i386:x86-64</architecture><feature name="core$#}*"><reg name="rip" bitsize="64" regnum="0"/></feature></target>`
	if err := s.respond(externalEncode(xml), true); err != nil {
		return err
	}
	if err := s.exchange("vCont?", "vCont;c;s;C;S"); err != nil {
		return err
	}
	return s.exchange("?", "T05thread:1;")
}

func (s *externalStub) wantClosed() error {
	b, err := s.reader.ReadByte()
	if errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("unexpected byte %#x before peer close", b)
}

func externalConnect(t *testing.T, options qemu.Options, noAck, corruptFirst bool, run func(*externalStub) error) *qemu.Session {
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
		stub := &externalStub{conn: conn, reader: bufio.NewReader(conn), ack: true, fragmented: corruptFirst}
		if err := stub.handshake(noAck, corruptFirst); err != nil {
			done <- fmt.Errorf("handshake: %w", err)
			return
		}
		done <- run(stub)
	}()
	t.Cleanup(func() {
		listener.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("stub: %v", err)
			}
		case <-time.After(6 * time.Second):
			t.Error("stub did not stop")
		}
	})
	session, err := qemu.Connect(listener.Addr().String(), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Close() })
	return session
}

func TestExternalFragmentedFramesChecksumRetryAndRLE(t *testing.T) {
	session := externalConnect(t, qemu.Options{Timeout: time.Second}, false, true, func(stub *externalStub) error {
		if err := stub.exchange("Hg1", "OK"); err != nil {
			return err
		}
		if err := stub.wantRequest("m4000,31"); err != nil {
			return err
		}
		if err := stub.respond([]byte("00*}"), true); err != nil {
			return err
		}
		return stub.wantClosed()
	})
	data := bytes.Repeat([]byte{0xff}, 49)
	n, err := session.ReadMemory(0x4000, data)
	if err != nil || n != len(data) {
		t.Fatalf("ReadMemory = %d, %v", n, err)
	}
	if !bytes.Equal(data, make([]byte, len(data))) {
		t.Fatalf("decoded RLE = %x", data)
	}
}

func TestExternalNoAckTransitionCoalescedConsoleAndOK(t *testing.T) {
	stopReply := "T05thread:1;vendor:opaque;"
	session := externalConnect(t, qemu.Options{Timeout: time.Second}, true, false, func(stub *externalStub) error {
		if err := stub.wantRequest("vCont;c"); err != nil {
			return err
		}
		frames := externalFrame(externalEncode("O6869"))
		frames = append(frames, externalFrame(externalEncode("O0a"))...)
		frames = append(frames, externalFrame(externalEncode(stopReply))...)
		if err := stub.write(frames); err != nil {
			return err
		}
		if err := stub.exchange("D", "OK"); err != nil {
			return err
		}
		return stub.wantClosed()
	})
	stop, err := session.Continue(target.Signal{})
	if err != nil {
		t.Fatal(err)
	}
	if stop.Raw != stopReply || stop.Reason != target.StopSignal || stop.Signal.Domain != target.SignalGDB || stop.Signal.Number != 5 {
		t.Fatalf("Continue stop = %+v", stop)
	}
	if output := string(session.TakeOutput()); output != "hi\n" {
		t.Fatalf("console output = %q", output)
	}
	if output := session.TakeOutput(); len(output) != 0 {
		t.Fatalf("console output was not drained: %q", output)
	}
	if err := session.Detach(); err != nil {
		t.Fatal(err)
	}
	if state := session.State(); state != target.StateDetached {
		t.Fatalf("state = %v", state)
	}
}

func TestExternalTimeoutRetiresPendingReply(t *testing.T) {
	session := externalConnect(t, qemu.Options{Timeout: 250 * time.Millisecond}, false, false, func(stub *externalStub) error {
		if err := stub.exchange("Hg1", "OK"); err != nil {
			return err
		}
		if err := stub.wantRequest("m4000,2"); err != nil {
			return err
		}
		if err := stub.write([]byte("+$aabb")); err != nil {
			return err
		}
		return stub.wantClosed()
	})
	data := []byte{0xcc, 0xdd}
	n, err := session.ReadMemory(0x4000, data)
	if n != 0 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timed-out ReadMemory = %d, %v", n, err)
	}
	if !bytes.Equal(data, []byte{0xcc, 0xdd}) {
		t.Fatalf("incomplete frame modified output: %x", data)
	}
	if state := session.State(); state != target.StateClosed {
		t.Fatalf("state after timeout = %v", state)
	}
	n, err = session.ReadMemory(0x5000, data)
	if n != 0 || !errors.Is(err, target.ErrClosed) {
		t.Fatalf("ReadMemory after timeout = %d, %v", n, err)
	}
}

func TestExternalInterruptAndCloseUnblockContinue(t *testing.T) {
	running := make(chan struct{}, 2)
	session := externalConnect(t, qemu.Options{Timeout: time.Second}, false, false, func(stub *externalStub) error {
		for run := range 2 {
			if err := stub.wantRequest("vCont;c"); err != nil {
				return err
			}
			if err := stub.write([]byte{'+'}); err != nil {
				return err
			}
			running <- struct{}{}
			if run == 1 {
				return stub.wantClosed()
			}
			if err := stub.wantByte(3); err != nil {
				return err
			}
			if err := stub.respond(externalEncode("T02thread:1;"), false); err != nil {
				return err
			}
		}
		return nil
	})
	type result struct {
		stop target.Stop
		err  error
	}
	continued := make(chan result, 1)
	for run := range 2 {
		go func() {
			stop, err := session.Continue(target.Signal{})
			continued <- result{stop, err}
		}()
		select {
		case <-running:
		case <-time.After(2 * time.Second):
			t.Fatal("continue request did not reach stub")
		}
		operation := make(chan error, 1)
		go func() {
			if run == 0 {
				operation <- session.Interrupt()
			} else {
				operation <- session.Close()
			}
		}()
		select {
		case err := <-operation:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("control operation blocked behind Continue")
		}
		select {
		case result := <-continued:
			if run == 0 {
				if result.err != nil || result.stop.Raw != "T02thread:1;" || result.stop.Signal.Number != 2 || result.stop.Reason != target.StopSignal {
					t.Fatalf("interrupted Continue = %+v, %v", result.stop, result.err)
				}
			} else if !errors.Is(result.err, target.ErrClosed) {
				t.Fatalf("closed Continue = %v", result.err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Continue did not finish")
		}
	}
	if state := session.State(); state != target.StateClosed {
		t.Fatalf("state = %v", state)
	}
}
