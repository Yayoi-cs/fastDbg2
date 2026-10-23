package cli

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/muesli/cancelreader"
)

func TestStreamReader(t *testing.T) {
	var output bytes.Buffer
	r, err := NewReader(Config{
		Input:  strings.NewReader("first\n日本語\r\n\nlast\r"),
		Output: &output,
		Prompt: "not printed> ",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.Interactive() {
		t.Fatal("stream reader is interactive")
	}
	for _, want := range []string{"first", "日本語", "", "last\r"} {
		got, err := r.ReadLine()
		if err != nil || got != want {
			t.Fatalf("got %q, %v; want %q", got, err, want)
		}
	}
	if _, err := r.ReadLine(); err != io.EOF {
		t.Fatalf("got %v, want EOF", err)
	}
	if output.Len() != 0 {
		t.Fatalf("stream reader wrote output: %q", output.String())
	}
}

func TestReaderValidation(t *testing.T) {
	for _, config := range []Config{
		{Output: io.Discard},
		{Input: strings.NewReader("")},
		{Input: strings.NewReader(""), Output: io.Discard, Commands: []string{"bad\n"}},
	} {
		if _, err := NewReader(config); err == nil {
			t.Fatal("expected validation error")
		}
	}
	if IsTerminal(strings.NewReader(""), io.Discard, "xterm") {
		t.Fatal("generic I/O reported as a terminal")
	}
}

func TestStreamReaderError(t *testing.T) {
	want := errors.New("read failed")
	for _, readErr := range []error{want, errors.Join(io.EOF, want)} {
		r, err := NewReader(Config{
			Input: readerFunc(func(p []byte) (int, error) {
				return copy(p, "partial"), readErr
			}),
			Output: io.Discard,
		})
		if err != nil {
			t.Fatal(err)
		}
		line, err := r.ReadLine()
		if line != "partial" || !errors.Is(err, want) {
			t.Fatalf("got %q, %v", line, err)
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStreamCloseDoesNotOwnInput(t *testing.T) {
	input := &ownedReader{Reader: strings.NewReader("help\n")}
	r, err := NewReader(Config{Input: input, Output: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if input.closed {
		t.Fatal("reader closed caller input")
	}
	if _, err := r.ReadLine(); err != io.EOF {
		t.Fatalf("got %v, want EOF after close", err)
	}
}

func TestRawMode(t *testing.T) {
	var enters, restores int
	raw := &rawMode{enter: func() (func() error, error) {
		enters++
		return func() error { restores++; return nil }, nil
	}}
	for range 2 {
		if err := raw.Enter(); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if err := raw.Exit(); err != nil {
			t.Fatal(err)
		}
	}
	if enters != 1 || restores != 1 {
		t.Fatalf("got %d entries, %d restores", enters, restores)
	}
	if err := raw.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestRawModePreservesErrorsAndRetriesRestore(t *testing.T) {
	wantEnter := errors.New("raw failed")
	wantRestore := errors.New("restore failed")
	var enters, restores int
	raw := &rawMode{enter: func() (func() error, error) {
		enters++
		if enters == 1 {
			return nil, wantEnter
		}
		return func() error {
			restores++
			if restores == 1 {
				return wantRestore
			}
			return nil
		}, nil
	}}
	if err := raw.Enter(); !errors.Is(err, wantEnter) {
		t.Fatalf("got %v, want enter failure", err)
	}
	if err := raw.Exit(); err != nil {
		t.Fatal(err)
	}
	if err := raw.Enter(); err != nil {
		t.Fatal(err)
	}
	if err := raw.Exit(); !errors.Is(err, wantRestore) {
		t.Fatalf("got %v, want restore failure", err)
	}
	if err := raw.Enter(); err != nil || enters != 2 {
		t.Fatalf("failed restore allowed duplicate raw entry: %d, %v", enters, err)
	}
	if err := raw.Exit(); err != nil || restores != 2 {
		t.Fatalf("restore did not retry: %d, %v", restores, err)
	}
	if !errors.Is(raw.Err(), wantEnter) {
		t.Fatalf("first raw failure lost: %v", raw.Err())
	}
}

func TestObservedIOErrors(t *testing.T) {
	want := errors.New("I/O failed")
	var failures firstError
	var cancels int
	cancel := func() { cancels++ }
	output := &observedWriter{
		target:   writerFunc(func(p []byte) (int, error) { return 0, want }),
		failures: &failures,
		cancel:   cancel,
	}
	if _, err := output.Write([]byte("test")); !errors.Is(err, want) {
		t.Fatalf("got %v", err)
	}
	output.target = writerFunc(func(p []byte) (int, error) { return len(p) - 1, nil })
	if _, err := output.Write([]byte("test")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("got %v", err)
	}
	if !errors.Is(failures.Err(), want) || cancels != 2 {
		t.Fatalf("got first error %v, cancellations %d", failures.Err(), cancels)
	}
}

func TestObservedReader(t *testing.T) {
	want := errors.New("read failed")
	for _, inputErr := range []error{nil, io.EOF, cancelreader.ErrCanceled, want, errors.Join(io.EOF, want), errors.Join(cancelreader.ErrCanceled, want)} {
		var failures firstError
		var reads, cancels int
		input := &observedReader{
			source:   readerFunc(func([]byte) (int, error) { reads++; return 0, inputErr }),
			failures: &failures,
			cancel:   func() { cancels++ },
		}
		if _, err := input.Read(make([]byte, 1)); err != inputErr {
			t.Fatalf("got %v, want %v", err, inputErr)
		}
		if errors.Is(inputErr, want) {
			if !errors.Is(failures.Err(), want) || cancels != 1 {
				t.Fatalf("error not preserved: %v, %d", failures.Err(), cancels)
			}
		} else if failures.Err() != nil || cancels != 0 {
			t.Fatalf("unexpected error: %v, %d", failures.Err(), cancels)
		}
		input.Stop()
		if _, err := input.Read(make([]byte, 1)); err != cancelreader.ErrCanceled || reads != 1 {
			t.Fatalf("stopped input read underlying source: %v, %d", err, reads)
		}
	}
}

func TestObservedReaderDoesNotReadAhead(t *testing.T) {
	var failures firstError
	source := strings.NewReader("run\n日本語 🌐 payload\n")
	input := &observedReader{
		source:   source,
		failures: &failures,
		cancel:   func() { t.Fatal("unexpected cancellation") },
	}
	var command strings.Builder
	for {
		buffer := make([]byte, 4096)
		n, err := input.Read(buffer)
		if n != 1 || err != nil {
			t.Fatalf("got %d bytes, %v; want one byte", n, err)
		}
		command.WriteByte(buffer[0])
		if buffer[0] == '\n' {
			break
		}
	}
	if command.String() != "run\n" {
		t.Fatalf("unexpected command %q", command.String())
	}
	payload, err := io.ReadAll(source)
	if err != nil || string(payload) != "日本語 🌐 payload\n" {
		t.Fatalf("reader consumed inferior input: %q, %v", payload, err)
	}
}

func TestTerminalReaderCloseCancelsPendingRead(t *testing.T) {
	source := newTestCancelReader()
	var restores atomic.Int32
	reader := testTerminalReader(t, source, io.Discard, &rawMode{enter: func() (func() error, error) {
		return func() error { restores.Add(1); return nil }, nil
	}})
	done := make(chan error, 1)
	go func() {
		_, err := reader.ReadLine()
		done <- err
	}()
	select {
	case <-source.started:
	case <-time.After(3 * time.Second):
		t.Fatal("read did not start")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- reader.Close() }()
	select {
	case err := <-done:
		if err != io.EOF {
			t.Fatalf("got %v, want EOF", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("read did not stop")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("close did not return")
	}
	if source.cancels.Load() != 1 || source.closes.Load() != 1 || restores.Load() != 1 || source.active.Load() != 0 {
		t.Fatalf("invalid cleanup: cancel=%d close=%d restore=%d reads=%d", source.cancels.Load(), source.closes.Load(), restores.Load(), source.active.Load())
	}
	if err := reader.Close(); err != nil || source.closes.Load() != 1 {
		t.Fatalf("close was not idempotent: %v, %d", err, source.closes.Load())
	}
}

func TestTerminalReaderEditing(t *testing.T) {
	source := newTestCancelReader()
	var output bytes.Buffer
	var entries, restores atomic.Int32
	reader := testTerminalReader(t, source, &output, &rawMode{enter: func() (func() error, error) {
		entries.Add(1)
		return func() error { restores.Add(1); return nil }, nil
	}})
	tests := []struct {
		input string
		line  string
		err   error
	}{
		{"h\t\r", "help ", nil},
		{"\x1b[A\r", "help ", nil},
		{"日本語 🌐\r", "日本語 🌐", nil},
		{"discard\x03", "", ErrInterrupt},
		{"\x04", "", io.EOF},
	}
	for _, test := range tests {
		source.events <- readEvent{data: []byte("\x1b[1;1R" + test.input)}
		line, err := reader.ReadLine()
		if line != test.line || err != test.err {
			t.Fatalf("input %q: got %q, %v; want %q, %v", test.input, line, err, test.line, test.err)
		}
		if entries.Load() != restores.Load() {
			t.Fatalf("raw mode not restored before returning: enter=%d restore=%d", entries.Load(), restores.Load())
		}
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTerminalReaderConcurrentClose(t *testing.T) {
	source := newTestCancelReader()
	reader := testTerminalReader(t, source, io.Discard, &rawMode{enter: func() (func() error, error) {
		return func() error { return nil }, nil
	}})
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			if err := reader.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	if source.cancels.Load() != 1 || source.closes.Load() != 1 {
		t.Fatalf("multiple cleanup calls: cancel=%d close=%d", source.cancels.Load(), source.closes.Load())
	}
}

func TestTerminalReaderPropagatesIOErrors(t *testing.T) {
	want := errors.New("terminal I/O failed")
	tests := []struct {
		name       string
		inputError error
		output     io.Writer
	}{
		{"read", want, io.Discard},
		{"write", nil, writerFunc(func([]byte) (int, error) { return 0, want })},
		{"joined EOF", errors.Join(io.EOF, want), io.Discard},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := newTestCancelReader()
			if test.inputError != nil {
				source.events <- readEvent{err: test.inputError}
			}
			var restores atomic.Int32
			reader := testTerminalReader(t, source, test.output, &rawMode{enter: func() (func() error, error) {
				return func() error { restores.Add(1); return nil }, nil
			}})
			done := make(chan error, 1)
			go func() {
				_, err := reader.ReadLine()
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, want) {
					t.Fatalf("got %v, want I/O failure", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("I/O failure did not cancel read")
			}
			if _, err := reader.ReadLine(); !errors.Is(err, want) {
				t.Fatalf("subsequent read lost failure: %v", err)
			}
			if err := reader.Close(); err != nil {
				t.Fatal(err)
			}
			if restores.Load() != 1 || source.cancels.Load() != 1 || source.active.Load() != 0 {
				t.Fatalf("invalid cleanup: restore=%d cancel=%d read=%d", restores.Load(), source.cancels.Load(), source.active.Load())
			}
		})
	}
}

func TestTerminalReaderRawEntryFailure(t *testing.T) {
	want := errors.New("raw failed")
	source := newTestCancelReader()
	reader := testTerminalReader(t, source, io.Discard, &rawMode{enter: func() (func() error, error) {
		return nil, want
	}})
	if _, err := reader.ReadLine(); !errors.Is(err, want) {
		t.Fatalf("got %v", err)
	}
	if err := reader.Close(); !errors.Is(err, want) {
		t.Fatalf("close lost raw failure: %v", err)
	}
	if source.active.Load() != 0 {
		t.Fatal("read started after raw entry failed")
	}
}

func TestTerminalReaderRestoreFailure(t *testing.T) {
	want := errors.New("restore failed")
	source := newTestCancelReader()
	source.events <- readEvent{err: io.EOF}
	reader := testTerminalReader(t, source, io.Discard, &rawMode{enter: func() (func() error, error) {
		return func() error { return want }, nil
	}})
	if _, err := reader.ReadLine(); !errors.Is(err, want) {
		t.Fatalf("got %v, want restore failure", err)
	}
	if err := reader.Close(); !errors.Is(err, want) {
		t.Fatalf("close lost restore failure: %v", err)
	}
}

func testTerminalReader(t *testing.T, source cancelreader.CancelReader, output io.Writer, raw *rawMode) *Reader {
	t.Helper()
	completer, err := NewCompleter([]string{"help", "exit", "quit"})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := newTerminalReader(Config{Output: output, Prompt: "> "}, completer, source, raw, func() (int, int) { return 80, 24 })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reader.Close() })
	return reader
}

type readEvent struct {
	data []byte
	err  error
}

type testCancelReader struct {
	events  chan readEvent
	started chan struct{}
	done    chan struct{}
	once    sync.Once
	cancels atomic.Int32
	closes  atomic.Int32
	active  atomic.Int32
	pending []byte
}

func newTestCancelReader() *testCancelReader {
	return &testCancelReader{
		events:  make(chan readEvent, 16),
		started: make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
}

func (r *testCancelReader) Read(p []byte) (int, error) {
	r.active.Add(1)
	defer r.active.Add(-1)
	select {
	case r.started <- struct{}{}:
	default:
	}
	if len(r.pending) != 0 {
		n := copy(p, r.pending)
		r.pending = r.pending[n:]
		return n, nil
	}
	select {
	case <-r.done:
		return 0, cancelreader.ErrCanceled
	case event := <-r.events:
		n := copy(p, event.data)
		r.pending = event.data[n:]
		return n, event.err
	}
}

func (r *testCancelReader) Cancel() bool {
	r.cancels.Add(1)
	r.once.Do(func() { close(r.done) })
	return true
}

func (r *testCancelReader) Close() error {
	r.closes.Add(1)
	if r.active.Load() != 0 {
		return errors.New("closed while input read active")
	}
	return nil
}

type ownedReader struct {
	io.Reader
	closed bool
}

func (r *ownedReader) Close() error {
	r.closed = true
	return nil
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) {
	return f(p)
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) {
	return f(p)
}
