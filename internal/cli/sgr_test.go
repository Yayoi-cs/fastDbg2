package cli

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
)

func TestSGRWriter(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"plain", "hello 日本語 雛 ě 😀\n", "hello 日本語 雛 ě 😀\n"},
		{"SGR", "\x1b[mA\x1b[0mB\x1b[1;31mC\x1b[38;2;1;2;3mD\x1b[38:2::1:2:3mE", "ABCDE"},
		{"CSI", "\x1b[?25h\x1b[6n\x1b[2K\x1b[1;1R\x1b[4C", "\x1b[?25h\x1b[6n\x1b[2K\x1b[1;1R\x1b[4C"},
		{"private", "\x1b[?1m\x1b[>0m\x1b[=1m\x1b[<2m", "\x1b[?1m\x1b[>0m\x1b[=1m\x1b[<2m"},
		{"intermediate", "\x1b[!m\x1b[1 m\x1b[2$m\x1b[ 31m", "\x1b[!m\x1b[1 m\x1b[2$m\x1b[ 31m"},
		{"literal final", "\x1b[2Km", "\x1b[2Km"},
		{"ESC", "\x1b", "\x1b"},
		{"CSI prefix", "\x1b[", "\x1b["},
		{"parameters", "\x1b[31", "\x1b[31"},
		{"other escape", "\x1b(B\x1b7\x1b8", "\x1b(B\x1b7\x1b8"},
		{"replacement escape", "\x1b[31\x1b[0mX", "\x1b[31X"},
		{"double escape", "\x1b\x1b[0m", "\x1b"},
		{"controls", "\x1b[3\a1\nm", "\a\n"},
		{"cancel", "\x1b[31\x18m\x1b[32\x1am", "\x1b[31\x18m\x1b[32\x1am"},
		{"invalid bytes", "\x1b[31\xffm", "\x1b[31\xffm"},
		{"C1 SGR", "\x9b31mA\x9bm", "A"},
		{"C1 other", "\x9b6n\x9b?1m\x9b31", "\x9b6n\x9b?1m\x9b31"},
		{"OSC BEL", "\x1b]0;title\x1b[31m\a\x1b[32mX", "\x1b]0;title\x1b[31m\aX"},
		{"OSC ST", "\x1b]0;title\x1b[31m\x1b\\\x1b[mX", "\x1b]0;title\x1b[31m\x1b\\X"},
		{"DCS", "\x1bPdata\x1b[31m\x1b\\\x1b[mX", "\x1bPdata\x1b[31m\x1b\\X"},
		{"APC", "\x1b_data\x1b[31m\x1b\\\x1b[mX", "\x1b_data\x1b[31m\x1b\\X"},
		{"PM", "\x1b^data\x1b[31m\x1b\\\x1b[mX", "\x1b^data\x1b[31m\x1b\\X"},
		{"SOS", "\x1bXdata\x1b[31m\x1b\\\x1b[mX", "\x1bXdata\x1b[31m\x1b\\X"},
		{"C1 string", "\x9dtitle\x1b[31m\x9c\x9b0mX", "\x9dtitle\x1b[31m\x9cX"},
		{"C1 DCS", "\x90data\x1b[31m\x9c\x9b0mX", "\x90data\x1b[31m\x9cX"},
		{"C1 SOS", "\x98data\x1b[31m\x9c\x9b0mX", "\x98data\x1b[31m\x9cX"},
		{"C1 PM", "\x9edata\x1b[31m\x9c\x9b0mX", "\x9edata\x1b[31m\x9cX"},
		{"C1 APC", "\x9fdata\x1b[31m\x9c\x9b0mX", "\x9fdata\x1b[31m\x9cX"},
		{"UTF8 in string", "\x1b]titleě雛😀\x1b[31m\a", "\x1b]titleě雛😀\x1b[31m\a"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for split := 0; split <= len(test.input); split++ {
				testSGRChunks(t, []string{test.input[:split], test.input[split:]}, test.want)
			}
			var chunks []string
			for i := range len(test.input) {
				chunks = append(chunks, test.input[i:i+1])
			}
			testSGRChunks(t, chunks, test.want)
		})
	}
}

func testSGRChunks(t *testing.T, chunks []string, want string) {
	t.Helper()
	var output bytes.Buffer
	writer := &sgrWriter{target: &output}
	for _, chunk := range chunks {
		if n, err := writer.Write([]byte(chunk)); n != len(chunk) || err != nil {
			t.Fatalf("write %q: got %d, %v", chunk, n, err)
		}
	}
	for range 2 {
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if output.String() != want {
		t.Fatalf("chunks %q: got %q, want %q", chunks, output.String(), want)
	}
	if n, err := writer.Write([]byte("after")); n != 0 || err != io.ErrClosedPipe {
		t.Fatalf("write after close: %d, %v", n, err)
	}
}

func TestSGRWriterErrors(t *testing.T) {
	want := errors.New("write failed")
	tests := []struct {
		name    string
		prefix  string
		input   string
		count   int
		err     error
		wantN   int
		wantErr error
	}{
		{"short", "", "abcd", 2, nil, 2, io.ErrShortWrite},
		{"failure", "", "abcd", 1, want, 1, want},
		{"SGR prefix", "", "\x1b[31mabc", 1, want, 6, want},
		{"buffered prefix", "\x1b", "[2Kabc", 1, want, 0, want},
		{"full write error", "", "\x1b[31mabc", 3, want, 8, want},
		{"invalid count", "", "abc", -1, nil, 0, io.ErrShortWrite},
		{"excess count", "", "abc", 10, nil, 0, io.ErrShortWrite},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			writer := &sgrWriter{target: writerFunc(func([]byte) (int, error) {
				calls++
				return test.count, test.err
			})}
			if test.prefix != "" {
				if n, err := writer.Write([]byte(test.prefix)); n != len(test.prefix) || err != nil {
					t.Fatalf("buffer prefix: %d, %v", n, err)
				}
			}
			if n, err := writer.Write([]byte(test.input)); n != test.wantN || !errors.Is(err, test.wantErr) {
				t.Fatalf("got %d, %v; want %d, %v", n, err, test.wantN, test.wantErr)
			}
			if n, err := writer.Write([]byte("later")); n != 0 || !errors.Is(err, test.wantErr) {
				t.Fatalf("failure not sticky: %d, %v", n, err)
			}
			if err := writer.Close(); !errors.Is(err, test.wantErr) {
				t.Fatalf("close lost write error: %v", err)
			}
			if calls != 1 {
				t.Fatalf("got %d target calls, want 1", calls)
			}
		})
	}
}

func TestSGRWriterCloseErrors(t *testing.T) {
	want := errors.New("flush failed")
	for _, targetErr := range []error{nil, want} {
		writer := &sgrWriter{target: writerFunc(func(p []byte) (int, error) {
			return len(p) - 1, targetErr
		})}
		if _, err := writer.Write([]byte("\x1b[31")); err != nil {
			t.Fatal(err)
		}
		expected := targetErr
		if expected == nil {
			expected = io.ErrShortWrite
		}
		for range 2 {
			if err := writer.Close(); !errors.Is(err, expected) {
				t.Fatalf("got %v, want %v", err, expected)
			}
		}
	}
}

func TestSGRWriterConcurrentWrites(t *testing.T) {
	var output bytes.Buffer
	writer := &sgrWriter{target: &output}
	var group sync.WaitGroup
	for range 20 {
		group.Go(func() {
			if _, err := writer.Write([]byte("\x1b[31mX\x1b[m")); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if output.String() != strings.Repeat("X", 20) {
		t.Fatalf("got %q", output.String())
	}
}

func TestTerminalReaderMenuColor(t *testing.T) {
	for _, noColor := range []bool{false, true} {
		var output bytes.Buffer
		source := newTestCancelReader()
		completer, err := NewCompleter([]string{"help", "exit", "quit"})
		if err != nil {
			t.Fatal(err)
		}
		reader, err := newTerminalReader(Config{Output: &output, Prompt: "> ", NoColor: noColor},
			completer, source, &rawMode{enter: func() (func() error, error) {
				return func() error { return nil }, nil
			}}, func() (int, int) { return 80, 24 })
		if err != nil {
			t.Fatal(err)
		}
		source.events <- readEvent{data: []byte("\x1b[1;1R\t\t\r\r")}
		line, err := reader.ReadLine()
		if err != nil || line != "exit " {
			reader.Close()
			t.Fatalf("got %q, %v", line, err)
		}
		if err := reader.Close(); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(output.Bytes(), []byte("\x1b[30;47m")) == noColor {
			t.Fatalf("NoColor=%v: unexpected menu color in %q", noColor, output.String())
		}
		if noColor && bytes.Contains(output.Bytes(), []byte("\x1b[0m")) {
			t.Fatalf("SGR reset remained: %q", output.String())
		}
		if !bytes.Contains(output.Bytes(), []byte("\x1b[6n")) || !bytes.Contains(output.Bytes(), []byte("\x1b[J")) {
			t.Fatalf("non-SGR terminal controls removed: %q", output.String())
		}
	}
}

func TestTerminalReaderColorFlushError(t *testing.T) {
	want := errors.New("flush failed")
	source := newTestCancelReader()
	completer, err := NewCompleter(nil)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := newTerminalReader(Config{
		Output:  writerFunc(func([]byte) (int, error) { return 0, want }),
		NoColor: true,
	}, completer, source, &rawMode{enter: func() (func() error, error) {
		return func() error { return nil }, nil
	}}, func() (int, int) { return 80, 24 })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.plainOutput.Write([]byte("\x1b[")); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); !errors.Is(err, want) {
		t.Fatalf("close lost flush error: %v", err)
	}
	if source.cancels.Load() != 1 || source.closes.Load() != 1 {
		t.Fatalf("invalid cleanup: cancel=%d close=%d", source.cancels.Load(), source.closes.Load())
	}
}
