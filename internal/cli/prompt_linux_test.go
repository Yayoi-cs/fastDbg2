package cli

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestTerminalReaderCompletesAtLineStartAndRestoresOutputMode(t *testing.T) {
	for _, originalPost := range []bool{false, true} {
		for _, noColor := range []bool{false, true} {
			for _, event := range []struct {
				name, input, line string
				err               error
			}{
				{"enter", "bad\r", "bad", nil},
				{"empty", "\r", "", nil},
				{"interrupt", "discard\x03", "", ErrInterrupt},
				{"eof", "\x04", "", io.EOF},
				{"wrapped", strings.Repeat("x", 50) + "\r", strings.Repeat("x", 50), nil},
			} {
				t.Run(fmt.Sprintf("post=%t/color=%t/%s", originalPost, !noColor, event.name), func(t *testing.T) {
					master, slave := openTestPTY(t)
					fd, err := fileDescriptor(slave)
					if err != nil {
						t.Fatal(err)
					}
					before, err := unix.IoctlGetTermios(fd, unix.TCGETS)
					if err != nil {
						t.Fatal(err)
					}
					if originalPost {
						before.Oflag |= unix.OPOST | unix.ONLCR
					} else {
						before.Oflag &^= unix.OPOST | unix.ONLCR
					}
					if err := unix.IoctlSetTermios(fd, unix.TCSETS, before); err != nil {
						t.Fatal(err)
					}
					if err := unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{Row: 24, Col: 20}); err != nil {
						t.Fatal(err)
					}
					reader, err := NewReader(Config{Input: slave, Output: slave, Prompt: "[\x1b[36mfastDbg2\x1b[0m]$ ", Term: "xterm", NoColor: noColor})
					if err != nil {
						t.Fatal(err)
					}
					defer reader.Close()
					done := make(chan readEvent, 1)
					go func() {
						line, err := reader.ReadLine()
						done <- readEvent{data: []byte(line), err: err}
					}()
					if err := master.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
						t.Fatal(err)
					}
					var output []byte
					readUntil := func(marker string) {
						t.Helper()
						for !bytes.Contains(output, []byte(marker)) {
							var buffer [1024]byte
							n, err := master.Read(buffer[:])
							if err != nil {
								t.Fatalf("waiting for %q: %v; output=%q", marker, err, output)
							}
							output = append(output, buffer[:n]...)
						}
					}
					readUntil("\x1b[6n")
					active, err := unix.IoctlGetTermios(fd, unix.TCGETS)
					if err != nil || active.Oflag != unix.OPOST|unix.ONLCR || active.Lflag&(unix.ECHO|unix.ICANON|unix.ISIG) != 0 {
						t.Fatalf("readline raw/output mode: %+v, %v", active, err)
					}
					if _, err := master.Write([]byte("\x1b[1;1R" + event.input)); err != nil {
						t.Fatal(err)
					}
					select {
					case result := <-done:
						if string(result.data) != event.line || result.err != event.err {
							t.Fatalf("readline: %q, %v", result.data, result.err)
						}
					case <-time.After(3 * time.Second):
						t.Fatal("readline did not complete")
					}
					after, err := unix.IoctlGetTermios(fd, unix.TCGETS)
					if err != nil || *after != *before {
						t.Fatalf("termios not restored before command: %+v -> %+v (%v)", before, after, err)
					}
					if _, err := io.WriteString(slave, "MARK"); err != nil {
						t.Fatal(err)
					}
					readUntil("MARK")
					prefix := output[:bytes.Index(output, []byte("MARK"))]
					newline := bytes.LastIndexByte(prefix, '\n')
					if newline < 1 || prefix[newline-1] != '\r' {
						t.Fatalf("readline did not return to column zero: %q", output)
					}
					if noColor && bytes.Contains(output, []byte("\x1b[36m")) {
						t.Fatalf("NO_COLOR prompt retained SGR: %q", output)
					}
				})
			}
		}
	}
}

func TestReaderSetPromptUpdatesOnlyInteractiveReader(t *testing.T) {
	source := newTestCancelReader()
	var output bytes.Buffer
	reader := testTerminalReader(t, source, &output, &rawMode{enter: func() (func() error, error) {
		return func() error { return nil }, nil
	}})
	reader.SetPrompt("[fastDbg2:0x123]$ ")
	source.events <- readEvent{data: []byte("\x1b[1;1R\r")}
	if _, err := reader.ReadLine(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "[fastDbg2:0x123]$ ") {
		t.Fatalf("prompt was not updated: %q", output.String())
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	reader.SetPrompt("closed")
	output.Reset()
	stream, err := NewReader(Config{Input: strings.NewReader("quit\n"), Output: &output})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	stream.SetPrompt("never print")
	if line, err := stream.ReadLine(); err != nil || line != "quit" || output.Len() != 0 {
		t.Fatalf("stream prompt effect: %q, %v, %q", line, err, output.String())
	}
}
