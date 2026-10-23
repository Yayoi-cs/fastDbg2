package display_test

import (
	"fmt"
	"os"
	"testing"

	"fastdbg2/display"
	"golang.org/x/sys/unix"
)

func TestOutputWidthDoesNotChangeCallerFileFlags(t *testing.T) {
	check := func(t *testing.T, file *os.File, fd, expected int) {
		t.Helper()
		before, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		if err != nil || before&unix.O_NONBLOCK == 0 {
			t.Fatalf("nonblocking setup: flags=%#x err=%v", before, err)
		}
		for range 3 {
			if width := display.OutputWidth(file); width != expected {
				t.Fatalf("width=%d want=%d", width, expected)
			}
		}
		after, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		if err != nil || before != after {
			t.Fatalf("caller flags changed: %#x -> %#x: %v", before, after, err)
		}
	}
	t.Run("pipe", func(t *testing.T) {
		var descriptors [2]int
		if err := unix.Pipe2(descriptors[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
			t.Fatal(err)
		}
		defer unix.Close(descriptors[0])
		writer := os.NewFile(uintptr(descriptors[1]), "nonblocking-output")
		defer writer.Close()
		check(t, writer, descriptors[1], 100)
	})
	t.Run("pty", func(t *testing.T) {
		master, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(master)
		if err := unix.IoctlSetPointerInt(master, unix.TIOCSPTLCK, 0); err != nil {
			t.Fatal(err)
		}
		number, err := unix.IoctlGetInt(master, unix.TIOCGPTN)
		if err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Open(fmt.Sprintf("/dev/pts/%d", number), unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		writer := os.NewFile(uintptr(fd), "nonblocking-tty-output")
		defer writer.Close()
		if err := unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{Col: 140, Row: 40}); err != nil {
			t.Fatal(err)
		}
		check(t, writer, fd, 140)
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if width := display.OutputWidth(writer); width != 100 {
			t.Fatalf("closed writer width=%d", width)
		}
	})
}
