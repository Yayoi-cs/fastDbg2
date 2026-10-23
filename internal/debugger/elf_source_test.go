package debugger

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"fastdbg2/target"
	"golang.org/x/sys/unix"
)

func elfSourceTestDirectory(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".cache", "fastdbg-amd64-command-port", "elf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(root, "source-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return dir
}

func TestELFSourceRegularAndSymlinkRemainReadableAndPrivate(t *testing.T) {
	dir := elfSourceTestDirectory(t)
	path, link := filepath.Join(dir, "source"), filepath.Join(dir, "link")
	if err := os.WriteFile(path, []byte("regular metadata"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{path, link} {
		source, err := openRegularELFSource(context.Background(), name)
		if err != nil {
			t.Fatal(err)
		}
		data, readErr := io.ReadAll(source)
		conn, connErr := source.SyscallConn()
		if connErr != nil {
			source.Close()
			t.Fatal(connErr)
		}
		var descriptorFlags, statusFlags int
		var descriptorErr, statusErr error
		controlErr := conn.Control(func(fd uintptr) {
			descriptorFlags, descriptorErr = unix.FcntlInt(fd, unix.F_GETFD, 0)
			statusFlags, statusErr = unix.FcntlInt(fd, unix.F_GETFL, 0)
		})
		closeErr := source.Close()
		if err := errors.Join(readErr, descriptorErr, statusErr, controlErr, closeErr); err != nil {
			t.Fatal(err)
		}
		if string(data) != "regular metadata" || source.Name() != name || descriptorFlags&unix.FD_CLOEXEC == 0 || statusFlags&unix.O_NONBLOCK == 0 || statusFlags&unix.O_ACCMODE != unix.O_RDONLY {
			t.Fatalf("name=%q bytes=%q descriptor=%#x status=%#x", source.Name(), data, descriptorFlags, statusFlags)
		}
	}
}

func TestELFSourcePathReplacementCannotRedirectPinnedSource(t *testing.T) {
	for _, replacement := range []string{"regular", "fifo", "symlink"} {
		t.Run(replacement, func(t *testing.T) {
			dir := elfSourceTestDirectory(t)
			path := filepath.Join(dir, "source")
			if err := os.WriteFile(path, []byte("pinned original"), 0o600); err != nil {
				t.Fatal(err)
			}
			pin, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(pin)
			if err := os.Rename(path, path+".original"); err != nil {
				t.Fatal(err)
			}
			switch replacement {
			case "regular":
				err = os.WriteFile(path, []byte("different file"), 0o600)
			case "fifo":
				err = unix.Mkfifo(path, 0o600)
			case "symlink":
				err = os.Symlink("/dev/null", path)
			}
			if err != nil {
				t.Fatal(err)
			}
			source, err := openPinnedRegularELFSource(context.Background(), pin, path)
			if err != nil {
				t.Fatal(err)
			}
			data, readErr := io.ReadAll(source)
			if err := errors.Join(readErr, source.Close()); err != nil || string(data) != "pinned original" {
				t.Fatalf("data=%q error=%v", data, err)
			}
		})
	}
}

func TestELFSourceRejectsNonregularBeforeReadableOpen(t *testing.T) {
	dir := elfSourceTestDirectory(t)
	for _, name := range []string{dir, "/dev/null"} {
		source, err := openRegularELFSource(context.Background(), name)
		if source != nil {
			source.Close()
		}
		if source != nil || !errors.Is(err, target.ErrUnsupported) {
			t.Fatalf("%q: source=%v error=%v", name, source, err)
		}
	}
}

func TestChecksecFIFORejectionDoesNotWaitForWriterOrDeadline(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "configured", true: "explicit"}[explicit], func(t *testing.T) {
			path := filepath.Join(elfSourceTestDirectory(t), "fifo")
			if err := unix.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			controller := &Controller{path: path, out: &output}
			arguments := ""
			if explicit {
				arguments = "--file " + strconv.Quote(path)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- controller.showChecksec(ctx, arguments) }()
			select {
			case err := <-done:
				if !errors.Is(err, target.ErrUnsupported) || errors.Is(err, context.DeadlineExceeded) || output.Len() != 0 {
					t.Fatalf("error=%v output=%q", err, output.String())
				}
			case <-time.After(time.Second):
				writer, err := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
				if err == nil {
					_ = unix.Close(writer)
				}
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("FIFO reader remained blocked after rescue writer closed")
				}
				t.Fatal("checksec waited for a FIFO writer after its context deadline")
			}
		})
	}
}

func TestELFSourceCancellationAndInvalidArgumentsDoNotOpen(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, test := range []struct {
		ctx  context.Context
		path string
		err  error
	}{
		{ctx, "/missing/canceled/ELF", context.Canceled},
		{nil, "/missing/ELF", target.ErrInvalidArgument},
		{context.Background(), "", target.ErrInvalidArgument},
		{context.Background(), "a\x00b", target.ErrInvalidArgument},
	} {
		source, err := openRegularELFSource(test.ctx, test.path)
		if source != nil || !errors.Is(err, test.err) {
			t.Fatalf("%q: source=%v error=%v", test.path, source, err)
		}
	}
}

func TestChecksecRegularReadAndOutputErrorsStaySeparated(t *testing.T) {
	path := filepath.Join(elfSourceTestDirectory(t), "source")
	if err := os.WriteFile(path, []byte("not an ELF"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	controller := &Controller{path: path, out: &output}
	if err := controller.showChecksec(context.Background(), ""); err == nil || output.Len() != 0 {
		t.Fatalf("invalid ELF error=%v output=%q", err, output.String())
	}
	_, data := elfCommandTestELF(t, nil, nil, nil)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	controller.out = controllerTestWriter(func([]byte) (int, error) { return 0, io.ErrClosedPipe })
	err := controller.showChecksec(context.Background(), "")
	var outputErr *OutputError
	if !errors.As(err, &outputErr) || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
}
