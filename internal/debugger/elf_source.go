package debugger

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"fastdbg2/target"
	"golang.org/x/sys/unix"
)

func openRegularELFSource(ctx context.Context, path string) (*os.File, error) {
	if err := contextReady(ctx); err != nil {
		return nil, err
	}
	if path == "" || strings.ContainsRune(path, 0) {
		return nil, target.ErrInvalidArgument
	}
	pin, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("pin ELF source %q: %w", path, err)
	}
	source, openErr := openPinnedRegularELFSource(ctx, pin, path)
	if err := errors.Join(openErr, unix.Close(pin), contextReady(ctx)); err != nil {
		if source != nil {
			err = errors.Join(err, source.Close())
		}
		return nil, err
	}
	return source, nil
}

func openPinnedRegularELFSource(ctx context.Context, pin int, name string) (*os.File, error) {
	if err := contextReady(ctx); err != nil {
		return nil, err
	}
	var before unix.Stat_t
	if err := unix.Fstat(pin, &before); err != nil {
		return nil, fmt.Errorf("inspect pinned ELF source %q: %w", name, err)
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("ELF source %q must be a regular file: %w", name, target.ErrUnsupported)
	}
	if err := contextReady(ctx); err != nil {
		return nil, err
	}
	fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", pin), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, fmt.Errorf("open pinned ELF source %q: %w", name, err)
	}
	var after unix.Stat_t
	err = unix.Fstat(fd, &after)
	if err == nil && (after.Mode&unix.S_IFMT != unix.S_IFREG || after.Dev != before.Dev || after.Ino != before.Ino) {
		err = fmt.Errorf("readable ELF source differs from pinned regular file %q: %w", name, target.ErrStale)
	}
	if err := errors.Join(err, contextReady(ctx)); err != nil {
		return nil, errors.Join(err, unix.Close(fd))
	}
	return os.NewFile(uintptr(fd), name), nil
}
