package shellcmd

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

type terminalLease struct {
	file    *os.File
	group   int
	termios *unix.Termios
	changed bool
}

func TerminalInput(file *os.File) (bool, error) {
	if file == nil {
		return false, errors.New("terminal input file is required")
	}
	connection, err := file.SyscallConn()
	if err != nil {
		return false, err
	}
	var terminalErr error
	err = connection.Control(func(fd uintptr) {
		_, terminalErr = unix.IoctlGetTermios(int(fd), unix.TCGETS)
	})
	if err != nil {
		return false, err
	}
	if errors.Is(terminalErr, unix.ENOTTY) {
		return false, nil
	}
	return terminalErr == nil, terminalErr
}

func acquireTerminal(file *os.File) (*terminalLease, error) {
	connection, err := file.SyscallConn()
	if err != nil {
		return nil, err
	}
	lease := &terminalLease{file: file}
	var terminalErr error
	err = connection.Control(func(fd uintptr) {
		var settings *unix.Termios
		settings, terminalErr = unix.IoctlGetTermios(int(fd), unix.TCGETS)
		if terminalErr == nil {
			lease.termios = settings
			lease.group, terminalErr = unix.IoctlGetInt(int(fd), unix.TIOCGPGRP)
		}
	})
	if err != nil {
		return nil, err
	}
	if errors.Is(terminalErr, unix.ENOTTY) && lease.termios == nil {
		return nil, nil
	}
	if terminalErr != nil {
		return nil, fmt.Errorf("read shell controlling terminal: %w", terminalErr)
	}
	if lease.group != unix.Getpgrp() {
		return nil, errors.New("shell requires the debugger's foreground controlling terminal")
	}
	return lease, nil
}

func (lease *terminalLease) give(group int) error {
	err := lease.control(func(fd int) error {
		current, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
		if err != nil {
			return err
		}
		if current != lease.group {
			return errors.New("terminal foreground group changed before shell startup")
		}
		if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, group); err != nil {
			return err
		}
		lease.changed = true
		return nil
	})
	if err != nil {
		return fmt.Errorf("give shell terminal: %w", err)
	}
	return nil
}

func (lease *terminalLease) restore() error {
	if !lease.changed {
		return nil
	}
	err := lease.control(func(fd int) error {
		groupErr := unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, lease.group)
		termiosErr := unix.IoctlSetTermios(fd, unix.TCSETS, lease.termios)
		return errors.Join(groupErr, termiosErr)
	})
	if err != nil {
		return fmt.Errorf("restore shell terminal: %w", err)
	}
	lease.changed = false
	return nil
}

func (lease *terminalLease) control(operation func(int) error) error {
	return withTerminalOutput(func() error {
		connection, err := lease.file.SyscallConn()
		var operationErr error
		if err == nil {
			err = connection.Control(func(fd uintptr) { operationErr = operation(int(fd)) })
		}
		return errors.Join(err, operationErr)
	})
}

func withTerminalOutput(operation func() error) (err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var mask, previous unix.Sigset_t
	mask.Val[0] = 1 << (uint(unix.SIGTTOU) - 1)
	if err := unix.PthreadSigmask(unix.SIG_BLOCK, &mask, &previous); err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unix.PthreadSigmask(unix.SIG_SETMASK, &previous, nil)) }()
	return operation()
}
