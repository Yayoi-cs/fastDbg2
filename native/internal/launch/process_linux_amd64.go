package launch

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"golang.org/x/sys/unix"
)

const readyTimeout = 5 * time.Second

type Process struct {
	Process        *os.Process
	PIDFD          int
	gate           *os.File
	errors         *os.File
	errorFD        int
	execResultRead bool
	execResult     error
}

func Start(target *os.File, argv []string, stdio [3]*os.File) (*Process, error) {
	bootstrap, err := newBootstrap()
	if err != nil {
		return nil, err
	}
	defer bootstrap.Close()
	return start(target, argv, stdio, bootstrap, readyTimeout)
}

func start(target *os.File, argv []string, stdio [3]*os.File, bootstrap *os.File, timeout time.Duration) (_ *Process, err error) {
	if target == nil || len(argv) == 0 {
		return nil, unix.EINVAL
	}
	gateR, gateW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer gateR.Close()
	p := &Process{PIDFD: -1, gate: gateW, errorFD: -1}
	defer func() {
		if err != nil {
			err = errors.Join(err, p.Close(), p.abort())
		}
	}()
	errorR, errorW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer errorW.Close()
	p.errors = errorR
	cmd := &exec.Cmd{
		Path:        "/proc/self/fd/6",
		Args:        argv,
		ExtraFiles:  []*os.File{target, gateR, errorW, bootstrap},
		SysProcAttr: &unix.SysProcAttr{PidFD: &p.PIDFD},
	}
	if stdio[0] != nil {
		cmd.Stdin = stdio[0]
	}
	if stdio[1] != nil {
		cmd.Stdout = stdio[1]
	}
	if stdio[2] != nil {
		cmd.Stderr = stdio[2]
	}
	if err = cmd.Start(); err != nil {
		return nil, fmt.Errorf("start launch bootstrap: %w", err)
	}
	p.Process = cmd.Process
	if err = errors.Join(gateR.Close(), errorW.Close()); err != nil {
		return nil, err
	}
	if p.PIDFD < 0 {
		return nil, fmt.Errorf("launch requires atomic child pidfd: %w", unix.ENOSYS)
	}
	if err = readReady(errorR, timeout); err != nil {
		return nil, err
	}
	p.errorFD = int(errorR.Fd())
	if err = unix.SetNonblock(p.errorFD, true); err != nil {
		return nil, fmt.Errorf("nonblocking launch error pipe: %w", err)
	}
	return p, nil
}

func readReady(f *os.File, timeout time.Duration) error {
	if err := f.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("launch ready deadline: %w", err)
	}
	var record [4]byte
	if _, err := io.ReadFull(f, record[:]); err != nil {
		return fmt.Errorf("launch ready: %w", err)
	}
	if value := binary.LittleEndian.Uint32(record[:]); value != 0 {
		return fmt.Errorf("launch bootstrap setup: %w", recordError(value))
	}
	if err := f.SetReadDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clear launch ready deadline: %w", err)
	}
	return nil
}

func recordError(value uint32) error {
	if value == 0 || value > 4095 {
		return fmt.Errorf("invalid launch error record %d: %w", value, unix.EPROTO)
	}
	return unix.Errno(value)
}

func (p *Process) Release() error {
	if p.gate == nil {
		return os.ErrClosed
	}
	f := p.gate
	p.gate = nil
	n, err := f.Write([]byte{1})
	if err == nil && n != 1 {
		err = io.ErrShortWrite
	}
	return errors.Join(err, f.Close())
}

func (p *Process) ExecError() error {
	if p.errors == nil {
		return os.ErrClosed
	}
	if p.execResultRead {
		return p.execResult
	}
	var record [4]byte
	var n int
	var err error
	for {
		n, err = unix.Read(p.errorFD, record[:])
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("read launch exec result: %w", err)
	}
	if n == 0 {
		p.execResultRead = true
		return nil
	}
	p.execResultRead = true
	if n != len(record) {
		p.execResult = fmt.Errorf("partial launch exec result: %w", unix.EPROTO)
	} else {
		p.execResult = fmt.Errorf("launch execveat: %w", recordError(binary.LittleEndian.Uint32(record[:])))
	}
	return p.execResult
}

func (p *Process) Close() error {
	var err error
	if p.gate != nil {
		err = p.gate.Close()
		p.gate = nil
	}
	if p.errors != nil {
		err = errors.Join(err, p.errors.Close())
		p.errors = nil
		p.errorFD = -1
	}
	return err
}

func (p *Process) abort() error {
	var err error
	if p.Process != nil {
		killErr := p.Process.Kill()
		if errors.Is(killErr, os.ErrProcessDone) || errors.Is(killErr, unix.ESRCH) {
			killErr = nil
		}
		_, waitErr := p.Process.Wait()
		err = errors.Join(killErr, waitErr)
		p.Process = nil
	}
	if p.PIDFD >= 0 {
		err = errors.Join(err, unix.Close(p.PIDFD))
		p.PIDFD = -1
	}
	return err
}
