package shellcmd

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

func Helper(arguments []string) (int, bool) {
	if len(arguments) != 1 || arguments[0] != helperArgument {
		return 0, false
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	signals := make(chan os.Signal, 16)
	signal.Notify(signals, syscall.SIGCHLD, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGPIPE, syscall.SIGQUIT, syscall.SIGTSTP)
	defer signal.Stop(signals)
	control, err := protocolFile(3, "shell-control")
	if err != nil {
		return 125, true
	}
	defer control.Close()
	response, err := protocolFile(4, "shell-result")
	if err != nil {
		return 125, true
	}
	defer response.Close()
	command, err := readConfiguration(control)
	var outcome result
	if err != nil {
		outcome.Error = err.Error()
	} else {
		outcome = supervise(command, control, signals)
	}
	if len(outcome.Error) > 4096 {
		const suffix = " ... [truncated]"
		end := 4096 - len(suffix)
		for !utf8.RuneStart(outcome.Error[end]) {
			end--
		}
		outcome.Error = outcome.Error[:end] + suffix
	}
	if err := json.NewEncoder(response).Encode(outcome); err != nil {
		return 125, true
	}
	return 0, true
}

func protocolFile(fd int, name string) (*os.File, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFIFO {
		return nil, errors.New("shell supervisor requires private protocol pipes")
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return nil, err
	}
	if fd == 3 && flags&unix.O_ACCMODE != unix.O_RDONLY || fd == 4 && flags&unix.O_ACCMODE != unix.O_WRONLY {
		return nil, errors.New("shell supervisor protocol pipe direction is invalid")
	}
	unix.CloseOnExec(fd)
	return os.NewFile(uintptr(fd), name), nil
}

func readConfiguration(input io.Reader) (request, error) {
	header := make([]byte, len(protocolMagic)+4)
	if _, err := io.ReadFull(input, header); err != nil {
		return request{}, fmt.Errorf("read shell supervisor configuration: %w", err)
	}
	if string(header[:len(protocolMagic)]) != protocolMagic {
		return request{}, errors.New("invalid shell supervisor protocol")
	}
	length := binary.LittleEndian.Uint32(header[len(protocolMagic):])
	if length == 0 || length > commandLimit {
		return request{}, errors.New("invalid shell supervisor command length")
	}
	command := make([]byte, length)
	if _, err := io.ReadFull(input, command); err != nil {
		return request{}, fmt.Errorf("read shell supervisor command: %w", err)
	}
	var configuration request
	decoder := json.NewDecoder(bytes.NewReader(command))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&configuration); err != nil {
		return request{}, fmt.Errorf("decode shell supervisor command: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return request{}, errors.New("unexpected trailing shell supervisor configuration")
	}
	if err := validateRequest(configuration); err != nil {
		return request{}, err
	}
	return configuration, nil
}

func supervise(command request, control *os.File, signals <-chan os.Signal) result {
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		return result{Error: fmt.Sprintf("shell child subreaper unavailable: %v", err)}
	}
	probe, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		return result{Error: fmt.Sprintf("shell pidfd support unavailable: %v", err)}
	}
	err = unix.PidfdSendSignal(probe, 0, nil, 0)
	unix.Close(probe)
	if err != nil {
		return result{Error: fmt.Sprintf("shell pidfd signals unavailable: %v", err)}
	}
	if _, err := directChildren(); err != nil {
		return result{Error: fmt.Sprintf("shell child ownership unavailable: %v", err)}
	}
	controlDone := make(chan struct{})
	go func() {
		var value [1]byte
		control.Read(value[:])
		close(controlDone)
	}()
	select {
	case <-controlDone:
		return result{Canceled: true}
	default:
	}
	files := []*os.File{os.Stdin, os.Stdout, os.Stderr}
	for index := 0; index < command.Files; index++ {
		fd := 5 + index
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
			return result{Error: fmt.Sprintf("supervised extra descriptor %d: %v", index, err)}
		}
		unix.CloseOnExec(fd)
		file := os.NewFile(uintptr(fd), "supervised-extra")
		defer file.Close()
		files = append(files, file)
	}
	if command.Env == nil {
		command.Env = os.Environ()
	}
	pid, err := spawnPinned(command.Path, command.Args, files, &syscall.ProcAttr{
		Dir: command.Dir,
		Env: command.Env,
	})
	if err != nil {
		return result{Error: fmt.Sprintf("start %q: %v", command.Path, err)}
	}
	var outcome result
	for {
		finished, _, err := reap(pid, &outcome)
		if err != nil {
			outcome.Error = fmt.Sprintf("wait shell children: %v", err)
			break
		}
		if finished {
			break
		}
		select {
		case <-controlDone:
			outcome.Canceled = true
		case caught := <-signals:
			if caught == syscall.SIGCHLD {
				continue
			}
			if command.Pager && caught == syscall.SIGINT {
				continue
			}
			outcome.Canceled = true
		}
		break
	}
	if command.Pager {
		var pagerErr error
		if outcome.Canceled && !outcome.reaped {
			pagerErr = stopPager(pid, &outcome)
		}
		if outcome.reaped {
			if outcome.Signal != 0 && pagerErr == nil {
				pagerErr = pagerSignalError(outcome.Signal)
			}
			children, err := directChildren()
			if err != nil || len(children) != 0 {
				pagerErr = errors.Join(pagerErr, fmt.Errorf("pager descendants require forced cleanup; terminal screen restoration is unconfirmed: children=%v, error=%v", children, err))
			}
		}
		if pagerErr != nil {
			fmt.Fprintf(os.Stderr, "command cleanup: %v\n", pagerErr)
			if outcome.Error != "" {
				pagerErr = errors.Join(errors.New(outcome.Error), pagerErr)
			}
			outcome.Error = pagerErr.Error()
		}
	}
	if err := terminateChildren(pid, &outcome); err != nil {
		if outcome.Error != "" {
			err = errors.Join(errors.New(outcome.Error), err)
		}
		outcome.Error = fmt.Sprintf("reap shell descendants: %v", err)
	}
	return outcome
}

func reap(root int, outcome *result) (bool, bool, error) {
	finished := outcome.reaped
	for {
		var status unix.WaitStatus
		pid, err := unix.Wait4(-1, &status, unix.WNOHANG|unix.WALL, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.ECHILD) {
			return finished, true, nil
		}
		if err != nil {
			return finished, false, err
		}
		if pid == 0 {
			return finished, false, nil
		}
		recordStatus(root, pid, status, outcome)
		finished = outcome.reaped
	}
}

func recordStatus(root, pid int, status unix.WaitStatus, outcome *result) {
	if pid != root || outcome.reaped {
		return
	}
	outcome.reaped = true
	if status.Exited() {
		outcome.Code = status.ExitStatus()
	} else if status.Signaled() {
		outcome.Signal = int(status.Signal())
	}
}

func waitOwnedChild(root int, outcome *result) error {
	for {
		var status unix.WaitStatus
		pid, err := unix.Wait4(-1, &status, unix.WALL, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.ECHILD) {
			return nil
		}
		if err != nil {
			return err
		}
		recordStatus(root, pid, status, outcome)
		return nil
	}
}

func directChildren() ([]int, error) {
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, task := range tasks {
		contents, err := os.ReadFile("/proc/self/task/" + task.Name() + "/children")
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, value := range strings.Fields(string(contents)) {
			pid, err := strconv.Atoi(value)
			if err != nil || pid <= 0 {
				return nil, errors.New("invalid direct child PID")
			}
			pids = append(pids, pid)
		}
	}
	slices.Sort(pids)
	return slices.Compact(pids), nil
}

func childHandle(pid int) (int, error) {
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return -1, err
	}
	contents, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		unix.Close(fd)
		return -1, err
	}
	open, close := strings.IndexByte(string(contents), '('), strings.LastIndexByte(string(contents), ')')
	if open <= 0 || close <= open {
		unix.Close(fd)
		return -1, errors.New("invalid child process identity")
	}
	identity, identityErr := strconv.Atoi(strings.TrimSpace(string(contents[:open])))
	fields := strings.Fields(string(contents[close+1:]))
	if identityErr != nil || identity != pid || len(fields) < 2 {
		unix.Close(fd)
		return -1, errors.New("invalid child process identity")
	}
	parent, err := strconv.Atoi(fields[1])
	if err != nil || parent != os.Getpid() {
		unix.Close(fd)
		return -1, fmt.Errorf("PID %d is not an owned shell child", pid)
	}
	return fd, nil
}

func terminateChildren(root int, outcome *result) error {
	var recorded error
	report := func(err error) {
		if recorded == nil {
			recorded = err
		}
		fmt.Fprintf(os.Stderr, "command cleanup: %v; retaining ownership and waiting for natural exit\n", err)
	}
	for {
		_, empty, err := reap(root, outcome)
		if err != nil {
			return errors.Join(recorded, err)
		}
		pids, err := directChildren()
		if err != nil {
			report(fmt.Errorf("cannot enumerate owned children: %w", err))
			if empty {
				return recorded
			}
			if err := waitOwnedChild(root, outcome); err != nil {
				return errors.Join(recorded, err)
			}
			continue
		}
		if empty && len(pids) == 0 {
			return recorded
		}
		var handles []unix.PollFd
		for _, pid := range pids {
			fd, err := childHandle(pid)
			if errors.Is(err, unix.ESRCH) || errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				report(fmt.Errorf("cannot verify owned child PID %d: %w", pid, err))
				continue
			}
			handles = append(handles, unix.PollFd{Fd: int32(fd), Events: unix.POLLIN})
			if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
				report(fmt.Errorf("cannot terminate owned PID %d: %w", pid, err))
			}
		}
		if len(handles) == 0 {
			if recorded != nil {
				if err := waitOwnedChild(root, outcome); err != nil {
					return errors.Join(recorded, err)
				}
			}
			continue
		}
		for {
			_, err = unix.Poll(handles, -1)
			if !errors.Is(err, unix.EINTR) {
				break
			}
		}
		for _, handle := range handles {
			unix.Close(int(handle.Fd))
		}
		if err != nil {
			return errors.Join(recorded, err)
		}
	}
}
