package shellcmd

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func spawnPinned(path string, args []string, files []*os.File, attributes *syscall.ProcAttr) (int, error) {
	attributes.Files = make([]uintptr, len(files))
	pid := -1
	var visit func(int) error
	visit = func(index int) error {
		if index == len(files) {
			var err error
			pid, err = syscall.ForkExec(path, append([]string{path}, args...), attributes)
			return err
		}
		connection, err := files[index].SyscallConn()
		if err != nil {
			return err
		}
		var childErr error
		err = connection.Control(func(fd uintptr) {
			attributes.Files[index] = fd
			childErr = visit(index + 1)
		})
		return errors.Join(err, childErr)
	}
	err := visit(0)
	return pid, err
}

func privateBlocking(file *os.File) error {
	connection, err := file.SyscallConn()
	if err != nil {
		return err
	}
	var flagErr error
	err = connection.Control(func(fd uintptr) { flagErr = unix.SetNonblock(int(fd), false) })
	return errors.Join(err, flagErr)
}

func waitSupervisor(pid int) error {
	for {
		var status unix.WaitStatus
		got, err := unix.Wait4(pid, &status, 0, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if got != pid {
			return fmt.Errorf("waited for supervisor PID %d but received PID %d", pid, got)
		}
		if status.Exited() && status.ExitStatus() == 0 {
			return nil
		}
		if status.Signaled() {
			return fmt.Errorf("terminated by signal %d", status.Signal())
		}
		return fmt.Errorf("exit status %d", status.ExitStatus())
	}
}
