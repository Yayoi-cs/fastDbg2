package shellcmd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestTerminalOutputRestoresSignalMask(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var before, after unix.Sigset_t
	if err := unix.PthreadSigmask(unix.SIG_SETMASK, nil, &before); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("output failure")
	err := withTerminalOutput(func() error {
		var current unix.Sigset_t
		if err := unix.PthreadSigmask(unix.SIG_SETMASK, nil, &current); err != nil {
			return err
		}
		if current.Val[0]&(1<<(uint(unix.SIGTTOU)-1)) == 0 {
			return errors.New("SIGTTOU was not blocked")
		}
		return failure
	})
	if !errors.Is(err, failure) {
		t.Fatalf("scoped output error: %v", err)
	}
	if err := unix.PthreadSigmask(unix.SIG_SETMASK, nil, &after); err != nil || before != after {
		t.Fatalf("signal mask changed: %v -> %v (%v)", before, after, err)
	}
	func() {
		defer func() { recover() }()
		withTerminalOutput(func() error { panic("writer panic") })
	}()
	if err := unix.PthreadSigmask(unix.SIG_SETMASK, nil, &after); err != nil || before != after {
		t.Fatalf("panic changed signal mask: %v -> %v (%v)", before, after, err)
	}
}

func TestTerminalOwnerProcess(t *testing.T) {
	var mode string
	for index, value := range os.Args {
		if value == "--" && len(os.Args) == index+3 && os.Args[index+1] == "terminal-owner" {
			mode = os.Args[index+2]
		}
	}
	if mode == "" {
		return
	}
	connection, err := os.Stdin.SyscallConn()
	if err != nil {
		os.Exit(75)
	}
	var flagErr error
	err = connection.Control(func(fd uintptr) {
		flags, err := unix.FcntlInt(fd, unix.F_GETFL, 0)
		if err != nil {
			flagErr = err
			return
		}
		_, flagErr = unix.FcntlInt(fd, unix.F_SETFL, flags|unix.O_NONBLOCK)
		if flagErr == nil {
			_, flagErr = unix.FcntlInt(fd, unix.F_SETFD, unix.FD_CLOEXEC)
		}
	})
	beforeFlags, flagsErr := readDescriptorFlags(os.Stdin)
	if err != nil || flagErr != nil || flagsErr != nil {
		os.Exit(76)
	}
	lease, err := acquireTerminal(os.Stdin)
	if err != nil || lease == nil {
		fmt.Fprintf(os.Stderr, "acquire: %v\n", err)
		os.Exit(71)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	command := "stty -echo -icanon; printf 'DONE\\n'"
	if strings.Contains(mode, "interrupt") {
		command = "stty -echo -icanon; printf 'READY\\n'; sleep 3600"
	}
	if strings.HasPrefix(mode, "direct-") {
		command = "test -t 1 && test -t 2 || exit 65; " + command
		output := os.Stdout
		if mode == "direct-alias" {
			output, err = os.OpenFile("/dev/tty", os.O_WRONLY, 0)
			if err != nil {
				os.Exit(78)
			}
			defer output.Close()
		}
		if mode == "direct-wrong-tty" {
			_, output = shellPTY(t, false)
		}
		err = RunCommand(ctx, Command{Path: "/bin/sh", Args: []string{"-c", command}, Stdin: os.Stdin, Output: output, Foreground: true, TerminalOutput: true})
		if mode == "direct-wrong-tty" {
			if err == nil || !strings.Contains(err.Error(), "same controlling terminal") {
				fmt.Fprintf(os.Stderr, "unowned output terminal: %v\n", err)
				os.Exit(79)
			}
			err = nil
		}
	} else {
		err = Run(ctx, command, os.Stdin, os.Stdout)
	}
	if strings.Contains(mode, "interrupt") {
		if err == nil || !strings.Contains(err.Error(), "shell interrupted") {
			fmt.Fprintf(os.Stderr, "interrupt: %v\n", err)
			os.Exit(72)
		}
	} else if err != nil {
		fmt.Fprintf(os.Stderr, "command: %v\n", err)
		os.Exit(73)
	}
	after, err := acquireTerminal(os.Stdin)
	if err != nil || after == nil || lease.group != after.group || *lease.termios != *after.termios {
		fmt.Fprintf(os.Stderr, "terminal not restored: %v\n", err)
		os.Exit(74)
	}
	afterFlags, err := readDescriptorFlags(os.Stdin)
	if err != nil || afterFlags != beforeFlags {
		fmt.Fprintf(os.Stderr, "terminal flags changed: %+v -> %+v (%v)\n", beforeFlags, afterFlags, err)
		os.Exit(77)
	}
	fmt.Fprintln(os.Stdout, "RESTORED")
	os.Exit(0)
}

func TestShellForegroundAndTermiosRestored(t *testing.T) {
	for _, mode := range []string{"normal", "interrupt", "tostop", "direct-normal", "direct-interrupt", "direct-tostop", "direct-alias", "direct-wrong-tty"} {
		t.Run(mode, func(t *testing.T) {
			master, slave := shellPTY(t, strings.HasSuffix(mode, "tostop"))
			defer master.Close()
			defer slave.Close()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			child := exec.Command(executable, "-test.run=^TestTerminalOwnerProcess$", "--", "terminal-owner", mode)
			child.Stdin, child.Stdout, child.Stderr = slave, slave, slave
			child.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			slave.Close()
			finished := make(chan error, 1)
			go func() { finished <- child.Wait() }()
			output := make(chan string, 1)
			go func() {
				var collected bytes.Buffer
				reader := bufio.NewReader(master)
				for {
					line, err := reader.ReadString('\n')
					collected.WriteString(line)
					if strings.Contains(line, "READY") {
						master.Write([]byte{3})
					}
					if err != nil {
						output <- collected.String()
						return
					}
				}
			}()
			select {
			case err := <-finished:
				text := <-output
				if err != nil || !strings.Contains(text, "RESTORED") {
					t.Fatalf("terminal shell: %v: %q", err, text)
				}
			case <-time.After(15 * time.Second):
				child.Process.Kill()
				<-finished
				master.Close()
				t.Fatalf("terminal shell timed out: %q", <-output)
			}
		})
	}
}

func shellPTY(t *testing.T, tostop bool) (*os.File, *os.File) {
	t.Helper()
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	master := os.NewFile(uintptr(fd), "shell-pty-master")
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		master.Close()
		t.Fatal(err)
	}
	index, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		master.Close()
		t.Fatal(err)
	}
	slaveFD, err := unix.Open("/dev/pts/"+strconv.Itoa(index), unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		master.Close()
		t.Fatal(err)
	}
	slave := os.NewFile(uintptr(slaveFD), "shell-pty-slave")
	if tostop {
		settings, err := unix.IoctlGetTermios(slaveFD, unix.TCGETS)
		if err == nil {
			settings.Lflag |= unix.TOSTOP
			err = unix.IoctlSetTermios(slaveFD, unix.TCSETS, settings)
		}
		if err != nil {
			master.Close()
			slave.Close()
			t.Fatal(err)
		}
	}
	return master, slave
}
