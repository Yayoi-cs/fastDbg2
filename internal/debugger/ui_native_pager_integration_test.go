package debugger

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"fastdbg2/display"
	"fastdbg2/target"

	"golang.org/x/sys/unix"
)

type uiNativePagerReport struct {
	Stage            string
	Error            string
	PID              int
	Before           target.Snapshot
	After            target.Snapshot
	SelectedBefore   target.ThreadRef
	SelectedAfter    target.ThreadRef
	Prompt           string
	PageError        string
	ForegroundBefore int
	ForegroundAfter  int
	TermiosRestored  bool
	FlagsRestored    bool
	ExitCode         int
}

func uiNativePagerFlags(file *os.File) ([2]int, error) {
	var flags [2]int
	connection, err := file.SyscallConn()
	if err != nil {
		return flags, err
	}
	var failure error
	err = connection.Control(func(fd uintptr) {
		flags[0], failure = unix.FcntlInt(fd, unix.F_GETFL, 0)
		if failure == nil {
			flags[1], failure = unix.FcntlInt(fd, unix.F_GETFD, 0)
		}
	})
	return flags, errors.Join(err, failure)
}

func uiNativePagerHelper(image, command, action string, output *json.Encoder) (result uiNativePagerReport, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	c := New(os.Stdout, display.Renderer{})
	c.contextDisabled = true
	defer func() { err = errors.Join(err, c.Close()) }()
	if err = c.Configure(image, nil); err != nil {
		return result, err
	}
	if _, err = c.Execute(ctx, "break", "ui_point"); err != nil {
		return result, err
	}
	if _, err = c.Execute(ctx, "run", ""); err != nil {
		return result, err
	}
	if c.session.State() != target.StateStopped || c.session.LastStop().Reason != target.StopBreakpoint || c.session.LastStop().Breakpoint == nil || c.session.LastStop().RawPC == nil || *c.session.LastStop().RawPC != *c.session.LastStop().Breakpoint+1 {
		return result, fmt.Errorf("fixture did not stop at its breakpoint: %+v", c.session.LastStop())
	}
	result.PID = c.session.PID()
	result.Before, err = c.session.Snapshot()
	if err != nil {
		return result, err
	}
	result.SelectedBefore = c.selected
	var trap [1]byte
	if n, err := c.session.ReadSpaceMemory(result.Before.Memory, *c.session.LastStop().Breakpoint, trap[:]); err != nil || n != 1 || trap[0] != 0xcc {
		return result, fmt.Errorf("initial software breakpoint byte: count=%d byte=%x error=%v", n, trap, err)
	}
	result.Prompt = c.Prompt()
	if result.Prompt != fmt.Sprintf("[fastDbg2:%#x]$ ", *c.session.LastStop().Breakpoint) || c.Prompt() != result.Prompt {
		return result, fmt.Errorf("prompt did not preserve confirmed breakpoint PC: %q", result.Prompt)
	}
	queried, err := c.session.Snapshot()
	if err != nil || !reflect.DeepEqual(result.Before, queried) {
		return result, fmt.Errorf("snapshot and prompt queries mutated native state: %w", err)
	}
	termiosBefore, err := unix.IoctlGetTermios(0, unix.TCGETS)
	if err != nil {
		return result, err
	}
	result.ForegroundBefore, err = unix.IoctlGetInt(0, unix.TIOCGPGRP)
	if err != nil {
		return result, err
	}
	inputFlags, err := uiNativePagerFlags(os.Stdin)
	if err != nil {
		return result, err
	}
	outputFlags, err := uiNativePagerFlags(os.Stdout)
	if err != nil {
		return result, err
	}
	c.EnablePager(os.Stdin)
	if c.pager == nil || c.out != os.Stdout {
		return result, errors.New("actual terminal pager was not enabled without replacing output identity")
	}
	result.Stage = "ready"
	if err = output.Encode(result); err != nil {
		return result, err
	}
	args := "ui_value"
	if command == "telescope" {
		args = "ui_chain 2"
	}
	_, pageErr := c.Execute(ctx, command, args)
	if pageErr != nil {
		return result, pageErr
	}
	if pageErr != nil {
		result.PageError = pageErr.Error()
	}
	result.After, err = c.session.Snapshot()
	if err != nil {
		return result, err
	}
	result.SelectedAfter = c.selected
	if n, err := c.session.ReadSpaceMemory(result.Before.Memory, *c.session.LastStop().Breakpoint, trap[:]); err != nil || n != 1 || trap[0] != 0xcc {
		return result, fmt.Errorf("pager changed physical breakpoint or invalidated original memory token: count=%d byte=%x error=%v", n, trap, err)
	}
	if !reflect.DeepEqual(result.Before, result.After) || result.SelectedBefore != result.SelectedAfter || c.Prompt() != result.Prompt {
		return result, errors.New("pager changed native snapshot, memory/thread tokens, selection, or prompt PC")
	}
	termiosAfter, err := unix.IoctlGetTermios(0, unix.TCGETS)
	if err != nil {
		return result, err
	}
	result.ForegroundAfter, err = unix.IoctlGetInt(0, unix.TIOCGPGRP)
	if err != nil {
		return result, err
	}
	inputAfter, inputErr := uiNativePagerFlags(os.Stdin)
	outputAfter, outputErr := uiNativePagerFlags(os.Stdout)
	if err = errors.Join(inputErr, outputErr); err != nil {
		return result, err
	}
	result.TermiosRestored = reflect.DeepEqual(termiosBefore, termiosAfter)
	result.FlagsRestored = inputFlags == inputAfter && outputFlags == outputAfter
	if !result.TermiosRestored || !result.FlagsRestored || result.ForegroundBefore != result.ForegroundAfter {
		return result, errors.New("pager did not restore terminal group, settings, and descriptor flags")
	}
	if _, err = c.Execute(ctx, "delete", "all"); err != nil {
		return result, err
	}
	for range 16 {
		if c.session.State() == target.StateExited {
			break
		}
		if _, err = c.Execute(ctx, "continue", ""); err != nil {
			return result, fmt.Errorf("continuing after pager exposed a pending signal: %w", err)
		}
	}
	stop := c.session.LastStop()
	if c.session.State() != target.StateExited || stop.Reason != target.StopExited || stop.ExitCode == nil || *stop.ExitCode != 29 {
		return result, fmt.Errorf("pager affected inferior completion: %+v", stop)
	}
	result.ExitCode = *stop.ExitCode
	if err = c.Close(); err != nil {
		return result, err
	}
	result.Stage = "done"
	return result, nil
}

func TestUINativePagerHelperProcess(t *testing.T) {
	if os.Getenv("FASTDBG2_UI_NATIVE_PAGER_HELPER") != "1" {
		return
	}
	unix.CloseOnExec(3)
	pipe := os.NewFile(3, "ui-native-pager-report")
	defer pipe.Close()
	encoder := json.NewEncoder(pipe)
	result, err := uiNativePagerHelper(os.Getenv("FASTDBG2_UI_NATIVE_PAGER_IMAGE"), os.Getenv("FASTDBG2_UI_NATIVE_PAGER_COMMAND"), os.Getenv("FASTDBG2_UI_NATIVE_PAGER_ACTION"), encoder)
	if err != nil {
		result.Stage, result.Error = "error", err.Error()
	}
	if encodeErr := encoder.Encode(result); encodeErr != nil {
		t.Fatal(encodeErr)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func uiNativePagerChildren() ([]int, error) {
	paths, err := filepath.Glob("/proc/self/task/*/children")
	if err != nil {
		return nil, err
	}
	seen := map[int]bool{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, word := range strings.Fields(string(data)) {
			pid, err := strconv.Atoi(word)
			if err != nil {
				return nil, err
			}
			seen[pid] = true
		}
	}
	var result []int
	for pid := range seen {
		result = append(result, pid)
	}
	return result, nil
}

func uiNativePagerLess(root int) (int, error) {
	queue := []int{root}
	seen := map[int]bool{}
	for len(queue) != 0 {
		pid := queue[0]
		queue = queue[1:]
		if seen[pid] {
			continue
		}
		seen[pid] = true
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			return 0, err
		}
		args := bytes.Split(data, []byte{0})
		if len(args) == 6 && filepath.Base(string(args[0])) == "less" && string(args[1]) == "-SR" && string(args[2]) == pagerPrompt && string(args[3]) == "--" && filepath.IsAbs(string(args[4])) {
			return pid, nil
		}
		paths, err := filepath.Glob(fmt.Sprintf("/proc/%d/task/*/children", pid))
		if err != nil {
			return 0, err
		}
		for _, path := range paths {
			data, err := os.ReadFile(path)
			if err != nil {
				return 0, err
			}
			for _, word := range strings.Fields(string(data)) {
				child, err := strconv.Atoi(word)
				if err != nil {
					return 0, err
				}
				queue = append(queue, child)
			}
		}
	}
	return 0, errors.New("actual less -SR process was not found in owned descendants")
}

func TestUINativePagerPreservesStoppedSnapshot(t *testing.T) {
	if _, err := exec.LookPath("less"); err != nil {
		t.Fatal(err)
	}
	var priorSubreaper int32
	if err := unix.Prctl(unix.PR_GET_CHILD_SUBREAPER, uintptr(unsafe.Pointer(&priorSubreaper)), 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, uintptr(priorSubreaper), 0, 0, 0); err != nil {
			t.Error(err)
		}
	})
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	image := deterministicBuild(t, "cc", uiIntegrationSource, true, "-O0")
	for _, name := range []string{"sym", "telescope"} {
		for _, action := range []string{"quit", "interrupt"} {
			t.Run(name+"/"+action, func(t *testing.T) {
				beforeChildren, err := uiNativePagerChildren()
				if err != nil {
					t.Fatal(err)
				}
				baseline := map[int]bool{}
				for _, pid := range beforeChildren {
					baseline[pid] = true
				}
				master, slave := pagerTestPTY(t)
				connection, err := slave.SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				var sizeErr error
				if err := connection.Control(func(fd uintptr) {
					sizeErr = unix.IoctlSetWinsize(int(fd), unix.TIOCSWINSZ, &unix.Winsize{Row: 24, Col: 80})
				}); err != nil || sizeErr != nil {
					t.Fatal(errors.Join(err, sizeErr))
				}
				if err := master.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
					t.Fatal(err)
				}
				reader, writer, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Close()
				defer writer.Close()
				if err := reader.SetReadDeadline(time.Now().Add(25 * time.Second)); err != nil {
					t.Fatal(err)
				}
				command := exec.Command(os.Args[0], "-test.run=^TestUINativePagerHelperProcess$", "-test.timeout=30s")
				command.Dir = root
				command.Stdin, command.Stdout, command.Stderr = slave, slave, slave
				command.ExtraFiles = []*os.File{writer}
				command.Env = append(os.Environ(), "TERM=xterm-256color", "NO_COLOR=1", "FASTDBG2_UI_NATIVE_PAGER_HELPER=1", "FASTDBG2_UI_NATIVE_PAGER_IMAGE="+image, "FASTDBG2_UI_NATIVE_PAGER_COMMAND="+name, "FASTDBG2_UI_NATIVE_PAGER_ACTION="+action)
				command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
				if err := command.Start(); err != nil {
					t.Fatal(err)
				}
				waited := false
				defer func() {
					aborted := !waited
					if aborted {
						_ = command.Process.Kill()
						_ = command.Wait()
					}
					for range 32 {
						current, err := uiNativePagerChildren()
						if err != nil {
							t.Error(err)
							break
						}
						found := false
						for _, pid := range current {
							if baseline[pid] {
								continue
							}
							found = true
							if aborted {
								t.Logf("validation-abort recovery owns adopted child %d", pid)
							} else {
								t.Errorf("completed pager helper left owned child %d", pid)
							}
							fd, err := unix.PidfdOpen(pid, 0)
							if err != nil {
								t.Error(err)
								continue
							}
							_ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
							_, pollErr := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, 10000)
							_ = unix.Close(fd)
							if pollErr != nil {
								t.Error(pollErr)
							}
							var status unix.WaitStatus
							if _, err := unix.Wait4(pid, &status, 0, nil); err != nil {
								t.Error(err)
							}
						}
						if !found {
							break
						}
					}
				}()
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				decoder := json.NewDecoder(reader)
				var ready uiNativePagerReport
				if err := decoder.Decode(&ready); err != nil || ready.Stage != "ready" {
					t.Fatalf("pager readiness: %+v %v", ready, err)
				}
				marker := []byte("[symbols]")
				if name == "telescope" {
					marker = []byte("|+0x0000|+000:")
				}
				var output bytes.Buffer
				data := make([]byte, 8192)
				for !bytes.Contains(output.Bytes(), marker) || !bytes.Contains(output.Bytes(), []byte("q quit")) {
					n, err := master.Read(data)
					output.Write(data[:n])
					if err != nil {
						t.Fatalf("actual pager output: %v\n%s", err, output.String())
					}
				}
				if !bytes.Contains(output.Bytes(), []byte("\x1b[?1049h")) || !bytes.Contains(output.Bytes(), []byte("\x1b[?1h")) || !bytes.Contains(output.Bytes(), []byte("\x1b=")) {
					t.Fatalf("pager bypassed alternate-screen/keypad initialization: %q", output.String())
				}
				less, err := uiNativePagerLess(command.Process.Pid)
				if err != nil {
					t.Fatal(err)
				}
				if name == "telescope" {
					arguments, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", less))
					if err != nil {
						t.Fatal(err)
					}
					page, err := os.ReadFile(string(bytes.Split(arguments, []byte{0})[4]))
					rows := strings.Split(strings.TrimSuffix(string(page), "\n"), "\n")
					if err != nil || len(rows) != 2 || display.VisibleWidth(rows[0]) <= 80 || strings.Count(rows[0], " -> ") < 2 {
						t.Fatalf("native telescope lost logical rows before less: error=%v page=%q", err, page)
					}
				}
				masterConnection, err := master.SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				var foreground int
				var foregroundErr error
				if err := masterConnection.Control(func(fd uintptr) {
					foreground, foregroundErr = unix.IoctlGetInt(int(fd), unix.TIOCGPGRP)
				}); err != nil || foregroundErr != nil {
					t.Fatal(errors.Join(err, foregroundErr))
				}
				group, err := unix.Getpgid(less)
				if err != nil || foreground != group || foreground == command.Process.Pid {
					t.Fatalf("less lacks isolated foreground group: foreground=%d less=%d group=%d err=%v", foreground, less, group, err)
				}
				if action == "interrupt" {
					if _, err := io.WriteString(master, "/N"); err != nil {
						t.Fatal(err)
					}
					var search bytes.Buffer
					for !bytes.Contains(search.Bytes(), []byte("N")) {
						n, err := master.Read(data)
						search.Write(data[:n])
						if err != nil {
							t.Fatalf("pager search input: %v\n%s", err, search.String())
						}
					}
					for range 2 {
						if _, err := io.WriteString(master, "\x03"); err != nil {
							t.Fatal(err)
						}
						var interrupted bytes.Buffer
						for !bytes.Contains(interrupted.Bytes(), []byte("q quit")) {
							n, err := master.Read(data)
							interrupted.Write(data[:n])
							if err != nil {
								t.Fatalf("pager did not retain Ctrl-C: %v\n%s", err, interrupted.String())
							}
						}
						current, err := uiNativePagerLess(command.Process.Pid)
						if err != nil || current != less || bytes.Contains(interrupted.Bytes(), []byte("\x1b[?1049l")) {
							t.Fatalf("Ctrl-C escaped or replaced less: before=%d after=%d error=%v text=%q", less, current, err, interrupted.String())
						}
					}
				}
				if _, err := io.WriteString(master, "q"); err != nil {
					t.Fatal(err)
				}
				var restored bytes.Buffer
				for !bytes.Contains(restored.Bytes(), []byte("\x1b[?1049l")) || !bytes.Contains(restored.Bytes(), []byte("\x1b[?1l")) || !bytes.Contains(restored.Bytes(), []byte("\x1b>")) {
					n, err := master.Read(data)
					restored.Write(data[:n])
					if err != nil {
						t.Fatalf("pager did not restore screen/keypad on q: %v\n%s", err, restored.String())
					}
				}
				var done uiNativePagerReport
				if err := decoder.Decode(&done); err != nil || done.Stage != "done" {
					t.Fatalf("pager completion: %+v %v", done, err)
				}
				if err := command.Wait(); err != nil {
					waited = true
					t.Fatal(err)
				}
				waited = true
				if !reflect.DeepEqual(ready.Before, done.After) || done.SelectedBefore != done.SelectedAfter || done.Before.State != target.StateStopped || len(done.Before.Threads) != 2 || !done.TermiosRestored || !done.FlagsRestored || done.ForegroundBefore != done.ForegroundAfter || done.ExitCode != 29 {
					t.Fatalf("native pager changed facts: %+v", done)
				}
				record, err := json.Marshal(done)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("native pager snapshot evidence: %s", record)
				for _, pid := range []int{less, done.PID} {
					if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("owned process %d remains: %v", pid, err)
					}
				}
			})
		}
	}
}
