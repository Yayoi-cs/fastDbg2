package shellcmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func pagerTestMode(tag string) string {
	for index, argument := range os.Args {
		if argument == "--" && len(os.Args) == index+3 && os.Args[index+1] == tag {
			return os.Args[index+2]
		}
	}
	return ""
}

func TestPagerShutdownChildProcess(t *testing.T) {
	mode := pagerTestMode("pager-child")
	if mode == "" {
		return
	}
	ready := os.NewFile(3, "pager-ready")
	signals := make(chan os.Signal, 4)
	if mode != "signaled" {
		signal.Notify(signals, syscall.SIGTERM)
	} else {
		signal.Reset(syscall.SIGTERM)
	}
	if _, err := ready.Write([]byte{'R'}); err != nil {
		syscall.Exit(81)
	}
	ready.Close()
	if mode == "signaled" {
		for {
			unix.Pause()
		}
	}
	for range signals {
		if mode == "graceful" {
			fmt.Fprintln(os.Stdout, "PAGER_DEINITIALIZED")
			syscall.Exit(0)
		}
	}
}

func pagerShutdownScenario(mode string) error {
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		return err
	}
	input, err := os.Open(os.DevNull)
	if err != nil {
		return err
	}
	defer input.Close()
	ready, writer, err := os.Pipe()
	if err != nil {
		return err
	}
	defer ready.Close()
	defer writer.Close()
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	pid, err := spawnPinned(executable, []string{"-test.run=^TestPagerShutdownChildProcess$", "--", "pager-child", mode}, []*os.File{input, os.Stdout, os.Stderr, writer}, &syscall.ProcAttr{Env: os.Environ()})
	if err != nil {
		return err
	}
	var outcome result
	defer terminateChildren(pid, &outcome)
	writer.Close()
	var signalReady [1]byte
	if _, err := io.ReadFull(ready, signalReady[:]); err != nil || signalReady[0] != 'R' {
		return errors.Join(errors.New("pager signal fixture was not ready"), err)
	}
	started := time.Now()
	stopErr := stopPager(pid, &outcome)
	if err := terminateChildren(pid, &outcome); err != nil {
		return err
	}
	if !outcome.reaped {
		return errors.New("pager root was not reaped")
	}
	switch mode {
	case "graceful":
		if stopErr != nil || outcome.Code != 0 || outcome.Signal != 0 {
			return fmt.Errorf("graceful pager exit: %+v, %v", outcome, stopErr)
		}
	case "ignore":
		if stopErr == nil || !strings.Contains(stopErr.Error(), "did not exit within 1s") || !strings.Contains(stopErr.Error(), "restoration is unconfirmed") || outcome.Signal != int(unix.SIGKILL) || time.Since(started) < pagerExitGrace {
			return fmt.Errorf("unresponsive pager exit: %+v, %v", outcome, stopErr)
		}
	case "signaled":
		if stopErr == nil || !strings.Contains(stopErr.Error(), "terminated by signal 15") || !strings.Contains(stopErr.Error(), "restoration is unconfirmed") || outcome.Signal != int(unix.SIGTERM) {
			return fmt.Errorf("abrupt pager exit: %+v, %v", outcome, stopErr)
		}
	default:
		return errors.New("unknown pager test mode")
	}
	children, err := directChildren()
	if err != nil || len(children) != 0 {
		return fmt.Errorf("pager descendants remain: %v, %v", children, err)
	}
	fmt.Printf("PAGER_SHUTDOWN_%s_OK\n", mode)
	return nil
}

func TestPagerShutdownPolicyProcess(t *testing.T) {
	mode := pagerTestMode("pager-shutdown")
	if mode == "" {
		return
	}
	if err := pagerShutdownScenario(mode); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(82)
	}
	os.Exit(0)
}

func TestPagerShutdownWaitsForDeinitializationOrReportsForcedCleanup(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"graceful", "ignore", "signaled"} {
		t.Run(mode, func(t *testing.T) {
			command := exec.CommandContext(shellContext(t), executable, "-test.run=^TestPagerShutdownPolicyProcess$", "--", "pager-shutdown", mode)
			output, err := command.CombinedOutput()
			if err != nil || !strings.Contains(string(output), "PAGER_SHUTDOWN_"+mode+"_OK") {
				t.Fatalf("pager shutdown policy %s: %v\n%s", mode, err, output)
			}
			if (mode == "graceful") != strings.Contains(string(output), "PAGER_DEINITIALIZED") {
				t.Fatalf("deinitialization evidence mismatched %s: %s", mode, output)
			}
		})
	}
}

func TestPagerPolicyRequiresForegroundTerminalOutput(t *testing.T) {
	for _, command := range []Command{
		{Pager: true},
		{Pager: true, Foreground: true},
		{Pager: true, TerminalOutput: true},
	} {
		command.Path, command.Stdin, command.Output = "/bin/true", shellInput(t), io.Discard
		if err := RunCommand(shellContext(t), command); err == nil || !strings.Contains(err.Error(), "pager execution requires foreground") {
			t.Fatalf("invalid pager execution accepted: %+v, %v", command, err)
		}
	}
}
