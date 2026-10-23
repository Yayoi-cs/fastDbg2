package shellcmd

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const helperArgument = "--fastdbg2-shell-helper-v1"
const protocolMagic = "fastDbg2 shell 1\n"
const commandLimit = 1 << 20

type OutputError struct {
	Err error
}

func (e *OutputError) Error() string { return fmt.Sprintf("shell output: %v", e.Err) }

func (e *OutputError) Unwrap() error { return e.Err }

type ExitError struct {
	Code   int
	Signal int
}

func (e *ExitError) Error() string {
	if e.Signal != 0 {
		return fmt.Sprintf("shell terminated by signal %d", e.Signal)
	}
	return fmt.Sprintf("shell exited with status %d", e.Code)
}

type result struct {
	Code     int    `json:"code"`
	Signal   int    `json:"signal"`
	Canceled bool   `json:"canceled"`
	Error    string `json:"error,omitempty"`
	reaped   bool
}

type Command struct {
	Path           string
	Args           []string
	Dir            string
	Env            []string
	Stdin          *os.File
	Output         io.Writer
	ExtraFiles     []*os.File
	Foreground     bool
	TerminalOutput bool
	Pager          bool
}

type request struct {
	Path  string   `json:"path"`
	Args  []string `json:"args"`
	Dir   string   `json:"dir"`
	Env   []string `json:"env"`
	Files int      `json:"files"`
	Pager bool     `json:"pager"`
}

func Run(ctx context.Context, command string, input *os.File, output io.Writer) error {
	if err := validateShell(command); err != nil {
		return err
	}
	return RunCommand(ctx, Command{Path: "/bin/sh", Args: []string{"-c", command}, Stdin: input, Output: output, Foreground: true})
}

func RunCommand(ctx context.Context, command Command) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	return runCommand(ctx, command, executable, []string{helperArgument})
}

func run(ctx context.Context, command string, input *os.File, output io.Writer, executable string, arguments []string) error {
	if err := validateShell(command); err != nil {
		return err
	}
	return runCommand(ctx, Command{Path: "/bin/sh", Args: []string{"-c", command}, Stdin: input, Output: output, Foreground: true}, executable, arguments)
}

func validateShell(command string) error {
	if strings.TrimSpace(command) == "" || strings.IndexByte(command, 0) >= 0 || len(command) > commandLimit {
		return errors.New("shell command must contain 1 to 1048576 non-NUL bytes and not be blank")
	}
	return nil
}

func validateRequest(command request) error {
	if !filepath.IsAbs(command.Path) || strings.IndexByte(command.Path, 0) >= 0 || strings.IndexByte(command.Dir, 0) >= 0 || !utf8.ValidString(command.Path) || !utf8.ValidString(command.Dir) || command.Files < 0 || command.Files > 64 || len(command.Args) > 65536 || len(command.Env) > 65536 {
		return errors.New("invalid supervised command path, directory, descriptor count or argument count")
	}
	size := len(command.Path) + len(command.Dir)
	for _, value := range command.Args {
		if strings.IndexByte(value, 0) >= 0 || !utf8.ValidString(value) {
			return errors.New("supervised command argument contains NUL or invalid UTF-8")
		}
		if len(value) > commandLimit-size {
			return errors.New("supervised command configuration exceeds 1048576 bytes")
		}
		size += len(value)
	}
	for _, value := range command.Env {
		if strings.IndexByte(value, 0) >= 0 || !utf8.ValidString(value) {
			return errors.New("supervised command environment contains NUL or invalid UTF-8")
		}
		if len(value) > commandLimit-size {
			return errors.New("supervised command configuration exceeds 1048576 bytes")
		}
		size += len(value)
	}
	if size > commandLimit {
		return errors.New("supervised command configuration exceeds 1048576 bytes")
	}
	return nil
}

func runCommand(ctx context.Context, command Command, executable string, arguments []string) (returnErr error) {
	if ctx == nil || command.Stdin == nil || command.Output == nil {
		return errors.New("supervised command requires a context, input and output")
	}
	if command.Pager && (!command.Foreground || !command.TerminalOutput) {
		return errors.New("pager execution requires foreground direct terminal output")
	}
	configuration := request{Path: command.Path, Args: command.Args, Dir: command.Dir, Env: command.Env, Files: len(command.ExtraFiles), Pager: command.Pager}
	if err := validateRequest(configuration); err != nil {
		return err
	}
	payload, err := json.Marshal(configuration)
	if err != nil {
		return err
	}
	if len(payload) > commandLimit {
		return errors.New("supervised command configuration exceeds 1048576 bytes")
	}
	for _, file := range command.ExtraFiles {
		if file == nil {
			return errors.New("supervised command extra descriptor is nil")
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var terminal *terminalLease
	if command.Foreground {
		terminal, err = acquireTerminal(command.Stdin)
		if err != nil {
			return err
		}
		if terminal != nil {
			defer func() { returnErr = errors.Join(returnErr, terminal.restore()) }()
		}
	}
	var directOutput *os.File
	if command.TerminalOutput {
		if terminal == nil {
			return errors.New("direct terminal output requires the foreground controlling terminal")
		}
		var ok bool
		directOutput, ok = command.Output.(*os.File)
		if !ok {
			return errors.New("direct terminal output requires a terminal file")
		}
		outputTerminal, err := acquireTerminal(directOutput)
		if err != nil || outputTerminal == nil || outputTerminal.group != terminal.group {
			return errors.Join(errors.New("direct output must be the same controlling terminal as input"), err)
		}
	}
	controlRead, controlWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer controlRead.Close()
	defer controlWrite.Close()
	resultRead, resultWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer resultRead.Close()
	defer resultWrite.Close()
	var outputRead, outputWrite *os.File
	if directOutput == nil {
		outputRead, outputWrite, err = os.Pipe()
		if err != nil {
			return err
		}
		defer outputRead.Close()
		defer outputWrite.Close()
	}
	private := []*os.File{controlRead, resultWrite}
	childOutput := directOutput
	if outputWrite != nil {
		private = append(private, outputWrite)
		childOutput = outputWrite
	}
	for _, file := range private {
		if err := privateBlocking(file); err != nil {
			return err
		}
	}
	files := append([]*os.File{command.Stdin, childOutput, childOutput, controlRead, resultWrite}, command.ExtraFiles...)
	pidfd := -1
	pid, err := spawnPinned(executable, arguments, files, &syscall.ProcAttr{Env: os.Environ(), Sys: &syscall.SysProcAttr{Setpgid: true, PidFD: &pidfd}})
	if err != nil {
		return fmt.Errorf("start shell supervisor: %w", err)
	}
	if pidfd < 0 {
		controlWrite.Close()
		resultRead.Close()
		return errors.Join(errors.New("shell supervisor pidfd is unavailable"), waitSupervisor(pid))
	}
	defer unix.Close(pidfd)
	controlRead.Close()
	resultWrite.Close()
	if outputWrite != nil {
		outputWrite.Close()
	}
	var foregroundErr error
	if terminal != nil {
		foregroundErr = terminal.give(pid)
	}
	responseDone := make(chan supervisorResponse, 1)
	go func() { responseDone <- readSupervisorResponse(resultRead, pidfd) }()
	configured := make(chan error, 1)
	go func() {
		if foregroundErr != nil {
			controlWrite.Close()
			configured <- foregroundErr
			return
		}
		configuration := make([]byte, len(protocolMagic)+4+len(payload))
		copy(configuration, protocolMagic)
		binary.LittleEndian.PutUint32(configuration[len(protocolMagic):], uint32(len(payload)))
		copy(configuration[len(protocolMagic)+4:], payload)
		_, err := controlWrite.Write(configuration)
		configured <- err
	}()
	var outputDone chan error
	if outputRead != nil {
		outputDone = make(chan error, 1)
		go func() {
			copyOutput := func() error {
				_, err := io.CopyBuffer(command.Output, outputRead, make([]byte, 32*1024))
				return err
			}
			var err error
			if terminal != nil {
				err = withTerminalOutput(copyOutput)
			} else {
				err = copyOutput()
			}
			outputRead.Close()
			outputDone <- err
		}()
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- waitSupervisor(pid) }()
	var configurationErr, outputErr, waitErr, canceled error
	var response result
	var responseErr error
	contextDone := ctx.Done()
	for configured != nil || outputDone != nil || waitDone != nil || responseDone != nil {
		select {
		case configurationErr = <-configured:
			configured = nil
			if configurationErr != nil {
				controlWrite.Close()
			}
		case outputErr = <-outputDone:
			outputDone = nil
			if outputErr != nil {
				controlWrite.Close()
			}
		case outcome := <-responseDone:
			responseDone = nil
			response, responseErr = outcome.value, outcome.err
			if responseErr != nil {
				controlWrite.Close()
			}
		case waitErr = <-waitDone:
			waitDone = nil
			contextDone = nil
			controlWrite.Close()
			if waitErr != nil && outputRead != nil {
				outputRead.Close()
			}
		case <-contextDone:
			canceled = ctx.Err()
			contextDone = nil
			controlWrite.Close()
		}
	}
	if responseErr != nil {
		responseErr = fmt.Errorf("shell supervisor response: %w", responseErr)
	}
	if configurationErr != nil {
		configurationErr = fmt.Errorf("configure shell supervisor: %w", configurationErr)
	}
	if waitErr != nil {
		waitErr = fmt.Errorf("shell supervisor: %w", waitErr)
	}
	if outputErr != nil {
		outputErr = &OutputError{Err: outputErr}
	}
	var commandErr error
	if response.Error != "" {
		commandErr = errors.New(response.Error)
	} else if response.Canceled && canceled == nil && outputErr == nil && configurationErr == nil {
		commandErr = errors.New("shell interrupted")
	} else if canceled == nil && outputErr == nil && configurationErr == nil && (response.Code != 0 || response.Signal != 0) {
		commandErr = &ExitError{Code: response.Code, Signal: response.Signal}
	}
	return errors.Join(canceled, outputErr, configurationErr, waitErr, responseErr, commandErr)
}
