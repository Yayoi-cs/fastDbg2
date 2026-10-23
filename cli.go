package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	"fastdbg2/display"
	"fastdbg2/internal/cli"
	"fastdbg2/internal/debugger"
)

func runCLI(args []string, output io.Writer) error {
	if err := runCLIInput(args, os.Stdin, output); err != nil {
		return &cliError{err: err}
	}
	return nil
}

type cliError struct {
	err error
}

func (e *cliError) Error() string {
	quoted := strconv.Quote(e.err.Error())
	return quoted[1 : len(quoted)-1]
}

func (e *cliError) Unwrap() error {
	return e.err
}

func runCLIInput(args []string, input io.Reader, output io.Writer) error {
	if len(args) == 0 || len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		return writeHelp(output)
	}
	options, err := parseCLIOptions(args)
	if err != nil {
		return err
	}
	return runInteractiveOptions(options, input, output)
}

type cliOptions struct {
	file string
	args []string
	pid  int
}

func parseCLIOptions(args []string) (cliOptions, error) {
	var options cliOptions
	var interactive, selected bool
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--interactive":
			if interactive {
				return cliOptions{}, errors.New("--interactive may only be specified once")
			}
			interactive = true
		case "-f":
			if selected {
				return cliOptions{}, errors.New("specify at most one -f FILE or -p PID")
			}
			index++
			if index == len(args) || args[index] == "" {
				return cliOptions{}, errors.New("-f requires a nonempty FILE")
			}
			options.file, selected = args[index], true
		case "-p":
			if selected {
				return cliOptions{}, errors.New("specify at most one -f FILE or -p PID")
			}
			index++
			if index == len(args) {
				return cliOptions{}, errors.New("-p requires a positive decimal PID")
			}
			value := args[index]
			pid, err := strconv.ParseUint(value, 10, strconv.IntSize)
			if err != nil || pid == 0 || pid > uint64(^uint(0)>>1) || strings.IndexFunc(value, func(r rune) bool {
				return r < '0' || r > '9'
			}) >= 0 {
				return cliOptions{}, fmt.Errorf("invalid PID: %q", value)
			}
			options.pid, selected = int(pid), true
		case "--":
			if options.file == "" {
				return cliOptions{}, errors.New("-- ARGS requires -f FILE")
			}
			options.args = slices.Clone(args[index+1:])
			return options, nil
		default:
			return cliOptions{}, fmt.Errorf("unsupported option or argument: %q", args[index])
		}
	}
	if !interactive && !selected {
		return cliOptions{}, errors.New("specify --interactive, -f FILE, or -p PID")
	}
	return options, nil
}

func runInteractive(input io.Reader, output io.Writer) (err error) {
	return runInteractiveOptions(cliOptions{}, input, output)
}

func runInteractiveOptions(options cliOptions, input io.Reader, output io.Writer) (err error) {
	terminal := os.Getenv("TERM")
	renderer, err := display.NewRenderer(display.Options{
		Mode:       display.ColorAuto,
		IsTerminal: cli.IsTerminal(input, output, terminal),
		Term:       terminal,
		NoColor:    os.Getenv("NO_COLOR"),
	})
	if err != nil {
		return err
	}
	reader, err := cli.NewReader(cli.Config{
		Input:    input,
		Output:   output,
		Prompt:   "[fastDbg2]$ ",
		Commands: debugger.CommandNames(),
		Term:     terminal,
		NoColor:  os.Getenv("NO_COLOR") != "",
	})
	if err != nil {
		return err
	}
	controller := debugger.New(output, renderer)
	controller.EnablePager(input)
	controller.EnableContextScreen(reader.Interactive())
	signals := newConsoleSignals(context.Background())
	stopClose := context.AfterFunc(signals.ctx, func() { reader.Close() })
	defer func() {
		stopClose()
		err = errors.Join(err, controller.Close(), reader.Close())
		signals.Close()
	}()
	if options.file != "" {
		if err := controller.Configure(options.file, options.args); err != nil {
			return err
		}
	}
	if options.pid != 0 {
		ctx, end := signals.beginCommand()
		_, err := controller.Execute(ctx, "attach", strconv.Itoa(options.pid))
		end()
		if err != nil {
			return err
		}
	}
	return runConsoleController(signals.ctx, reader, output, renderer, controller, signals)
}

type lineReader interface {
	ReadLine() (string, error)
}

type consoleController interface {
	Execute(context.Context, string, string) (bool, error)
	Close() error
}

func runConsole(ctx context.Context, input lineReader, output io.Writer, renderer display.Renderer) (err error) {
	controller := debugger.New(output, renderer)
	defer func() { err = errors.Join(err, controller.Close()) }()
	return runConsoleController(ctx, input, output, renderer, controller, nil)
}

func runConsoleController(ctx context.Context, input lineReader, output io.Writer, renderer display.Renderer, controller consoleController, signals *consoleSignals) error {
	interactive := false
	if mode, ok := input.(interface{ Interactive() bool }); ok {
		interactive = mode.Interactive()
	}
	previous := ""
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		updateConsolePrompt(input, controller)
		line, err := input.ReadLine()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return errors.Join(ctxErr, nonEOF(err))
		}
		if err == cli.ErrInterrupt {
			continue
		}
		if err != nil {
			return nonEOF(err)
		}
		if interactive {
			if line == "" {
				line = previous
			} else {
				previous = line
			}
		}
		name, arguments := cli.SplitCommand(line)
		if name == "" {
			if !interactive || line == "" {
				continue
			}
			name = line
		}
		commandCtx, end := ctx, func() {}
		if signals != nil {
			commandCtx, end = signals.beginCommand()
		}
		quit, err := controller.Execute(commandCtx, name, arguments)
		end()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return errors.Join(ctxErr, err)
		}
		if err != nil {
			var outputErr *debugger.OutputError
			if errors.As(err, &outputErr) {
				return err
			}
			message := fmt.Sprintf("error: %q", err.Error())
			if err := writeCLIText(output, renderer.Text(display.StyleError, message)+"\n"); err != nil {
				return err
			}
			continue
		}
		if quit {
			return nil
		}
	}
}

func updateConsolePrompt(input lineReader, controller consoleController) {
	setter, ok := input.(interface{ SetPrompt(string) })
	if !ok {
		return
	}
	if mode, ok := input.(interface{ Interactive() bool }); ok && !mode.Interactive() {
		return
	}
	prompt := "[fastDbg2]$ "
	if provider, ok := controller.(interface{ Prompt() string }); ok {
		prompt = provider.Prompt()
	}
	setter.SetPrompt(prompt)
}

func nonEOF(err error) error {
	if err == io.EOF {
		return nil
	}
	return err
}
