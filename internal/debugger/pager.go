package debugger

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"fastdbg2/internal/shellcmd"
	"fastdbg2/target"

	"golang.org/x/term"
)

const pagerCache = ".cache/fastdbg-amd64-command-port/pager"
const pagerPrompt = "-Ps[fastDbg2] lines %lt-%lb?L/%L. ?e(END) .q quit"

type commandPager struct {
	input  *os.File
	output *os.File
}

func (c *Controller) EnablePager(input io.Reader) {
	c.pager = nil
	in, inputOK := input.(*os.File)
	out, outputOK := c.out.(*os.File)
	terminal := os.Getenv("TERM")
	if !inputOK || !outputOK || terminal == "" || terminal == "dumb" || !pagerTerminal(in) || !pagerTerminal(out) {
		return
	}
	c.pager = &commandPager{input: in, output: out}
}

func pagerTerminal(file *os.File) bool {
	connection, err := file.SyscallConn()
	if err != nil {
		return false
	}
	terminal := false
	err = connection.Control(func(fd uintptr) { terminal = term.IsTerminal(int(fd)) })
	return err == nil && terminal
}

func (c *Controller) publishPaged(ctx context.Context, text string) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	if c.pager == nil {
		return c.writef("%s", text)
	}
	return c.pager.displayWith(ctx, text, shellcmd.RunCommand)
}

func (c *Controller) publishPagedAddressWalk(ctx context.Context, heading, body string, readErr error) error {
	if addressWalkFatal(readErr) || contextReady(ctx) != nil {
		return errors.Join(readErr, contextReady(ctx))
	}
	return errors.Join(readErr, c.publishPaged(ctx, body))
}

func pagerEnvironment(directory string) []string {
	var environment []string
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(name, "LESS") && name != "TMPDIR" && name != "TMP" && name != "TEMP" {
			environment = append(environment, entry)
		}
	}
	return append(environment, "LESSSECURE=1", "LESSHISTFILE=-", "TMPDIR="+directory, "TMP="+directory, "TEMP="+directory)
}

func pagerWrite(output io.Writer, text string) error {
	n, err := io.WriteString(output, text)
	if err == nil && n != len(text) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return &OutputError{Err: err}
	}
	return nil
}

func (pager *commandPager) displayWith(ctx context.Context, text string, run func(context.Context, shellcmd.Command) error) (err error) {
	if err := contextReady(ctx); err != nil {
		return err
	}
	if pager == nil || pager.input == nil || pager.output == nil || run == nil {
		return fmt.Errorf("pager requires input, output and command runner: %w", target.ErrInvalidArgument)
	}
	if text == "" {
		return nil
	}
	executable, err := exec.LookPath("less")
	if err != nil {
		if err := pagerWrite(pager.output, fmt.Sprintf("pager unavailable: %q; displaying output directly\n", err.Error())); err != nil {
			return err
		}
		if err := contextReady(ctx); err != nil {
			return err
		}
		return pagerWrite(pager.output, text)
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(cwd)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	if err := root.MkdirAll(pagerCache, 0700); err != nil {
		return err
	}
	name := filepath.Join(pagerCache, "view-"+rand.Text()+".txt")
	file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close(), root.Remove(name)) }()
	if n, err := io.WriteString(file, text); err != nil {
		return err
	} else if n != len(text) {
		return io.ErrShortWrite
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	directory := filepath.Join(cwd, pagerCache)
	err = run(ctx, shellcmd.Command{
		Path: executable, Args: []string{"-SR", pagerPrompt, "--", filepath.Join(cwd, name)},
		Dir: directory, Env: pagerEnvironment(directory), Stdin: pager.input, Output: pager.output,
		Foreground: true, TerminalOutput: true, Pager: true,
	})
	if canceled := contextReady(ctx); canceled != nil && !errors.Is(err, canceled) {
		err = errors.Join(err, canceled)
	}
	var outputErr *shellcmd.OutputError
	if errors.As(err, &outputErr) {
		return &OutputError{Err: err}
	}
	return err
}
