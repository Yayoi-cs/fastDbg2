package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/ergochat/readline"
	"github.com/muesli/cancelreader"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

var ErrInterrupt = errors.New("input interrupted")

type Config struct {
	Input    io.Reader
	Output   io.Writer
	Prompt   string
	Commands []string
	Term     string
	NoColor  bool
}

type Reader struct {
	stream      *bufio.Reader
	editor      *readline.Instance
	input       *observedReader
	cancel      cancelreader.CancelReader
	raw         *rawMode
	plainOutput *sgrWriter
	failures    firstError
	refresh     func()
	readMu      sync.Mutex
	closeOnce   sync.Once
	cancelOnce  sync.Once
	closed      atomic.Bool
	cancelErr   error
	closeErr    error
}

func IsTerminal(input io.Reader, output io.Writer, terminal string) bool {
	in, inOK := input.(*os.File)
	out, outOK := output.(*os.File)
	if terminal == "dumb" || !inOK || !outOK {
		return false
	}
	inputFD, err := fileDescriptor(in)
	if err != nil {
		return false
	}
	outputFD, err := fileDescriptor(out)
	return err == nil && term.IsTerminal(inputFD) && term.IsTerminal(outputFD)
}

func NewReader(config Config) (*Reader, error) {
	if config.Input == nil || config.Output == nil {
		return nil, errors.New("input and output are required")
	}
	completer, err := NewCompleter(config.Commands)
	if err != nil {
		return nil, err
	}
	if !IsTerminal(config.Input, config.Output, config.Term) {
		return newStreamReader(config.Input)
	}
	input := config.Input.(*os.File)
	output := config.Output.(*os.File)
	inputFD, err := fileDescriptor(input)
	if err != nil {
		return nil, fmt.Errorf("inspect terminal input: %w", err)
	}
	outputFD, err := fileDescriptor(output)
	if err != nil {
		return nil, fmt.Errorf("inspect terminal output: %w", err)
	}
	source, err := newFileCancelReader(input)
	if err != nil {
		return nil, fmt.Errorf("initialize terminal input: %w", err)
	}
	raw := &rawMode{enter: func() (func() error, error) {
		settings, err := unix.IoctlGetTermios(inputFD, unix.TCGETS)
		if err != nil {
			return nil, err
		}
		before := *settings
		settings.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
		settings.Oflag = unix.OPOST | unix.ONLCR
		settings.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
		settings.Cflag &^= unix.CSIZE | unix.PARENB
		settings.Cflag |= unix.CS8
		settings.Cc[unix.VMIN], settings.Cc[unix.VTIME] = 1, 0
		if err := unix.IoctlSetTermios(inputFD, unix.TCSETS, settings); err != nil {
			return nil, err
		}
		return func() error { return unix.IoctlSetTermios(inputFD, unix.TCSETS, &before) }, nil
	}}
	return newTerminalReader(config, completer, source, raw, func() (int, int) {
		width, height, err := term.GetSize(outputFD)
		if err != nil || width <= 0 || height <= 0 {
			return -1, -1
		}
		return width, height
	})
}

func newStreamReader(input io.Reader) (*Reader, error) {
	r := &Reader{stream: bufio.NewReader(input)}
	file, ok := input.(*os.File)
	if !ok {
		return r, nil
	}
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect input: %w", err)
	}
	fd, err := fileDescriptor(file)
	if err != nil {
		return nil, fmt.Errorf("inspect input descriptor: %w", err)
	}
	if !term.IsTerminal(fd) && info.Mode()&(os.ModeNamedPipe|os.ModeSocket) == 0 {
		return r, nil
	}
	source, err := newFileCancelReader(file)
	if err != nil {
		return nil, fmt.Errorf("initialize stream input: %w", err)
	}
	r.cancel = source
	r.stream = bufio.NewReader(source)
	return r, nil
}

func newTerminalReader(config Config, completer *Completer, source cancelreader.CancelReader, raw *rawMode, size func() (int, int)) (*Reader, error) {
	r := &Reader{cancel: source, raw: raw, refresh: func() {}}
	raw.onError = func(err error) {
		r.failures.Record(err)
		r.cancelInput()
	}
	r.input = &observedReader{source: source, failures: &r.failures, cancel: r.cancelInput}
	var output io.Writer = &observedWriter{target: config.Output, failures: &r.failures, cancel: r.cancelInput}
	if config.NoColor {
		r.plainOutput = &sgrWriter{target: output}
		output = r.plainOutput
	}
	editor, err := readline.NewFromConfig(&readline.Config{
		Prompt:             config.Prompt,
		HistoryFile:        "",
		AutoComplete:       completer,
		Stdin:              r.input,
		Stdout:             output,
		Stderr:             output,
		EOFPrompt:          "\n",
		FuncIsTerminal:     func() bool { return true },
		FuncMakeRaw:        raw.Enter,
		FuncExitRaw:        raw.Exit,
		FuncGetSize:        size,
		FuncOnWidthChanged: func(refresh func()) { r.refresh = refresh },
	})
	if err != nil {
		return nil, errors.Join(err, source.Close())
	}
	r.editor = editor
	return r, nil
}

func (r *Reader) Interactive() bool {
	return r.editor != nil
}

func (r *Reader) SetPrompt(prompt string) {
	r.readMu.Lock()
	defer r.readMu.Unlock()
	if r.editor != nil && !r.closed.Load() {
		r.editor.SetPrompt(prompt)
	}
}

func (r *Reader) ReadLine() (line string, err error) {
	r.readMu.Lock()
	defer r.readMu.Unlock()
	if r.closed.Load() {
		return "", io.EOF
	}
	if r.stream != nil {
		line, err = r.stream.ReadString('\n')
		if r.closed.Load() && (err == nil || err == cancelreader.ErrCanceled) {
			return "", io.EOF
		}
		if err == io.EOF && line != "" {
			err = nil
		}
		if strings.HasSuffix(line, "\n") {
			line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		}
		return line, err
	}
	if err = r.failures.Err(); err != nil {
		return "", err
	}
	if err = r.raw.Enter(); err != nil {
		return "", fmt.Errorf("enter terminal raw mode: %w", err)
	}
	defer func() {
		if restoreErr := errors.Join(r.raw.Exit(), r.raw.Err()); restoreErr != nil {
			err = errors.Join(err, restoreErr)
		}
	}()
	r.refresh()
	line, err = r.editor.ReadLine()
	if failure := r.failures.Err(); failure != nil {
		return "", failure
	}
	if r.closed.Load() {
		return "", io.EOF
	}
	if errors.Is(err, readline.ErrInterrupt) {
		return "", ErrInterrupt
	}
	return line, err
}

func (r *Reader) cancelInput() {
	r.cancelOnce.Do(func() {
		if !r.cancel.Cancel() {
			r.cancelErr = errors.New("terminal input cancellation failed")
			r.failures.Record(r.cancelErr)
		}
	})
}

func (r *Reader) Close() error {
	r.closeOnce.Do(func() {
		r.closed.Store(true)
		if r.stream != nil {
			if r.cancel != nil {
				r.cancelInput()
				r.readMu.Lock()
				defer r.readMu.Unlock()
				r.closeErr = errors.Join(r.cancelErr, r.cancel.Close())
			}
			return
		}
		r.cancelInput()
		r.readMu.Lock()
		defer r.readMu.Unlock()
		editorErr := r.editor.Close()
		r.input.Stop()
		var outputErr error
		if r.plainOutput != nil {
			outputErr = r.plainOutput.Close()
		}
		r.closeErr = errors.Join(r.cancelErr, editorErr, outputErr, r.raw.Exit(), r.raw.Err(), r.cancel.Close())
	})
	return r.closeErr
}

type firstError struct {
	mu  sync.Mutex
	err error
}

func (e *firstError) Record(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.err == nil {
		e.err = err
	}
}

func (e *firstError) Err() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.err
}

type observedReader struct {
	mu       sync.Mutex
	source   io.Reader
	failures *firstError
	cancel   func()
	stopped  bool
}

func (r *observedReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return 0, cancelreader.ErrCanceled
	}
	if len(p) > 1 {
		p = p[:1]
	}
	n, err := r.source.Read(p)
	if err != nil && err != io.EOF && err != cancelreader.ErrCanceled {
		r.failures.Record(err)
		r.cancel()
	}
	return n, err
}

func (r *observedReader) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopped = true
}

type observedWriter struct {
	target   io.Writer
	failures *firstError
	cancel   func()
}

func (w *observedWriter) Write(p []byte) (int, error) {
	n, err := w.target.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		w.failures.Record(err)
		w.cancel()
	}
	return n, err
}

type rawMode struct {
	mu      sync.Mutex
	enter   func() (func() error, error)
	restore func() error
	onError func(error)
	err     error
}

func (r *rawMode) Enter() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.restore != nil {
		return nil
	}
	restore, err := r.enter()
	if err == nil {
		r.restore = restore
	} else {
		if r.err == nil {
			r.err = err
		}
		if r.onError != nil {
			r.onError(err)
		}
	}
	return err
}

func (r *rawMode) Exit() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.restore == nil {
		return nil
	}
	err := r.restore()
	if err == nil {
		r.restore = nil
	} else if r.err == nil {
		r.err = err
	}
	return err
}

func (r *rawMode) Err() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}
