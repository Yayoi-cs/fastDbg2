package debugger

import (
	"bytes"
	"context"
	"crypto/rand"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"fastdbg2/internal/cli"
	"fastdbg2/internal/shellcmd"
	"fastdbg2/target"
)

const (
	cyclicSequenceLength = 26 * 26 * 26 * 26
	maxAssemblySource    = 64 << 10
	maxAssemblyBytes     = 1 << 20
	assemblyCache        = ".cache/fastdbg-amd64-command-port/asm"
)

func (c *Controller) showCyclic(ctx context.Context, rawArgs string) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	if len(rawArgs) > 2*cyclicSequenceLength+128 {
		return fmt.Errorf("cyclic arguments exceed the maximum pattern length: %w", target.ErrInvalidArgument)
	}
	args, err := cli.ParseArgs(rawArgs)
	if err != nil {
		return fmt.Errorf("cyclic arguments: %w: %w", target.ErrInvalidArgument, err)
	}
	if len(args) == 0 {
		return fmt.Errorf("usage: cyclic LENGTH | -d|-D [--size N] [--endian little|big] VALUE: %w", target.ErrInvalidArgument)
	}
	if args[0] != "-d" && args[0] != "-D" {
		if len(args) != 1 {
			return fmt.Errorf("cyclic generation takes one length: %w", target.ErrInvalidArgument)
		}
		length, err := utilityUint(args[0], "cyclic length")
		if err != nil {
			return err
		}
		if length > cyclicSequenceLength {
			return fmt.Errorf("cyclic length must not exceed %d: %w", cyclicSequenceLength, target.ErrInvalidArgument)
		}
		sequence, err := cyclicGenerate(ctx, int(length))
		if err != nil {
			return err
		}
		return c.writef("%s\n", sequence)
	}
	pattern, err := cyclicPattern(args[1:])
	if err != nil {
		return err
	}
	sequence, err := cyclicGenerate(ctx, cyclicSequenceLength)
	if err != nil {
		return err
	}
	offset := bytes.Index(sequence, pattern)
	if err := contextReady(ctx); err != nil {
		return err
	}
	if offset < 0 {
		return fmt.Errorf("pattern %q not found in cyclic(26^4): %w", pattern, target.ErrNotFound)
	}
	qualification := "first exact match"
	if len(pattern) < 4 {
		qualification += "; short patterns may be nonunique"
	}
	return c.writef("offset: %d (0x%x)  pattern: %q [%s]\n", offset, offset, pattern, qualification)
}

func utilityUint(text, label string) (uint64, error) {
	if text == "" || text[0] == '+' || text[0] == '-' {
		return 0, fmt.Errorf("%s must be an unsigned integer: %w", label, target.ErrInvalidArgument)
	}
	value, err := strconv.ParseUint(text, 0, 64)
	if errors.Is(err, strconv.ErrRange) {
		return 0, fmt.Errorf("%s %q: %w", label, text, target.ErrOverflow)
	}
	if err != nil {
		return 0, fmt.Errorf("%s %q: %w", label, text, target.ErrInvalidArgument)
	}
	return value, nil
}

func cyclicPattern(args []string) ([]byte, error) {
	var size int
	endian := "little"
	var hasSize, hasEndian bool
	for len(args) > 1 {
		if len(args) < 3 {
			return nil, fmt.Errorf("cyclic search options require a value and pattern: %w", target.ErrInvalidArgument)
		}
		switch args[0] {
		case "--size":
			if hasSize {
				return nil, fmt.Errorf("duplicate cyclic --size: %w", target.ErrInvalidArgument)
			}
			n, err := utilityUint(args[1], "cyclic size")
			if err != nil {
				return nil, err
			}
			if n < 1 || n > 8 {
				return nil, fmt.Errorf("cyclic size must be between 1 and 8 bytes: %w", target.ErrInvalidArgument)
			}
			size, hasSize = int(n), true
		case "--endian":
			if hasEndian || (args[1] != "little" && args[1] != "big") {
				return nil, fmt.Errorf("cyclic --endian must be supplied once as little or big: %w", target.ErrInvalidArgument)
			}
			endian, hasEndian = args[1], true
		default:
			return nil, fmt.Errorf("unknown cyclic search option %q: %w", args[0], target.ErrInvalidArgument)
		}
		args = args[2:]
	}
	if len(args) != 1 || args[0] == "" {
		return nil, fmt.Errorf("cyclic search needs one nonempty pattern: %w", target.ErrInvalidArgument)
	}
	value := args[0]
	if strings.HasPrefix(value, "--") {
		return nil, fmt.Errorf("incomplete cyclic search option %q: %w", value, target.ErrInvalidArgument)
	}
	if !strings.HasPrefix(value, "0x") && !strings.HasPrefix(value, "0X") {
		if hasSize || hasEndian {
			return nil, fmt.Errorf("cyclic --size and --endian require a hexadecimal integer pattern: %w", target.ErrInvalidArgument)
		}
		if len(value) > cyclicSequenceLength {
			return nil, fmt.Errorf("cyclic pattern exceeds %d bytes: %w", cyclicSequenceLength, target.ErrInvalidArgument)
		}
		return []byte(value), nil
	}
	number, err := utilityUint(value, "cyclic hexadecimal pattern")
	if err != nil {
		return nil, err
	}
	minimum := max(1, (bits.Len64(number)+7)/8)
	if !hasSize {
		size = minimum
	}
	if minimum > size {
		return nil, fmt.Errorf("cyclic pattern does not fit in %d bytes: %w", size, target.ErrOverflow)
	}
	var encoded [8]byte
	if endian == "big" {
		binary.BigEndian.PutUint64(encoded[:], number)
		return bytes.Clone(encoded[8-size:]), nil
	}
	binary.LittleEndian.PutUint64(encoded[:], number)
	return bytes.Clone(encoded[:size]), nil
}

func cyclicGenerate(ctx context.Context, length int) ([]byte, error) {
	if err := contextReady(ctx); err != nil {
		return nil, err
	}
	if length < 0 || length > cyclicSequenceLength {
		return nil, fmt.Errorf("cyclic length must be between 0 and %d: %w", cyclicSequenceLength, target.ErrInvalidArgument)
	}
	sequence := make([]byte, 0, length)
	var word [5]byte
	var generate func(int, int) error
	generate = func(position, period int) error {
		if len(sequence) >= length {
			return nil
		}
		if len(sequence)%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if position == len(word) {
			if 4%period == 0 {
				for i := 1; i <= period && len(sequence) < length; i++ {
					sequence = append(sequence, 'a'+word[i])
				}
			}
			return nil
		}
		word[position] = word[position-period]
		if err := generate(position+1, period); err != nil {
			return err
		}
		for next := word[position-period] + 1; next < 26; next++ {
			word[position] = next
			if err := generate(position+1, position); err != nil {
				return err
			}
		}
		return nil
	}
	if err := generate(1, 1); err != nil {
		return nil, err
	}
	if err := contextReady(ctx); err != nil {
		return nil, err
	}
	return sequence, nil
}

func (c *Controller) showAssembly(ctx context.Context, rawArgs string) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	if len(rawArgs) > 2*maxAssemblySource+2 {
		return fmt.Errorf("assembly input exceeds %d bytes: %w", maxAssemblySource, target.ErrInvalidArgument)
	}
	args, err := cli.ParseArgs(rawArgs)
	if err != nil {
		return fmt.Errorf("assembly arguments: %w: %w", target.ErrInvalidArgument, err)
	}
	if len(args) != 1 {
		return fmt.Errorf("usage: asm \"INTEL_ASSEMBLY\" | INSTRUCTION: %w", target.ErrInvalidArgument)
	}
	arch, err := c.assemblyArchitecture()
	if err != nil {
		return err
	}
	data, err := assembleNative(ctx, args[0], arch)
	if err != nil {
		return err
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	if err := c.writef("%d bytes: %x\n", len(data), data); err != nil {
		return err
	}
	view := *c
	view.arch = arch
	for offset := 0; offset < len(data); offset += 16 {
		if err := contextReady(ctx); err != nil {
			return err
		}
		if err := view.hexRows(target.Address(offset), data[offset:min(offset+16, len(data))], 1); err != nil {
			return err
		}
	}
	return nil
}

func validateAssemblySource(source string) error {
	if len(source) == 0 || len(source) > maxAssemblySource {
		return fmt.Errorf("assembly source must contain 1 through %d bytes: %w", maxAssemblySource, target.ErrInvalidArgument)
	}
	for _, value := range []byte(source) {
		if value >= 0x7f || (value < 0x20 && value != '\n' && value != '\t') {
			return fmt.Errorf("assembly source must contain ASCII instructions: %w", target.ErrInvalidArgument)
		}
	}
	if strings.ContainsAny(source, "#\\\"'=") || strings.Contains(source, "/*") || strings.Contains(source, "*/") || strings.Contains(source, "//") {
		return fmt.Errorf("assembly comments, strings, escapes and assignments are unsupported: %w", target.ErrUnsupported)
	}
	instructions := 0
	for _, statement := range strings.FieldsFunc(source, func(value rune) bool { return value == ';' || value == '\n' }) {
		statement = strings.TrimSpace(statement)
		for {
			colon := strings.IndexByte(statement, ':')
			if colon < 0 || !assemblyLabel(strings.TrimSpace(statement[:colon])) {
				break
			}
			statement = strings.TrimSpace(statement[colon+1:])
		}
		if statement == "" {
			continue
		}
		if statement[0] == '.' {
			return fmt.Errorf("assembly directives are unsupported: %w", target.ErrUnsupported)
		}
		if !(statement[0] >= 'A' && statement[0] <= 'Z' || statement[0] >= 'a' && statement[0] <= 'z') {
			return fmt.Errorf("assembly statement must begin with an instruction: %w", target.ErrInvalidArgument)
		}
		instructions++
	}
	if instructions == 0 {
		return fmt.Errorf("assembly source contains no instructions: %w", target.ErrInvalidArgument)
	}
	return nil
}

func assemblyLabel(label string) bool {
	if label == "" {
		return false
	}
	numeric := label[0] >= '0' && label[0] <= '9'
	for i, value := range []byte(label) {
		if value >= '0' && value <= '9' {
			continue
		}
		if numeric || !(value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || value == '_' || value == '.' || value == '$' && i > 0) {
			return false
		}
	}
	return true
}

type assemblyDiagnostics struct {
	data      []byte
	truncated bool
}

func (output *assemblyDiagnostics) Write(data []byte) (int, error) {
	available := max(0, (16<<10)-len(output.data))
	output.data = append(output.data, data[:min(available, len(data))]...)
	output.truncated = output.truncated || len(data) > available
	return len(data), nil
}

func assembleAMD64(ctx context.Context, source string) ([]byte, error) {
	return assembleNative(ctx, source, target.AMD64)
}

func assembleNative(ctx context.Context, source string, arch target.Architecture) (data []byte, err error) {
	if err := contextReady(ctx); err != nil {
		return nil, err
	}
	if err := validateAssemblySource(source); err != nil {
		return nil, err
	}
	assembler, err := exec.LookPath("as")
	if err != nil {
		return nil, fmt.Errorf("GNU as is required for x86/amd64 assembly: %w: %w", target.ErrUnavailable, err)
	}
	assembler, err = filepath.Abs(assembler)
	if err != nil {
		return nil, err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(cwd)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	if err := root.MkdirAll(assemblyCache, 0700); err != nil {
		return nil, err
	}
	name := filepath.Join(assemblyCache, "snippet-"+rand.Text()+".o")
	object, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, object.Close(), root.Remove(name)) }()
	sourceName := filepath.Join(assemblyCache, "snippet-"+rand.Text()+".s")
	input, err := root.OpenFile(sourceName, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, input.Close(), root.Remove(sourceName)) }()
	program := ".intel_syntax noprefix\n.text\n" + source + "\n"
	if n, err := io.WriteString(input, program); err != nil {
		return nil, err
	} else if n != len(program) {
		return nil, io.ErrShortWrite
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	directory := filepath.Join(cwd, assemblyCache)
	var environment []string
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "TMPDIR=") && !strings.HasPrefix(entry, "TMP=") && !strings.HasPrefix(entry, "TEMP=") {
			environment = append(environment, entry)
		}
	}
	environment = append(environment, "TMPDIR="+directory, "TMP="+directory, "TEMP="+directory)
	diagnostic := &assemblyDiagnostics{}
	command := shellcmd.Command{
		Path:       assembler,
		Args:       []string{fmt.Sprintf("--%d", abiFor(arch).bits), "--fatal-warnings", "-o", "/proc/self/fd/3", "-"},
		Dir:        directory,
		Env:        environment,
		Stdin:      input,
		Output:     diagnostic,
		ExtraFiles: []*os.File{object},
	}
	if runErr := shellcmd.RunCommand(ctx, command); runErr != nil {
		if ctx.Err() != nil {
			return nil, errors.Join(ctx.Err(), runErr)
		}
		kind := target.ErrUnavailable
		var exitErr *shellcmd.ExitError
		if errors.As(runErr, &exitErr) {
			kind = target.ErrInvalidArgument
		}
		return nil, fmt.Errorf("GNU as failed (diagnostics truncated=%t): %q: %w: %w", diagnostic.truncated, diagnostic.data, kind, runErr)
	}
	if err := contextReady(ctx); err != nil {
		return nil, err
	}
	data, err = readAssemblyObjectFor(object, arch)
	if cancelErr := contextReady(ctx); cancelErr != nil {
		return nil, errors.Join(err, cancelErr)
	}
	return data, err
}

func readAssemblyObject(reader io.ReaderAt) ([]byte, error) {
	return readAssemblyObjectFor(reader, target.AMD64)
}

func readAssemblyObjectFor(reader io.ReaderAt, arch target.Architecture) ([]byte, error) {
	file, err := elf.NewFile(reader)
	if err != nil {
		return nil, fmt.Errorf("assembler object: %w", err)
	}
	actual, archErr := nativeELFArchitecture(file)
	if archErr != nil || actual != arch || file.Type != elf.ET_REL {
		return nil, fmt.Errorf("assembler must emit an ELF64 little-endian AMD64 relocatable object: %w", target.ErrUnsupported)
	}
	var text *elf.Section
	var textIndex int
	for index, section := range file.Sections {
		if section.Name == ".text" {
			if text != nil {
				return nil, fmt.Errorf("assembler object contains multiple .text sections: %w", target.ErrAmbiguous)
			}
			text, textIndex = section, index
		}
	}
	if text == nil || text.Size == 0 {
		return nil, fmt.Errorf("assembler object contains no .text bytes: %w", target.ErrInvalidArgument)
	}
	if text.Size > maxAssemblyBytes {
		return nil, fmt.Errorf("assembly output exceeds %d bytes: %w", maxAssemblyBytes, target.ErrInvalidArgument)
	}
	if text.Type != elf.SHT_PROGBITS || text.Flags&elf.SHF_EXECINSTR == 0 || text.Flags&elf.SHF_COMPRESSED != 0 {
		return nil, fmt.Errorf("assembler .text must be uncompressed executable PROGBITS: %w", target.ErrUnsupported)
	}
	for _, section := range file.Sections {
		if (section.Type == elf.SHT_REL || section.Type == elf.SHT_RELA) && section.Size != 0 && section.Info == uint32(textIndex) {
			return nil, fmt.Errorf("assembly .text contains relocations; use resolved local branches or literal encodings: %w", target.ErrUnsupported)
		}
	}
	data, err := text.Data()
	if err != nil {
		return nil, fmt.Errorf("read assembled .text: %w", err)
	}
	if uint64(len(data)) != text.Size {
		return nil, fmt.Errorf("assembled .text is incomplete: %w", io.ErrUnexpectedEOF)
	}
	return data, nil
}
