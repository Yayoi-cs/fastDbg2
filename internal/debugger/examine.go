package debugger

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"fastdbg2/display"
	"fastdbg2/target"
)

type examineFormat struct {
	count  int
	format byte
	size   int
}

func parseExamineFormat(spec string) (examineFormat, error) {
	result := examineFormat{count: 1, format: 'x', size: 4}
	index := 0
	for index < len(spec) && spec[index] >= '0' && spec[index] <= '9' {
		index++
	}
	if index != 0 {
		value, err := strconv.ParseUint(spec[:index], 10, 32)
		if err != nil || value == 0 || value > maxMemoryBytes {
			return examineFormat{}, fmt.Errorf("examine count must be between 1 and %d: %w", maxMemoryBytes, target.ErrInvalidArgument)
		}
		result.count = int(value)
	}
	var hasFormat, hasSize bool
	for ; index < len(spec); index++ {
		char := spec[index]
		switch {
		case strings.ContainsRune("xduotcis", rune(char)):
			if hasFormat {
				return examineFormat{}, fmt.Errorf("duplicate examine format: %w", target.ErrInvalidArgument)
			}
			result.format, hasFormat = char, true
		case strings.ContainsRune("bhwg", rune(char)):
			if hasSize {
				return examineFormat{}, fmt.Errorf("duplicate examine unit: %w", target.ErrInvalidArgument)
			}
			hasSize = true
			result.size = map[byte]int{'b': 1, 'h': 2, 'w': 4, 'g': 8}[char]
		default:
			return examineFormat{}, fmt.Errorf("invalid examine format %q: %w", spec, target.ErrInvalidArgument)
		}
	}
	switch result.format {
	case 'i':
		if result.count > maxDisplayInstructions {
			return examineFormat{}, fmt.Errorf("instruction count must be between 1 and %d: %w", maxDisplayInstructions, target.ErrInvalidArgument)
		}
	case 's', 'c':
		if hasSize && result.size != 1 {
			return examineFormat{}, fmt.Errorf("examine %c supports only byte units: %w", result.format, target.ErrUnsupported)
		}
		result.size = 1
	default:
		if result.count > maxMemoryBytes/result.size {
			return examineFormat{}, fmt.Errorf("examine range exceeds %d bytes: %w", maxMemoryBytes, target.ErrInvalidArgument)
		}
	}
	return result, nil
}

func (c *Controller) showExamine(ctx context.Context, spec, rawArgs string) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	format, err := parseExamineFormat(spec)
	if err != nil {
		return err
	}
	if strings.TrimSpace(rawArgs) == "" {
		return fmt.Errorf("usage: x[/COUNT,FORMAT,UNIT] EXPR; an explicit address is required: %w", target.ErrInvalidArgument)
	}
	snapshot, thread, err := c.stopped()
	if err != nil {
		return err
	}
	address, err := c.evaluate(ctx, rawArgs, snapshot, thread)
	if err != nil {
		return err
	}
	switch format.format {
	case 'i':
		if err := contextReady(ctx); err != nil {
			return err
		}
		location, err := c.session.ReadCodeLocation(thread.Token)
		if err != nil {
			return err
		}
		if location.Breakpoint != nil && *location.Breakpoint != location.InstructionPC {
			return fmt.Errorf("code location disagrees with breakpoint: %w", target.ErrStale)
		}
		return c.showInstructionRange(ctx, snapshot.Memory, address, format.count, &location, false)
	case 's':
		return c.showExamineStrings(ctx, snapshot.Memory, address, format.count)
	}
	if err := inspectionRange(address, format.count*format.size); err != nil {
		return err
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	data := make([]byte, format.count*format.size)
	n, readErr := c.session.ReadSpaceMemory(snapshot.Memory, address, data)
	data, readErr = inspectionConfirmedBytes(data, n, readErr)
	if err := contextReady(ctx); err != nil {
		return err
	}
	if err := c.examineRows(address, data, format); err != nil {
		return err
	}
	return readErr
}

func (c *Controller) examineRows(address target.Address, data []byte, format examineFormat) error {
	width := 16
	if format.format == 'c' || format.format == 't' {
		width = format.size * 4
	}
	for offset := 0; offset < len(data); offset += width {
		row := data[offset:min(offset+width, len(data))]
		addressText, err := c.renderer.Address(target.AMD64, address+target.Address(offset), display.AddressUnknown)
		if err != nil {
			return err
		}
		var values []string
		for i := 0; i < len(row); i += format.size {
			part := row[i:min(i+format.size, len(row))]
			if len(part) != format.size {
				values = append(values, "<partial bytes: "+display.FormatBytes(part)+">")
				continue
			}
			values = append(values, inspectionNumber(inspectionWord(part), format.size, format.format))
		}
		if err := c.writef("%s:\t%s\n", addressText, strings.Join(values, "\t")); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) showExamineStrings(ctx context.Context, token target.MemoryToken, address target.Address, count int) error {
	start := address
	var current []byte
	completed := 0
	for offset := 0; offset < maxMemoryBytes; offset++ {
		if err := contextReady(ctx); err != nil {
			return err
		}
		if uint64(offset) > math.MaxUint64-uint64(address) {
			return errors.Join(c.examineString(start, current, false), target.ErrOverflow)
		}
		var data [1]byte
		n, readErr := c.session.ReadSpaceMemory(token, address+target.Address(offset), data[:])
		prefix, readErr := inspectionConfirmedBytes(data[:], n, readErr)
		if err := contextReady(ctx); err != nil {
			return err
		}
		if len(prefix) != 0 && prefix[0] != 0 {
			current = append(current, prefix[0])
		}
		if len(prefix) != 0 && prefix[0] == 0 {
			if err := c.examineString(start, current, true); err != nil {
				return err
			}
			completed++
			if readErr != nil || completed == count {
				return readErr
			}
			if address+target.Address(offset) == math.MaxUint64 {
				return target.ErrOverflow
			}
			start, current = address+target.Address(offset)+1, nil
		} else if readErr != nil {
			if errors.Is(readErr, target.ErrStale) {
				return readErr
			}
			return errors.Join(c.examineString(start, current, false), readErr)
		}
	}
	if len(current) != 0 {
		if err := c.examineString(start, current, false); err != nil {
			return err
		}
	}
	return fmt.Errorf("string display reached %d bytes with %d of %d NUL-terminated strings: %w", maxMemoryBytes, completed, count, target.ErrUnavailable)
}

func (c *Controller) examineString(address target.Address, data []byte, terminated bool) error {
	addressText, err := c.renderer.Address(target.AMD64, address, display.AddressUnknown)
	if err != nil {
		return err
	}
	suffix := ""
	if !terminated {
		suffix = " <unterminated>"
	}
	return c.writef("%s:\t%s%s\n", addressText, strconv.QuoteToASCII(string(data)), suffix)
}
