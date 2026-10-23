package debugger

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"fastdbg2/target"
)

type elfBuildIDNote struct {
	offset uint64
	id     []byte
}

func elfGNUNotes(data []byte, base uint64, order binary.ByteOrder) ([]elfBuildIDNote, error) {
	if order == nil || uint64(len(data)) > math.MaxUint64-base {
		return nil, target.ErrInvalidArgument
	}
	var notes []elfBuildIDNote
	for cursor := uint64(0); cursor < uint64(len(data)); {
		remaining := data[cursor:]
		if len(remaining) < 12 {
			if bytes.Count(remaining, []byte{0}) == len(remaining) {
				break
			}
			return nil, fmt.Errorf("truncated ELF note header: %w", target.ErrInvalidArgument)
		}
		nameSize := uint64(order.Uint32(remaining[:4]))
		dataSize := uint64(order.Uint32(remaining[4:8]))
		kind := order.Uint32(remaining[8:12])
		namePadded, dataPadded := (nameSize+3)&^uint64(3), (dataSize+3)&^uint64(3)
		if namePadded > uint64(len(remaining))-12 || dataPadded > uint64(len(remaining))-12-namePadded {
			return nil, fmt.Errorf("ELF note exceeds its container: %w", target.ErrInvalidArgument)
		}
		nameStart, dataStart := cursor+12, cursor+12+namePadded
		if kind == 3 && bytes.Equal(data[nameStart:nameStart+nameSize], []byte("GNU\x00")) {
			if dataSize == 0 || dataSize > 4096 {
				return nil, fmt.Errorf("GNU build ID length %d: %w", dataSize, target.ErrUnsupported)
			}
			notes = append(notes, elfBuildIDNote{base + cursor, bytes.Clone(data[dataStart : dataStart+dataSize])})
		}
		cursor += 12 + namePadded + dataPadded
	}
	return notes, nil
}

func elfGNUBuildID(file *elf.File) ([]byte, error) {
	if file == nil || file.ByteOrder == nil {
		return nil, target.ErrInvalidArgument
	}
	var notes []elfBuildIDNote
	remaining := uint64(maxELFCommandMetadata)
	for _, program := range file.Progs {
		if program.Type != elf.PT_NOTE {
			continue
		}
		if program.Filesz > remaining || program.Filesz > math.MaxUint64-program.Off {
			return nil, fmt.Errorf("ELF note segment range: %w", target.ErrOverflow)
		}
		remaining -= program.Filesz
		data := make([]byte, int(program.Filesz))
		if _, err := io.ReadFull(program.Open(), data); err != nil {
			return nil, err
		}
		found, err := elfGNUNotes(data, program.Off, file.ByteOrder)
		if err != nil {
			return nil, err
		}
		notes = append(notes, found...)
	}
	for _, section := range file.Sections {
		if section.Type != elf.SHT_NOTE {
			continue
		}
		if section.Size > remaining {
			return nil, fmt.Errorf("ELF note metadata budget exhausted: %w", target.ErrOverflow)
		}
		remaining -= section.Size
		data, err := elfCommandSectionData(section)
		if err != nil {
			return nil, err
		}
		found, err := elfGNUNotes(data, section.Offset, file.ByteOrder)
		if err != nil {
			return nil, err
		}
		notes = append(notes, found...)
	}
	return uniqueELFBuildID(notes)
}

func uniqueELFBuildID(notes []elfBuildIDNote) ([]byte, error) {
	if len(notes) == 0 {
		return nil, fmt.Errorf("ELF has no GNU build ID: %w", target.ErrUnavailable)
	}
	first := notes[0]
	if len(first.id) == 0 || len(first.id) > 4096 {
		return nil, target.ErrInvalidArgument
	}
	for _, note := range notes[1:] {
		if note.offset != first.offset || !bytes.Equal(note.id, first.id) {
			return nil, fmt.Errorf("ELF contains multiple GNU build ID notes: %w", target.ErrAmbiguous)
		}
	}
	return bytes.Clone(first.id), nil
}
