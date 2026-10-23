package debugger

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"strings"

	"fastdbg2/target"
)

const maxSeparateDebugBytes = 1 << 30

type associatedDebugELF struct {
	Source  *os.File
	File    *elf.File
	Path    string
	Proof   string
	BuildID []byte
}

func elfGNUDebuglink(file *elf.File) (string, uint32, error) {
	if file == nil || file.ByteOrder == nil {
		return "", 0, target.ErrInvalidArgument
	}
	var found *elf.Section
	for _, section := range file.Sections {
		if section.Name != ".gnu_debuglink" {
			continue
		}
		if found != nil {
			return "", 0, fmt.Errorf("multiple .gnu_debuglink sections: %w", target.ErrAmbiguous)
		}
		found = section
	}
	if found == nil {
		return "", 0, target.ErrNotFound
	}
	data, err := elfCommandSectionData(found)
	if err != nil {
		return "", 0, err
	}
	end := bytes.IndexByte(data, 0)
	if end <= 0 || end > 4096 {
		return "", 0, fmt.Errorf("invalid GNU debuglink name: %w", target.ErrInvalidArgument)
	}
	name := string(data[:end])
	if strings.ContainsRune(name, '/') || name == "." || name == ".." {
		return "", 0, fmt.Errorf("GNU debuglink name is not a basename: %w", target.ErrInvalidArgument)
	}
	checksumOffset := (end + 1 + 3) &^ 3
	if len(data) != checksumOffset+4 {
		return "", 0, fmt.Errorf("invalid GNU debuglink checksum extent: %w", target.ErrInvalidArgument)
	}
	return name, file.ByteOrder.Uint32(data[checksumOffset:]), nil
}

func debugFileCRC32(ctx context.Context, source *os.File) (uint32, error) {
	if err := contextReady(ctx); err != nil {
		return 0, err
	}
	info, err := source.Stat()
	if err != nil {
		return 0, err
	}
	if info.Size() < 0 || info.Size() > maxSeparateDebugBytes {
		return 0, fmt.Errorf("debug file size exceeds %d bytes: %w", maxSeparateDebugBytes, target.ErrUnsupported)
	}
	hash := crc32.NewIEEE()
	buffer := make([]byte, 64<<10)
	for offset := int64(0); offset < info.Size(); {
		if err := contextReady(ctx); err != nil {
			return 0, err
		}
		chunk := buffer[:min(int64(len(buffer)), info.Size()-offset)]
		n, err := source.ReadAt(chunk, offset)
		if err != nil || n != len(chunk) {
			return 0, errors.Join(err, io.ErrUnexpectedEOF)
		}
		_, _ = hash.Write(chunk)
		offset += int64(n)
	}
	if err := contextReady(ctx); err != nil {
		return 0, err
	}
	return hash.Sum32(), nil
}

func associateELFDebugFile(ctx context.Context, module *mappedELF, path string) (result *associatedDebugELF, err error) {
	if module == nil || module.File == nil {
		return nil, target.ErrInvalidArgument
	}
	source, err := openRegularELFSource(ctx, path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if result == nil {
			err = errors.Join(err, source.Close())
		}
	}()
	return associateELFDebugSource(ctx, module, source, path)
}

func associateELFDebugSource(ctx context.Context, module *mappedELF, source *os.File, path string) (*associatedDebugELF, error) {
	if module == nil || module.File == nil || source == nil {
		return nil, target.ErrInvalidArgument
	}
	if err := contextReady(ctx); err != nil {
		return nil, err
	}
	file, err := parseAMD64ELFSource(source)
	if err != nil {
		return nil, err
	}
	if file.Type != module.File.Type {
		return nil, fmt.Errorf("module and separate debug ELF types differ: %w", target.ErrInvalidArgument)
	}
	moduleID, moduleIDErr := elfGNUBuildID(module.File)
	debugID, debugIDErr := elfGNUBuildID(file)
	if moduleIDErr != nil && !errors.Is(moduleIDErr, target.ErrUnavailable) {
		return nil, moduleIDErr
	}
	if debugIDErr != nil && !errors.Is(debugIDErr, target.ErrUnavailable) {
		return nil, debugIDErr
	}
	if moduleIDErr == nil && debugIDErr == nil {
		if !bytes.Equal(moduleID, debugID) {
			return nil, fmt.Errorf("module and separate debug GNU build IDs differ: %w", target.ErrUnavailable)
		}
		if err := contextReady(ctx); err != nil {
			return nil, err
		}
		return &associatedDebugELF{Source: source, File: file, Path: path, Proof: "gnu-build-id-metadata", BuildID: bytes.Clone(debugID)}, nil
	}
	name, expected, err := elfGNUDebuglink(module.File)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("no matching GNU build ID or usable debuglink association: %w", target.ErrUnavailable), err)
	}
	checksum, err := debugFileCRC32(ctx, source)
	if err != nil {
		return nil, err
	}
	if checksum != expected {
		return nil, fmt.Errorf("debuglink %q CRC32 %#x differs from candidate %#x: %w", name, expected, checksum, target.ErrUnavailable)
	}
	return &associatedDebugELF{Source: source, File: file, Path: path, Proof: "gnu-debuglink-crc32-metadata", BuildID: bytes.Clone(debugID)}, nil
}
