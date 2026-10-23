package debugger

import (
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"fastdbg2/inspect"
	"fastdbg2/target"
)

type imageState struct {
	space target.SpaceRef
	image *loadedImage
}

type loadedImage struct {
	symbols   *inspect.SymbolIndex
	symbolErr error
	loadBias  uint64
	path      string
}

func preflightAMD64(path string) error {
	if path == "" {
		return fmt.Errorf("executable path is required: %w", target.ErrInvalidArgument)
	}
	resolved, err := exec.LookPath(path)
	if err != nil {
		return fmt.Errorf("executable %q: %w", path, err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return err
	}
	return preflightELF(resolved)
}

func preflightAttachAMD64(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("attach PID %d: %w", pid, target.ErrInvalidArgument)
	}
	return preflightELF(fmt.Sprintf("/proc/%d/exe", pid))
}

func preflightELF(path string) (err error) {
	file, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf("ELF %q: %w", path, err)
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	if err := validateAMD64ELF(file); err != nil {
		return fmt.Errorf("ELF %q: %w", path, err)
	}
	return nil
}

func validateAMD64ELF(file *elf.File) error {
	if file == nil {
		return target.ErrInvalidArgument
	}
	if file.Class != elf.ELFCLASS64 || file.Machine != elf.EM_X86_64 || file.Data != elf.ELFDATA2LSB {
		return fmt.Errorf("commands require little-endian ELF64 AMD64: %w", target.ErrUnsupported)
	}
	if file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN {
		return fmt.Errorf("ELF type %s: %w", file.Type, target.ErrUnsupported)
	}
	return nil
}

func validateImageSnapshot(snapshot target.Snapshot, thread target.ThreadInfo) error {
	if snapshot.Architecture != target.AMD64 {
		return fmt.Errorf("commands require AMD64, target is %s: %w", snapshot.Architecture, target.ErrUnsupported)
	}
	if snapshot.State != target.StateStopped {
		return fmt.Errorf("target is %s: %w", snapshot.State, target.ErrInvalidState)
	}
	if snapshot.Process.ID == 0 || snapshot.Process.Session == 0 ||
		snapshot.Memory.Space.ID == 0 || snapshot.Memory.Space.Session != snapshot.Process.Session ||
		snapshot.Memory.Revision == 0 {
		return fmt.Errorf("primary memory is unavailable: %w", target.ErrUnavailable)
	}
	if thread.Process != snapshot.Process {
		return fmt.Errorf("selected thread is not in the primary process: %w", target.ErrUnsupported)
	}
	if thread.TID <= 0 || thread.Ref.ID == 0 || thread.Ref.Session != snapshot.Process.Session ||
		thread.State != target.StateStopped || thread.Exiting || thread.Listening {
		return fmt.Errorf("selected thread is not inspectable: %w", target.ErrInvalidState)
	}
	if thread.Token.Thread != thread.Ref || thread.Token.Stop == 0 || thread.Token.Registers == 0 {
		return fmt.Errorf("selected thread token is invalid: %w", target.ErrStale)
	}
	for _, current := range snapshot.Threads {
		if current.Ref == thread.Ref {
			if current.TID != thread.TID || current.Process != thread.Process || current.Token != thread.Token ||
				current.State != thread.State || current.Exiting != thread.Exiting || current.Listening != thread.Listening {
				return fmt.Errorf("selected thread differs from snapshot: %w", target.ErrStale)
			}
			return nil
		}
	}
	return fmt.Errorf("selected thread is absent from snapshot: %w", target.ErrStale)
}

func (state *imageState) load(ctx context.Context, snapshot target.Snapshot, thread target.ThreadInfo) (*loadedImage, error) {
	return state.loadWith(ctx, snapshot, thread, readLiveImage)
}

func (state *imageState) loadWith(ctx context.Context, snapshot target.Snapshot, thread target.ThreadInfo, read func(context.Context, int) (*loadedImage, error)) (*loadedImage, error) {
	if state == nil || ctx == nil || read == nil {
		return nil, target.ErrInvalidArgument
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateImageSnapshot(snapshot, thread); err != nil {
		return nil, err
	}
	if state.space == snapshot.Memory.Space && state.image != nil {
		return state.image, nil
	}
	state.space, state.image = target.SpaceRef{}, nil
	image, err := read(ctx, thread.TID)
	if err != nil {
		return nil, err
	}
	if image == nil {
		return nil, fmt.Errorf("image source returned no image: %w", target.ErrUnavailable)
	}
	state.space, state.image = snapshot.Memory.Space, image
	return image, nil
}

func readLiveImage(ctx context.Context, tid int) (image *loadedImage, err error) {
	if ctx == nil || tid <= 0 {
		return nil, target.ErrInvalidArgument
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/proc/%d/exe", tid)
	source, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open executable for TID %d: %w", tid, err)
	}
	defer func() { err = errors.Join(err, source.Close()) }()
	file, err := elf.NewFile(source)
	if err != nil {
		return nil, fmt.Errorf("ELF for TID %d: %w", tid, err)
	}
	if err := validateAMD64ELF(file); err != nil {
		return nil, err
	}
	auxv, err := os.ReadFile(fmt.Sprintf("/proc/%d/auxv", tid))
	if err != nil {
		return nil, fmt.Errorf("auxv for TID %d: %w", tid, err)
	}
	bias, err := imageLoadBias(file.Type, file.Entry, auxv)
	if err != nil {
		return nil, err
	}
	symbols, symbolErr := inspect.LoadSymbols(ctx, []inspect.Module{{
		ID:       "main",
		Path:     fmt.Sprintf("/proc/self/fd/%d", source.Fd()),
		LoadBias: bias,
	}}, 1)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &loadedImage{symbols: symbols, symbolErr: symbolErr, loadBias: bias, path: path}, nil
}

func imageLoadBias(kind elf.Type, entry uint64, auxv []byte) (uint64, error) {
	if kind != elf.ET_EXEC && kind != elf.ET_DYN {
		return 0, fmt.Errorf("ELF type %s: %w", kind, target.ErrUnsupported)
	}
	actual, err := auxiliaryEntry(auxv)
	if err != nil {
		return 0, err
	}
	if kind == elf.ET_EXEC {
		if actual != entry {
			return 0, fmt.Errorf("AT_ENTRY %#x differs from ELF entry %#x: %w", actual, entry, target.ErrStale)
		}
		return 0, nil
	}
	if actual < entry {
		return 0, fmt.Errorf("AT_ENTRY %#x is below ELF entry %#x: %w", actual, entry, target.ErrOverflow)
	}
	return actual - entry, nil
}

func auxiliaryEntry(data []byte) (uint64, error) {
	if len(data) == 0 || len(data)%16 != 0 {
		return 0, fmt.Errorf("invalid AMD64 auxv length %d: %w", len(data), target.ErrInvalidArgument)
	}
	var entry uint64
	var found, terminated bool
	for offset := 0; offset < len(data); offset += 16 {
		key := binary.LittleEndian.Uint64(data[offset : offset+8])
		value := binary.LittleEndian.Uint64(data[offset+8 : offset+16])
		if terminated {
			if key != 0 || value != 0 {
				return 0, fmt.Errorf("nonzero data after AT_NULL: %w", target.ErrInvalidArgument)
			}
			continue
		}
		if key == 0 {
			if value != 0 {
				return 0, fmt.Errorf("nonzero AT_NULL value: %w", target.ErrInvalidArgument)
			}
			terminated = true
		} else if key == 9 {
			if found {
				return 0, fmt.Errorf("duplicate AT_ENTRY: %w", target.ErrInvalidArgument)
			}
			entry, found = value, true
		}
	}
	if !terminated {
		return 0, fmt.Errorf("auxv has no AT_NULL: %w", target.ErrInvalidArgument)
	}
	if !found {
		return 0, fmt.Errorf("auxv has no AT_ENTRY: %w", target.ErrUnavailable)
	}
	return entry, nil
}

func (image *loadedImage) resolveSymbol(name string) (uint64, error) {
	if image == nil {
		return 0, fmt.Errorf("main executable symbols: %w", target.ErrUnavailable)
	}
	if image.symbolErr != nil {
		return 0, fmt.Errorf("main executable symbols: %w", image.symbolErr)
	}
	symbol, err := image.symbols.ResolveName("main", name)
	if err != nil {
		return 0, err
	}
	if !symbol.AddressKnown {
		return 0, fmt.Errorf("symbol %q has no runtime address: %w", name, target.ErrUnavailable)
	}
	return uint64(symbol.Address), nil
}
