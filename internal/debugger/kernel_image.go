package debugger

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"

	"fastdbg2/inspect"
	"fastdbg2/target"
)

type kernelImage struct {
	orcOnce     sync.Once
	orc         *inspect.ORCIndex
	orcErr      error
	source      *os.File
	file        *elf.File
	info        os.FileInfo
	path        string
	slide, base uint64
	symbols     []inspect.Symbol
	cfiOnce     sync.Once
	cfi         *inspect.CFIIndex
	cfiErr      error
}

func openKernelImage(ctx context.Context, path string, slide uint64) (image *kernelImage, err error) {
	source, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			source.Close()
		}
	}()
	file, err := elf.NewFile(source)
	if err != nil {
		return nil, err
	}
	if err = validateAMD64ELF(file); err != nil {
		return nil, err
	}
	info, err := source.Stat()
	if err != nil {
		return nil, err
	}
	base := uint64(math.MaxUint64)
	for _, program := range file.Progs {
		if program.Type != elf.PT_LOAD || program.Memsz == 0 {
			continue
		}
		if program.Vaddr > math.MaxUint64-slide || program.Memsz > math.MaxUint64-(program.Vaddr+slide) {
			return nil, target.ErrOverflow
		}
		base = min(base, program.Vaddr)
	}
	if base == math.MaxUint64 {
		return nil, target.ErrUnavailable
	}
	index, err := inspect.LoadSymbols(ctx, []inspect.Module{{ID: "kernel", Path: fmt.Sprintf("/proc/self/fd/%d", source.Fd()), LoadBias: slide}}, 1)
	if err != nil {
		return nil, err
	}
	symbols, err := index.Symbols("kernel")
	if err != nil {
		return nil, err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	return &kernelImage{source: source, file: file, info: info, path: path, slide: slide, base: base + slide, symbols: symbols}, nil
}
func (image *kernelImage) Close() error { return image.source.Close() }
func (image *kernelImage) validate() error {
	info, err := image.source.Stat()
	if err != nil {
		return err
	}
	if info.Size() != image.info.Size() || !info.ModTime().Equal(image.info.ModTime()) {
		return fmt.Errorf("vmlinux changed: %w", target.ErrStale)
	}
	return nil
}
func (image *kernelImage) module() *mappedELF {
	return &mappedELF{ID: "kernel", Path: image.path, MetadataPath: image.path, File: image.file, Source: image.source, LoadBias: image.slide, Main: true, Proof: "explicit-vmlinux-and-slide", Scope: "kernel"}
}
func (s *qemuSession) addressWalkSymbols(ctx context.Context, snapshot target.Snapshot, thread target.ThreadInfo) ([]inspect.Symbol, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.image == nil {
		return nil, nil
	}
	if err := s.image.validate(); err != nil {
		return nil, err
	}
	return s.image.symbols, nil
}
func (image *kernelImage) frame(ctx context.Context, pc target.Address, read inspect.CFIReader) (*inspect.CFIFrame, error) {
	if err := image.validate(); err != nil {
		return nil, err
	}
	image.cfiOnce.Do(func() {
		for _, name := range []string{".eh_frame", ".debug_frame"} {
			section := image.file.Section(name)
			if section == nil || section.Size == 0 {
				continue
			}
			if section.Size > maxUnwindSectionBytes {
				image.cfiErr = target.ErrOverflow
				return
			}
			data, err := section.Data()
			if err != nil {
				image.cfiErr = err
				return
			}
			kind := inspect.CFIEHFrame
			if name == ".debug_frame" {
				kind = inspect.CFIDebugFrame
			}
			image.cfi, image.cfiErr = inspect.ParseCFISection(ctx, inspect.CFISection{AddressSize: 8, Kind: kind, Address: target.Address(section.Addr + image.slide), Data: data, LoadBias: image.slide, Source: image.path + ":" + name}, read)
			return
		}
		image.cfiErr = fmt.Errorf("vmlinux has no DWARF unwind tables: %w", target.ErrUnavailable)
	})
	if ctx.Err() != nil {
		image.cfiOnce = sync.Once{}
		return nil, ctx.Err()
	}
	if image.cfiErr != nil {
		return nil, image.cfiErr
	}
	return image.cfi.Lookup(pc)
}
func (c *Controller) collectKernelUnwind(ctx context.Context, seed unwindCommandSeed, limit int, profile inspect.UnwindProfile) (unwindCommandSeed, inspect.UnwindResult, error) {
	session := c.session.(*qemuSession)
	seed.profile = profile
	if session.image != nil {
		seed.symbols = session.image.symbols
		seed.symbolKey = newUISymbolCacheKey(seed.snapshot, seed.thread)
	}
	read := func(ctx context.Context, address target.Address, data []byte) (int, error) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		return session.ReadSpaceMemory(seed.snapshot.Memory, address, data)
	}
	if session.image != nil && session.image.file.Section(".orc_unwind") != nil {
		image := session.image
		seed.orc = true
		if err := image.validate(); err != nil {
			return seed, inspect.UnwindResult{}, err
		}
		image.orcOnce.Do(func() {
			var data [3][]byte
			for i, name := range []string{".orc_header", ".orc_unwind_ip", ".orc_unwind"} {
				section := image.file.Section(name)
				if section == nil {
					image.orcErr = target.ErrUnavailable
					return
				}
				if section.Size > 32<<20 {
					image.orcErr = target.ErrOverflow
					return
				}
				data[i], image.orcErr = section.Data()
				if image.orcErr != nil {
					return
				}
			}
			image.orc, image.orcErr = inspect.ParseORC(ctx, data[0], data[1], data[2], target.Address(image.file.Section(".orc_unwind_ip").Addr+image.slide), image.path+":ORC")
		})
		if ctx.Err() != nil {
			image.orcOnce = sync.Once{}
			return seed, inspect.UnwindResult{}, ctx.Err()
		}
		if image.orcErr != nil {
			return seed, inspect.UnwindResult{}, image.orcErr
		}
		result, err := image.orc.Unwind(ctx, seed.registers, seed.location.InstructionPC, read, limit)
		if proof := c.verifyProcSnapshot(seed.snapshot, seed.thread); proof != nil {
			return seed, inspect.UnwindResult{}, errors.Join(err, proof)
		}
		return seed, result, err
	}
	result, err := inspect.Unwind(ctx, inspect.UnwindRequest{Profile: profile, Registers: seed.registers, PC: seed.location.InstructionPC, MaxFrames: limit, Read: read, Find: func(ctx context.Context, pc target.Address) (*inspect.CFIFrame, error) {
		if session.image == nil {
			return nil, fmt.Errorf("backtrace requires --vmlinux and --kernel-slide: %w", target.ErrUnavailable)
		}
		return session.image.frame(ctx, pc, read)
	}})
	proof := c.verifyProcSnapshot(seed.snapshot, seed.thread)
	if proof != nil {
		return seed, inspect.UnwindResult{}, errors.Join(err, proof)
	}
	return seed, result, err
}

func (image *kernelImage) facts() moduleSymbolFacts {
	facts := moduleSymbolFacts{id: "kernel", path: image.path, proof: "explicit-vmlinux-and-slide", metadata: image.path, symbols: image.symbols, header: newMetadataModuleHeader(image.module())}
	for _, p := range image.file.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 && p.Memsz != 0 {
			facts.executable = append(facts.executable, executableSymbolRange{target.Address(p.Vaddr + image.slide), p.Memsz})
		}
	}
	return facts
}
