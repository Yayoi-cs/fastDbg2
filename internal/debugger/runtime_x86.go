package debugger

import (
	"context"
	"debug/elf"
	"errors"
	"os"

	"fastdbg2/target"
)

func (c *Controller) runtimeX86Modules(ctx context.Context, snapshot target.Snapshot, proc *stoppedProc, main *mappedELF) (*runtimeELFView, error) {
	mappings, err := proc.maps()
	if err != nil {
		return nil, err
	}
	if main == nil {
		main, err = openMainELF(proc, mappings, uint64(os.Getpagesize()))
		if err != nil {
			return nil, err
		}
		defer main.Source.Close()
	}
	extra, discovery := c.x86MappedModules(ctx, snapshot, proc, main, mappings)
	defer func() {
		for _, m := range extra {
			if m.Source != nil {
				m.Source.Close()
			}
		}
	}()
	if runtimeELFFatal(discovery) {
		return nil, discovery
	}
	memory, err := newRuntimeELFMemory(ctx, mappings, func(address target.Address, data []byte) (int, error) {
		return c.session.ReadSpaceMemory(snapshot.Memory, address, data)
	})
	if err != nil {
		return nil, err
	}
	view := &runtimeELFView{Memory: memory, LoaderComplete: discovery == nil}
	values, err := x86Auxiliary(proc)
	if err != nil {
		memory.close()
		return nil, err
	}
	debug, present, debugErr := x86DebugAddress(memory, main)
	if present && debugErr == nil {
		view.Loader, err = runtimeELFLinkMaps(memory, debug, 4)
		if err != nil {
			memory.close()
			return nil, err
		}
	}
	for _, m := range append([]*mappedELF{main}, extra...) {
		r := &runtimeELFModule{Architecture: target.X86, ID: m.ID, Name: m.Path, Proof: m.Proof, Main: m.Main, LoadBias: m.LoadBias}
		if m.Runtime != nil {
			r.Programs = m.Runtime.Programs
		} else {
			for _, p := range m.File.Progs {
				r.Programs = append(r.Programs, p.ProgHeader)
			}
			r.BuildID, r.BuildIDErr = elfGNUBuildID(m.File)
		}
		for _, p := range r.Programs {
			address := target.Address(r.LoadBias + p.Vaddr)
			switch p.Type {
			case elf.PT_LOAD:
				r.Loads = append(r.Loads, runtimeELFSpan{Address: address, Size: p.Memsz})
				if p.Off == 0 && p.Filesz >= 52 {
					r.Header = address
				}
			case elf.PT_DYNAMIC:
				r.Dynamic = runtimeELFSpan{Address: address, Size: p.Memsz}
			case elf.PT_GNU_EH_FRAME:
				r.EHFrameHeader = runtimeELFSpan{Address: address, Size: p.Memsz}
			}
		}
		for _, tag := range []uint64{7, 33} {
			if values[tag] != 0 && uint64(r.Header) == values[tag] {
				r.AuxiliaryTag = tag
				r.AuxiliaryAddress = r.Header
			}
		}
		for _, l := range view.Loader {
			if l.bias == r.LoadBias && l.dynamic == r.Dynamic.Address {
				r.Links = append(r.Links, runtimeELFLink{Namespace: l.namespace, Address: l.address, Name: l.name})
			}
		}
		view.Modules = append(view.Modules, r)
	}
	if discovery != nil {
		return view, &runtimeELFPartialError{Err: discovery}
	}
	return view, errors.Join(err)
}
