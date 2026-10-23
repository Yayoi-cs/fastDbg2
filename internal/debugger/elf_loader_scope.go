package debugger

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"math"

	"fastdbg2/target"
)

func mappedELFDynamicAddress(module *mappedELF) (target.Address, error) {
	var address target.Address
	found := false
	for _, program := range module.File.Progs {
		if program.Type != elf.PT_DYNAMIC {
			continue
		}
		if found {
			return 0, target.ErrAmbiguous
		}
		if program.Vaddr > math.MaxUint64-module.LoadBias {
			return 0, target.ErrOverflow
		}
		address, found = target.Address(module.LoadBias+program.Vaddr), true
	}
	if !found {
		return 0, target.ErrUnavailable
	}
	return address, nil
}

func loaderELFMembership(view *runtimeELFView, mappings []procMap, main *mappedELF) (map[mappedELFIdentity][]runtimeLinkMap, error) {
	if view == nil || !view.LoaderComplete || main == nil {
		return nil, target.ErrInvalidArgument
	}
	mainDynamic, err := mappedELFDynamicAddress(main)
	if err != nil {
		return nil, err
	}
	groups := make(map[mappedELFIdentity][]runtimeLinkMap)
	var failures error
	for _, link := range view.Loader {
		if link.bias == main.LoadBias && link.dynamic == mainDynamic {
			continue
		}
		found := false
		for _, mapping := range mappings {
			if link.dynamic < mapping.Start || link.dynamic >= mapping.End {
				continue
			}
			found = true
			if mapping.Inode == 0 {
				if !runtimeVDSOLoaderAnchor(view, link) {
					failures = errors.Join(failures, fmt.Errorf("loader module %q at %#x has no supported runtime metadata provider: %w", link.name, link.bias, target.ErrUnavailable))
				}
				break
			}
			key := elfMapIdentity(mapping)
			duplicate := false
			for _, previous := range groups[key] {
				if previous.bias == link.bias && previous.dynamic == link.dynamic {
					duplicate = true
					break
				}
			}
			if !duplicate {
				groups[key] = append(groups[key], link)
			}
			break
		}
		if !found {
			failures = errors.Join(failures, fmt.Errorf("loader module %q dynamic address %#x is absent from mappings: %w", link.name, link.dynamic, target.ErrStale))
		}
	}
	return groups, failures
}

func runtimeVDSOLoaderAnchor(view *runtimeELFView, link runtimeLinkMap) bool {
	for _, module := range view.Modules {
		if module.AuxiliaryTag == 33 && module.AuxiliaryAddress == module.Header && module.LoadBias == link.bias && module.Dynamic.Address == link.dynamic {
			return true
		}
	}
	return false
}

func runtimeOnlyELFMetadata(view *runtimeELFView, loaderOnly bool) ([]*mappedELF, error) {
	var modules []*mappedELF
	for _, runtime := range view.Modules {
		if runtime.AuxiliaryTag != 33 || runtime.AuxiliaryAddress != runtime.Header {
			continue
		}
		found := false
		for _, link := range view.Loader {
			if runtime.LoadBias == link.bias && runtime.Dynamic.Address == link.dynamic {
				found = true
				break
			}
		}
		if loaderOnly && !found {
			continue
		}
		metadata, err := readRuntimeVDSO(view, runtime)
		if err != nil {
			return nil, fmt.Errorf("runtime vDSO metadata: %w", err)
		}
		scope := "auxv/runtime-dynamic"
		if found {
			scope = "loader/runtime-dynamic"
		}
		modules = append(modules, &mappedELF{
			ID: runtime.ID, Path: runtime.Name, LoadBias: runtime.LoadBias,
			Proof: "auxv-vdso+runtime-dynamic-metadata", Scope: scope, BuildID: runtime.BuildID, Runtime: metadata,
		})
	}
	return modules, nil
}

func (c *Controller) namedRuntimeELFMetadata(ctx context.Context, snapshot target.Snapshot, proc *stoppedProc) ([]*mappedELF, error) {
	view, err := c.runtimeELFModules(ctx, snapshot, proc)
	if view != nil && view.Memory != nil {
		defer view.Memory.close()
	}
	if view == nil || runtimeELFFatal(err) {
		return nil, err
	}
	return runtimeOnlyELFMetadata(view, false)
}

func validateELFLoaderMembership(module *mappedELF, links []runtimeLinkMap, view *runtimeELFView) error {
	if len(links) != 1 {
		return fmt.Errorf("mapped metadata group has %d distinct loader instances: %w", len(links), target.ErrAmbiguous)
	}
	link := links[0]
	dynamic, err := mappedELFDynamicAddress(module)
	if err != nil {
		return err
	}
	if module.LoadBias != link.bias || dynamic != link.dynamic {
		return fmt.Errorf("associated ELF metadata does not match the loader bias/dynamic address: %w", target.ErrUnavailable)
	}
	for _, runtime := range view.Modules {
		if runtime.LoadBias == link.bias && runtime.Dynamic.Address == link.dynamic {
			return validateMappedELFRuntime(module, runtime)
		}
	}
	return nil
}
