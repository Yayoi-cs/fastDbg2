package debugger

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"slices"
	"strings"

	"fastdbg2/target"
	"golang.org/x/sys/unix"
)

const kernelBuildIDMetadataProof = "kernel-vma-build-id-metadata"

func mappedELFSourceDescription(module *mappedELF) string {
	text := fmt.Sprintf("source-proof=%q scope=%q", module.Proof, module.Scope)
	if module.Runtime != nil {
		text += " metadata-source=runtime-memory"
	} else {
		text += fmt.Sprintf(" metadata-file=%q", module.MetadataPath)
	}
	if len(module.BuildID) != 0 {
		text += fmt.Sprintf(" build-id=%x", module.BuildID)
	}
	if module.Proof == kernelBuildIDMetadataProof {
		text += " (metadata association; backing-file identity is not established)"
	}
	return text
}

func mappedELFPathLabel(module *mappedELF) string {
	if module.Runtime != nil {
		return "runtime-image"
	}
	return "file"
}

func mappedELFMetadataFallback(err error) bool {
	return errors.Is(err, target.ErrUnavailable) && !errors.Is(err, target.ErrStale) && !runtimeELFFatal(err)
}

func commonMappedBuildID(group []procMap, query func(procMap) ([]byte, error)) ([]byte, error) {
	if len(group) == 0 || query == nil {
		return nil, target.ErrInvalidArgument
	}
	var expected []byte
	for _, mapping := range group {
		id, err := query(mapping)
		if err != nil {
			return nil, err
		}
		if len(id) == 0 || len(id) > 4096 {
			return nil, fmt.Errorf("VMA %#x has no usable GNU build ID: %w", mapping.Start, target.ErrUnavailable)
		}
		if expected == nil {
			expected = bytes.Clone(id)
		} else if !bytes.Equal(expected, id) {
			return nil, fmt.Errorf("maps device/inode group contains different kernel build IDs: %w", target.ErrAmbiguous)
		}
	}
	return expected, nil
}

func moduleMetadataCandidateNames(group []procMap) []string {
	var names []string
	for _, mapping := range group {
		if !strings.HasPrefix(mapping.Path, "/") || strings.ContainsRune(mapping.Path, 0) {
			continue
		}
		for _, name := range []string{strings.ReplaceAll(mapping.Path, `\012`, "\n"), mapping.Path} {
			if !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
	return names
}

func openModuleMetadataCandidate(proc *stoppedProc, root int, name string) (*os.File, error) {
	if err := contextReady(proc.ctx); err != nil {
		return nil, err
	}
	pin, err := unix.Openat2(root, name, &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_IN_ROOT})
	if err != nil {
		return nil, fmt.Errorf("pin module metadata candidate %q: %w", name, err)
	}
	source, readErr := openPinnedRegularELFSource(proc.ctx, pin, name)
	if err := errors.Join(readErr, unix.Close(pin)); err != nil {
		if source != nil {
			err = errors.Join(err, source.Close())
		}
		return nil, err
	}
	return source, nil
}

func openBuildIDMappedELF(proc *stoppedProc, group []procMap, identity mappedELFIdentity, page uint64) (module *mappedELF, err error) {
	id, err := commonMappedBuildID(group, proc.mappedBuildID)
	if err != nil {
		return nil, err
	}
	names := moduleMetadataCandidateNames(group)
	if len(names) == 0 {
		return nil, fmt.Errorf("no exact module metadata candidate path: %w", target.ErrUnavailable)
	}
	root, err := unix.Openat(int(proc.dir.Fd()), "root", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, unix.Close(root))
		if err != nil && module != nil {
			err = errors.Join(err, module.Source.Close())
			module = nil
		}
	}()
	var accepted []*mappedELF
	defer func() {
		for _, candidate := range accepted {
			if candidate != module {
				err = errors.Join(err, candidate.Source.Close())
			}
		}
	}()
	var failures, inaccessible error
	seen := make(map[mappedELFIdentity]bool)
	for _, name := range names {
		source, openErr := openModuleMetadataCandidate(proc, root, name)
		if openErr != nil {
			failures = errors.Join(failures, openErr)
			if !errors.Is(openErr, os.ErrNotExist) {
				inaccessible = errors.Join(inaccessible, openErr)
			}
			continue
		}
		sourceIdentity, identityErr := elfSourceIdentity(source)
		if identityErr != nil {
			return nil, errors.Join(identityErr, source.Close())
		}
		if seen[sourceIdentity] {
			if err := source.Close(); err != nil {
				return nil, err
			}
			continue
		}
		seen[sourceIdentity] = true
		candidate, candidateErr := associateMappedELFSource(source, name, group, identity, page, id)
		if candidateErr != nil {
			failures = errors.Join(failures, fmt.Errorf("module metadata candidate %q: %w", name, candidateErr))
			if err := source.Close(); err != nil {
				return nil, err
			}
			continue
		}
		accepted = append(accepted, candidate)
	}
	if len(accepted) > 1 {
		return nil, fmt.Errorf("multiple distinct module metadata candidates share the kernel build ID: %w", target.ErrAmbiguous)
	}
	if len(accepted) == 0 || inaccessible != nil {
		return nil, errors.Join(fmt.Errorf("no unique accessible module metadata association: %w", target.ErrUnavailable), failures)
	}
	return accepted[0], nil
}

func associateMappedELFSource(source *os.File, path string, group []procMap, identity mappedELFIdentity, page uint64, expectedID []byte) (*mappedELF, error) {
	if source == nil || len(group) == 0 || len(expectedID) == 0 {
		return nil, target.ErrInvalidArgument
	}
	file, err := parseAMD64ELFSource(source)
	if err != nil {
		return nil, err
	}
	id, err := elfGNUBuildID(file)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(id, expectedID) {
		return nil, fmt.Errorf("candidate GNU build ID %x differs from kernel VMA build ID %x: %w", id, expectedID, target.ErrUnavailable)
	}
	bias, err := mappedELFLoadBias(file, group, page)
	if err != nil {
		return nil, err
	}
	return &mappedELF{
		ID:   fmt.Sprintf("%x:%x:%d@0x%x", identity.major, identity.minor, identity.inode, bias),
		Path: group[0].Path, MetadataPath: path, Source: source, File: file, LoadBias: bias,
		Proof: kernelBuildIDMetadataProof, BuildID: bytes.Clone(id), Scope: "mapped-image",
	}, nil
}

func validateMappedELFRuntime(module *mappedELF, runtime *runtimeELFModule) error {
	if module == nil || runtime == nil || module.LoadBias != runtime.LoadBias {
		return fmt.Errorf("runtime and metadata ELF load biases differ: %w", target.ErrInvalidArgument)
	}
	if len(runtime.Programs) != len(module.File.Progs) {
		return fmt.Errorf("runtime and metadata ELF program counts differ: %w", target.ErrInvalidArgument)
	}
	for index, program := range module.File.Progs {
		if program.ProgHeader != runtime.Programs[index] {
			return fmt.Errorf("runtime and metadata ELF program header %d differs: %w", index, target.ErrInvalidArgument)
		}
	}
	if len(runtime.BuildID) != 0 {
		id, err := elfGNUBuildID(module.File)
		if err != nil {
			return err
		}
		if !bytes.Equal(id, runtime.BuildID) {
			return fmt.Errorf("runtime and metadata GNU build IDs differ: %w", target.ErrInvalidArgument)
		}
	}
	return nil
}

func openRuntimeMappedELF(proc *stoppedProc, runtime *runtimeELFModule) (module *mappedELF, err error) {
	if proc == nil || runtime == nil || !runtime.Main && (runtime.Dynamic.Address == 0 || runtime.Dynamic.Size == 0) {
		return nil, target.ErrInvalidArgument
	}
	mappings, err := proc.maps()
	if err != nil {
		return nil, err
	}
	page := uint64(os.Getpagesize())
	if runtime.Main {
		module, err = openMainELF(proc, mappings, page)
	} else {
		var group []procMap
		var identity mappedELFIdentity
		found := false
		for _, mapping := range mappings {
			if runtime.Dynamic.Address >= mapping.Start && runtime.Dynamic.Address < mapping.End {
				if mapping.Inode == 0 {
					return nil, fmt.Errorf("runtime ELF has no file-backed metadata candidate: %w", target.ErrUnavailable)
				}
				identity, found = elfMapIdentity(mapping), true
				break
			}
		}
		if !found {
			return nil, target.ErrUnavailable
		}
		for _, mapping := range mappings {
			if elfMapIdentity(mapping) == identity {
				group = append(group, mapping)
			}
		}
		module, err = openMappedELF(proc, group, identity, page)
	}
	if err != nil {
		return nil, err
	}
	if module == nil {
		return nil, target.ErrUnavailable
	}
	if err := validateMappedELFRuntime(module, runtime); err != nil {
		return nil, errors.Join(err, module.Source.Close())
	}
	if runtime.Dynamic.Size > math.MaxUint64-uint64(runtime.Dynamic.Address) {
		return nil, errors.Join(target.ErrOverflow, module.Source.Close())
	}
	return module, nil
}
