package debugger

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"fastdbg2/target"
	"golang.org/x/sys/unix"
)

type elfModuleSelection struct {
	All  bool
	Name string
}

type mappedELF struct {
	ID           string
	Path         string
	MetadataPath string
	File         *elf.File
	Source       *os.File
	LoadBias     uint64
	Main         bool
	Proof        string
	BuildID      []byte
	Scope        string
	Runtime      *runtimeVDSOMetadata
}

type mappedELFIdentity struct {
	major uint32
	minor uint32
	inode uint64
}

type mappedELFPartialError struct {
	Err error
}

func (err *mappedELFPartialError) Error() string {
	return fmt.Sprintf("mapped ELF scan incomplete: %v", err.Err)
}

func (err *mappedELFPartialError) Unwrap() error { return err.Err }

func (err *mappedELFPartialError) Is(other error) bool { return other == target.ErrPartial }

func mappedELFResultUsable(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, target.ErrStale) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	_, ok := err.(*mappedELFPartialError)
	return ok
}

func elfSourceIdentity(source *os.File) (mappedELFIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(source.Fd()), &stat); err != nil {
		return mappedELFIdentity{}, err
	}
	return mappedELFIdentity{unix.Major(stat.Dev), unix.Minor(stat.Dev), stat.Ino}, nil
}

func elfMapIdentity(mapping procMap) mappedELFIdentity {
	return mappedELFIdentity{mapping.DevMajor, mapping.DevMinor, mapping.Inode}
}

func (c *Controller) withELFModules(ctx context.Context, snapshot target.Snapshot, thread target.ThreadInfo, selection elfModuleSelection, visit func([]*mappedELF) error) error {
	if visit == nil || selection.All && selection.Name != "" {
		return target.ErrInvalidArgument
	}
	var discoveryErr error
	err := c.withStoppedProc(ctx, snapshot, thread, func(proc *stoppedProc) (err error) {
		var modules []*mappedELF
		var sources []*os.File
		defer func() {
			for _, source := range sources {
				err = errors.Join(err, source.Close())
			}
		}()
		mappings, err := proc.maps()
		if err != nil {
			return err
		}
		page := uint64(os.Getpagesize())
		main, err := openMainELF(proc, mappings, page)
		if err != nil {
			return err
		}
		sources = append(sources, main.Source)
		modules = append(modules, main)
		if !selection.All && (selection.Name == "" || selection.Name == "main") {
			return visit(modules)
		}
		var loader *runtimeELFView
		var membership map[mappedELFIdentity][]runtimeLinkMap
		if selection.All {
			view, runtimeErr := c.runtimeELFModulesWithMain(ctx, snapshot, proc, main)
			if view != nil && view.Memory != nil {
				defer view.Memory.close()
			}
			if runtimeELFFatal(runtimeErr) {
				return runtimeErr
			}
			if view != nil && view.LoaderComplete {
				loader = view
				var scopeErr error
				membership, scopeErr = loaderELFMembership(view, mappings, main)
				discoveryErr = errors.Join(discoveryErr, runtimeErr, scopeErr)
				main.Scope = "loader"
				runtimeModules, runtimeMetadataErr := runtimeOnlyELFMetadata(view, true)
				discoveryErr = errors.Join(discoveryErr, runtimeMetadataErr)
				modules = append(modules, runtimeModules...)
			} else if runtimeErr != nil {
				discoveryErr = errors.Join(discoveryErr, fmt.Errorf("loader module scope unavailable; examining mapped images instead: %w", runtimeErr))
			}
		}
		groups := make(map[mappedELFIdentity][]procMap)
		var identities []mappedELFIdentity
		for _, mapping := range mappings {
			key := elfMapIdentity(mapping)
			if mapping.Inode == 0 || elfMapAtLoadBias(main.File, mapping, main.LoadBias) {
				continue
			}
			if _, ok := groups[key]; !ok {
				identities = append(identities, key)
			}
			groups[key] = append(groups[key], mapping)
		}
		for _, key := range identities {
			if err := contextReady(ctx); err != nil {
				return err
			}
			group := groups[key]
			if loader != nil && len(membership[key]) == 0 {
				continue
			}
			if !selection.All && !elfGroupMatches(group, key, selection.Name) {
				continue
			}
			module, err := openMappedELF(proc, group, key, page)
			if err != nil {
				discoveryErr = errors.Join(discoveryErr, fmt.Errorf("mapped file %q: %w", group[0].Path, err))
				continue
			}
			if module == nil {
				continue
			}
			if loader != nil {
				if scopeErr := validateELFLoaderMembership(module, membership[key], loader); scopeErr != nil {
					discoveryErr = errors.Join(discoveryErr, scopeErr, module.Source.Close())
					continue
				}
				module.Scope = "loader"
			}
			sources = append(sources, module.Source)
			modules = append(modules, module)
		}
		if !selection.All && selection.Name != "" {
			runtimeModules, runtimeErr := c.namedRuntimeELFMetadata(ctx, snapshot, proc)
			if runtimeELFFatal(runtimeErr) {
				return runtimeErr
			}
			if runtimeErr == nil {
				modules = append(modules, runtimeModules...)
			} else {
				discoveryErr = errors.Join(discoveryErr, runtimeErr)
			}
		}
		selected, err := selectELFModules(modules, selection)
		if err != nil {
			if discoveryErr != nil && errors.Is(err, target.ErrNotFound) {
				return errors.Join(fmt.Errorf("selected mapped ELF %q could not be fully examined: %w", selection.Name, target.ErrUnavailable), discoveryErr)
			}
			return errors.Join(err, discoveryErr)
		}
		return visit(selected)
	})
	if err != nil {
		return err
	}
	if discoveryErr != nil {
		if errors.Is(discoveryErr, target.ErrStale) || errors.Is(discoveryErr, context.Canceled) || errors.Is(discoveryErr, context.DeadlineExceeded) {
			return discoveryErr
		}
		return &mappedELFPartialError{Err: discoveryErr}
	}
	return nil
}

func openMappedELF(proc *stoppedProc, group []procMap, identity mappedELFIdentity, page uint64) (module *mappedELF, err error) {
	module, err = openIdentityMappedELF(proc, group, identity, page)
	if !mappedELFMetadataFallback(err) {
		return module, err
	}
	associated, associationErr := openBuildIDMappedELF(proc, group, identity, page)
	if associationErr != nil {
		return nil, errors.Join(err, associationErr)
	}
	return associated, nil
}

func openIdentityMappedELF(proc *stoppedProc, group []procMap, identity mappedELFIdentity, page uint64) (module *mappedELF, err error) {
	if len(group) == 0 {
		return nil, target.ErrInvalidArgument
	}
	source, err := proc.openMappedFile(group[0])
	if err != nil {
		return nil, err
	}
	defer func() {
		if module == nil {
			err = errors.Join(err, source.Close())
		}
	}()
	var magic [4]byte
	_, err = source.ReadAt(magic[:], 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if string(magic[:]) != elf.ELFMAG {
		return nil, nil
	}
	file, err := elf.NewFile(source)
	if err != nil {
		return nil, err
	}
	if err := validateAMD64ELF(file); err != nil {
		return nil, err
	}
	if err := verifyMappedELFGroup(proc, group, source); err != nil {
		return nil, err
	}
	bias, err := mappedELFLoadBias(file, group, page)
	if err != nil {
		return nil, err
	}
	return &mappedELF{
		ID:   fmt.Sprintf("%x:%x:%d@0x%x", identity.major, identity.minor, identity.inode, bias),
		Path: group[0].Path, MetadataPath: group[0].Path, File: file, Source: source, LoadBias: bias, Proof: "mapped-file", Scope: "mapped-image",
	}, nil
}

func parseAMD64ELFSource(source *os.File) (*elf.File, error) {
	file, err := elf.NewFile(source)
	if err != nil {
		return nil, err
	}
	if err := validateAMD64ELF(file); err != nil {
		return nil, err
	}
	return file, nil
}

func openMainELF(proc *stoppedProc, mappings []procMap, page uint64) (module *mappedELF, err error) {
	source, err := proc.openFile("exe")
	if err != nil {
		return nil, err
	}
	defer func() {
		if module == nil {
			err = errors.Join(err, source.Close())
		}
	}()
	path, err := proc.readlink("exe")
	if err != nil {
		return nil, err
	}
	file, err := parseAMD64ELFSource(source)
	if err != nil {
		return nil, fmt.Errorf("main executable ELF: %w", err)
	}
	auxv, err := proc.readFile("auxv")
	if err != nil {
		return nil, err
	}
	bias, err := imageLoadBias(file.Type, file.Entry, auxv)
	if err != nil {
		return nil, err
	}
	if err := validateELFLoadBias(file, mappings, page, bias); err != nil {
		return nil, fmt.Errorf("main executable PT_LOAD coverage observation: %w", err)
	}
	return &mappedELF{ID: "main", Path: path, MetadataPath: path, Source: source, File: file, Main: true, LoadBias: bias, Proof: "proc-exe+auxv", Scope: "executable"}, nil
}

func verifyMappedELFGroup(proc *stoppedProc, group []procMap, source *os.File) error {
	identity, err := elfSourceIdentity(source)
	if err != nil {
		return err
	}
	for _, mapping := range group[1:] {
		other, err := proc.openMappedFile(mapping)
		if err != nil {
			return err
		}
		otherIdentity, identityErr := elfSourceIdentity(other)
		if err := errors.Join(identityErr, other.Close()); err != nil {
			return err
		}
		if otherIdentity != identity {
			return fmt.Errorf("maps device/inode group contains distinct pinned files: %w", target.ErrAmbiguous)
		}
	}
	return nil
}

func elfMapAtLoadBias(file *elf.File, mapping procMap, bias uint64) bool {
	for _, program := range file.Progs {
		if program.Type != elf.PT_LOAD || program.Vaddr > math.MaxUint64-bias || program.Filesz > math.MaxUint64-(program.Vaddr+bias) {
			continue
		}
		begin := program.Vaddr + bias
		cursor := max(begin, uint64(mapping.Start))
		if cursor >= min(begin+program.Filesz, uint64(mapping.End)) {
			continue
		}
		delta := cursor - uint64(mapping.Start)
		if delta <= math.MaxUint64-mapping.Offset && cursor-begin <= math.MaxUint64-program.Off && mapping.Offset+delta == program.Off+cursor-begin {
			return true
		}
	}
	return false
}

func elfGroupMatches(mappings []procMap, identity mappedELFIdentity, name string) bool {
	prefix := fmt.Sprintf("%x:%x:%d@", identity.major, identity.minor, identity.inode)
	if strings.HasPrefix(name, prefix) {
		return true
	}
	for _, mapping := range mappings {
		if name == mapping.Path || name == filepath.Base(mapping.Path) {
			return true
		}
	}
	return false
}

func selectELFModules(modules []*mappedELF, selection elfModuleSelection) ([]*mappedELF, error) {
	if selection.All {
		return slices.Clone(modules), nil
	}
	var matched []*mappedELF
	for _, module := range modules {
		if selection.Name == "" && module.Main || selection.Name == module.ID || selection.Name == module.Path || selection.Name == filepath.Base(module.Path) {
			matched = append(matched, module)
		}
	}
	if len(matched) == 0 {
		return nil, fmt.Errorf("mapped ELF %q: %w", selection.Name, target.ErrNotFound)
	}
	if len(matched) != 1 {
		return nil, fmt.Errorf("mapped ELF %q has %d exact matches: %w", selection.Name, len(matched), target.ErrAmbiguous)
	}
	return matched, nil
}

func elfLoadSegments(file *elf.File, page uint64) ([]*elf.Prog, error) {
	if file == nil || page == 0 || page&(page-1) != 0 {
		return nil, target.ErrInvalidArgument
	}
	var loads []*elf.Prog
	for _, program := range file.Progs {
		if program.Type != elf.PT_LOAD {
			continue
		}
		if program.Filesz > program.Memsz || program.Filesz > math.MaxUint64-program.Off || program.Memsz > math.MaxUint64-program.Vaddr {
			return nil, fmt.Errorf("invalid PT_LOAD range: %w", target.ErrOverflow)
		}
		if program.Vaddr%page != program.Off%page {
			return nil, fmt.Errorf("PT_LOAD page congruence: %w", target.ErrInvalidArgument)
		}
		if program.Align > 1 && (program.Align&(program.Align-1) != 0 || program.Vaddr%program.Align != program.Off%program.Align) {
			return nil, fmt.Errorf("PT_LOAD alignment: %w", target.ErrInvalidArgument)
		}
		if program.Filesz != 0 {
			loads = append(loads, program)
		}
	}
	if len(loads) == 0 {
		return nil, fmt.Errorf("no file-backed PT_LOAD bytes: %w", target.ErrUnavailable)
	}
	return loads, nil
}

func validateELFLoadBias(file *elf.File, mappings []procMap, page, bias uint64) error {
	loads, err := elfLoadSegments(file, page)
	if err != nil {
		return err
	}
	if bias%page != 0 || file.Type == elf.ET_EXEC && bias != 0 {
		return fmt.Errorf("invalid ELF load bias %#x: %w", bias, target.ErrInvalidArgument)
	}
	for _, program := range loads {
		if program.Vaddr > math.MaxUint64-bias || program.Memsz > math.MaxUint64-(bias+program.Vaddr) {
			return target.ErrOverflow
		}
		begin := bias + program.Vaddr
		end := begin + program.Filesz
		for cursor := begin; cursor < end; {
			next := cursor
			for _, mapping := range mappings {
				if uint64(mapping.Start) > cursor || uint64(mapping.End) <= cursor || mapping.Start >= mapping.End {
					continue
				}
				delta := cursor - uint64(mapping.Start)
				if delta > math.MaxUint64-mapping.Offset || mapping.Offset+delta != program.Off+(cursor-begin) {
					continue
				}
				next = max(next, min(end, uint64(mapping.End)))
			}
			if next == cursor {
				return fmt.Errorf("PT_LOAD at %#x is not covered by matching file offsets: %w", cursor, target.ErrUnavailable)
			}
			cursor = next
		}
	}
	return nil
}

func mappedELFLoadBias(file *elf.File, mappings []procMap, page uint64) (uint64, error) {
	loads, err := elfLoadSegments(file, page)
	if err != nil {
		return 0, err
	}
	var candidates []uint64
	seen := make(map[uint64]bool)
	for _, program := range loads {
		fileBase, virtualBase := program.Off&^(page-1), program.Vaddr&^(page-1)
		fileEnd := program.Off + program.Filesz
		for _, mapping := range mappings {
			if mapping.Start >= mapping.End {
				return 0, target.ErrInvalidArgument
			}
			length := uint64(mapping.End - mapping.Start)
			if length > math.MaxUint64-mapping.Offset {
				return 0, target.ErrOverflow
			}
			overlap := max(fileBase, mapping.Offset)
			if overlap >= min(fileEnd, mapping.Offset+length) {
				continue
			}
			actual := uint64(mapping.Start) + overlap - mapping.Offset
			if overlap-fileBase > math.MaxUint64-virtualBase {
				return 0, target.ErrOverflow
			}
			virtual := virtualBase + overlap - fileBase
			if actual < virtual {
				continue
			}
			bias := actual - virtual
			if seen[bias] {
				continue
			}
			seen[bias] = true
			if len(seen) > 4096 {
				return 0, fmt.Errorf("too many ELF load-bias candidates: %w", target.ErrUnsupported)
			}
			if validateELFLoadBias(file, mappings, page, bias) == nil {
				candidates = append(candidates, bias)
			}
		}
	}
	if len(candidates) == 0 {
		return 0, fmt.Errorf("no proven PT_LOAD mapping: %w", target.ErrUnavailable)
	}
	if len(candidates) != 1 {
		return 0, fmt.Errorf("%d proven ELF load biases: %w", len(candidates), target.ErrAmbiguous)
	}
	return candidates[0], nil
}

func parseELFModuleArguments(arguments []string, allowFile bool) (elfModuleSelection, string, error) {
	if len(arguments) == 0 {
		return elfModuleSelection{}, "", nil
	}
	if len(arguments) == 1 && arguments[0] == "all" {
		return elfModuleSelection{All: true}, "", nil
	}
	if len(arguments) == 2 && arguments[0] == "--module" && arguments[1] != "" && !strings.ContainsRune(arguments[1], 0) {
		return elfModuleSelection{Name: arguments[1]}, "", nil
	}
	if allowFile && len(arguments) == 2 && arguments[0] == "--file" && arguments[1] != "" && !strings.ContainsRune(arguments[1], 0) {
		return elfModuleSelection{}, arguments[1], nil
	}
	return elfModuleSelection{}, "", fmt.Errorf("expected all or --module EXACT%s: %w", map[bool]string{true: " or --file PATH"}[allowFile], target.ErrInvalidArgument)
}
