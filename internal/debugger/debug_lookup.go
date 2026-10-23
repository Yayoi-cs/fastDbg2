package debugger

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"fastdbg2/target"
	"golang.org/x/sys/unix"
)

const maxDebugLookupCandidates = 32
const maxDebugLookupCompareBytes = 2 << 30

type elfDebugLookupPaths struct {
	local   string
	system  string
	clients []string
}

type elfDebugLookupCandidate struct {
	path   string
	target bool
}

type elfDebugLookupError struct {
	err error
}

func (err *elfDebugLookupError) Error() string {
	if err.err == nil {
		return "no local separate ELF debug file: " + target.ErrUnavailable.Error()
	}
	return fmt.Sprintf("local separate ELF debug lookup failed: %v", err.err)
}

func (err *elfDebugLookupError) Unwrap() error { return err.err }

func (err *elfDebugLookupError) Is(other error) bool { return other == target.ErrUnavailable }

func elfDebugLookupMissing(err error) bool {
	lookup, ok := err.(*elfDebugLookupError)
	return ok && lookup.err == nil
}

func localELFDebugLookupPaths() (elfDebugLookupPaths, error) {
	local, err := filepath.Abs(filepath.Join(".cache", "debug-info"))
	if err != nil {
		return elfDebugLookupPaths{}, err
	}
	paths := elfDebugLookupPaths{local: local, system: "/usr/lib/debug"}
	if configured := os.Getenv("DEBUGINFOD_CACHE_PATH"); configured != "" {
		configured, err = filepath.Abs(configured)
		if err != nil {
			return elfDebugLookupPaths{}, err
		}
		paths.clients = append(paths.clients, configured)
	}
	if cache, err := os.UserCacheDir(); err == nil && filepath.IsAbs(cache) {
		paths.clients = append(paths.clients, filepath.Join(cache, "debuginfod_client"))
	}
	return paths, nil
}

func elfDebugLookupCandidates(module *mappedELF, paths elfDebugLookupPaths, targetRoot bool) ([]elfDebugLookupCandidate, error) {
	if module == nil || module.File == nil {
		return nil, target.ErrInvalidArgument
	}
	id, idErr := elfGNUBuildID(module.File)
	if idErr != nil && !errors.Is(idErr, target.ErrUnavailable) {
		return nil, idErr
	}
	link, _, linkErr := elfGNUDebuglink(module.File)
	if linkErr != nil && !errors.Is(linkErr, target.ErrNotFound) {
		return nil, linkErr
	}
	var candidates []elfDebugLookupCandidate
	seen := make(map[elfDebugLookupCandidate]bool)
	add := func(path string, inTarget bool) error {
		if path == "" || !filepath.IsAbs(path) || strings.ContainsRune(path, 0) {
			return fmt.Errorf("invalid local debug lookup path %q: %w", path, target.ErrInvalidArgument)
		}
		if len(path) >= 4096 {
			return fmt.Errorf("local debug lookup path exceeds 4095 bytes: %w", target.ErrUnsupported)
		}
		candidate := elfDebugLookupCandidate{path: path, target: inTarget}
		if !seen[candidate] {
			if len(candidates) == maxDebugLookupCandidates {
				return fmt.Errorf("local debug lookup exceeds %d candidates: %w", maxDebugLookupCandidates, target.ErrUnsupported)
			}
			seen[candidate] = true
			candidates = append(candidates, candidate)
		}
		return nil
	}
	if idErr == nil {
		encoded := hex.EncodeToString(id)
		if len(id) <= 125 {
			for _, root := range []string{paths.local, paths.system} {
				if root == "" {
					continue
				}
				if err := add(filepath.Join(root, ".build-id", encoded[:2], encoded[2:]+".debug"), false); err != nil {
					return nil, err
				}
			}
			if targetRoot && paths.system != "" {
				if err := add(filepath.Join(paths.system, ".build-id", encoded[:2], encoded[2:]+".debug"), true); err != nil {
					return nil, err
				}
			}
		}
		if len(id) <= 127 {
			for _, root := range paths.clients {
				if err := add(filepath.Join(root, encoded, "debuginfo"), false); err != nil {
					return nil, err
				}
			}
		}
		if len(candidates) == 0 && linkErr != nil {
			return nil, fmt.Errorf("complete GNU build ID does not fit a configured local debug path: %w", target.ErrUnsupported)
		}
	}
	if linkErr == nil {
		for _, name := range []string{module.Path, module.MetadataPath} {
			if !filepath.IsAbs(name) {
				continue
			}
			directory := filepath.Dir(name)
			names := []string{filepath.Join(directory, link), filepath.Join(directory, ".debug", link)}
			if paths.system != "" {
				names = append(names, filepath.Join(paths.system, strings.TrimPrefix(directory, string(filepath.Separator)), link))
			}
			for _, path := range names {
				if err := add(path, false); err != nil {
					return nil, err
				}
				if targetRoot && name == module.Path {
					if err := add(path, true); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	return candidates, nil
}

func findELFDebugFile(ctx context.Context, proc *stoppedProc, module *mappedELF) (result *associatedDebugELF, err error) {
	if err := contextReady(ctx); err != nil {
		return nil, err
	}
	paths, err := localELFDebugLookupPaths()
	if err != nil {
		return nil, err
	}
	root := -1
	if proc != nil {
		if proc.dir == nil {
			return nil, target.ErrInvalidArgument
		}
		root, err = unix.Openat(int(proc.dir.Fd()), "root", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		defer func() {
			if closeErr := unix.Close(root); closeErr != nil {
				err = errors.Join(err, closeErr)
				if result != nil {
					err = errors.Join(err, result.Source.Close())
					result = nil
				}
			}
		}()
	}
	return findELFDebugFileAt(ctx, module, paths, root)
}

func openELFDebugLookupCandidate(ctx context.Context, candidate elfDebugLookupCandidate, root int) (*os.File, error) {
	if !candidate.target {
		return openRegularELFSource(ctx, candidate.path)
	}
	if root < 0 {
		return nil, target.ErrInvalidArgument
	}
	if err := contextReady(ctx); err != nil {
		return nil, err
	}
	pin, err := unix.Openat2(root, candidate.path, &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_IN_ROOT})
	if err != nil {
		return nil, err
	}
	source, readErr := openPinnedRegularELFSource(ctx, pin, candidate.path)
	if err := errors.Join(readErr, unix.Close(pin), contextReady(ctx)); err != nil {
		if source != nil {
			err = errors.Join(err, source.Close())
		}
		return nil, err
	}
	return source, nil
}

func findELFDebugFileAt(ctx context.Context, module *mappedELF, paths elfDebugLookupPaths, root int) (result *associatedDebugELF, err error) {
	if err := contextReady(ctx); err != nil {
		return nil, err
	}
	candidates, err := elfDebugLookupCandidates(module, paths, root >= 0)
	if err != nil {
		return nil, err
	}
	var accepted *associatedDebugELF
	defer func() {
		if accepted != nil && result == nil {
			err = errors.Join(err, accepted.Source.Close())
		}
	}()
	seen := make(map[mappedELFIdentity]bool)
	var rejected, blocked error
	remaining := int64(maxDebugLookupCompareBytes)
	for _, candidate := range candidates {
		if err := contextReady(ctx); err != nil {
			return nil, err
		}
		label := candidate.path
		if candidate.target {
			label = "target-root:" + label
		}
		source, openErr := openELFDebugLookupCandidate(ctx, candidate, root)
		if openErr != nil {
			if errors.Is(openErr, os.ErrNotExist) || errors.Is(openErr, unix.ENOTDIR) {
				continue
			}
			if runtimeELFFatal(openErr) {
				return nil, openErr
			}
			blocked = errors.Join(blocked, fmt.Errorf("debug candidate %q: %w", label, openErr))
			continue
		}
		identity, identityErr := elfSourceIdentity(source)
		if identityErr != nil {
			return nil, errors.Join(identityErr, source.Close())
		}
		if seen[identity] {
			if err := source.Close(); err != nil {
				return nil, err
			}
			continue
		}
		seen[identity] = true
		info, statErr := source.Stat()
		if statErr != nil {
			return nil, errors.Join(statErr, source.Close())
		}
		if info.Size() < 0 || info.Size() > maxSeparateDebugBytes {
			return nil, errors.Join(fmt.Errorf("debug candidate %q exceeds %d bytes: %w", label, maxSeparateDebugBytes, target.ErrUnsupported), source.Close())
		}
		association, associationErr := associateELFDebugSource(ctx, module, source, label)
		if associationErr != nil {
			if closeErr := source.Close(); closeErr != nil {
				return nil, errors.Join(associationErr, closeErr)
			}
			if runtimeELFFatal(associationErr) {
				return nil, associationErr
			}
			if errors.Is(associationErr, target.ErrUnavailable) && !errors.Is(associationErr, target.ErrInvalidArgument) && !errors.Is(associationErr, target.ErrAmbiguous) {
				rejected = errors.Join(rejected, fmt.Errorf("debug candidate %q: %w", label, associationErr))
			} else {
				blocked = errors.Join(blocked, fmt.Errorf("debug candidate %q: %w", label, associationErr))
			}
			continue
		}
		if accepted == nil {
			accepted = association
			continue
		}
		equal, compareErr := equalELFDebugSources(ctx, accepted.Source, source, &remaining)
		if err := errors.Join(compareErr, source.Close()); err != nil {
			return nil, err
		}
		if !equal {
			return nil, fmt.Errorf("distinct local debug candidates %q and %q satisfy association metadata but differ in content: %w", accepted.Path, label, target.ErrAmbiguous)
		}
	}
	if err := contextReady(ctx); err != nil {
		return nil, err
	}
	if accepted == nil || blocked != nil {
		return nil, &elfDebugLookupError{err: errors.Join(rejected, blocked)}
	}
	return accepted, nil
}

func equalELFDebugSources(ctx context.Context, left, right *os.File, remaining *int64) (bool, error) {
	if left == nil || right == nil || remaining == nil || *remaining < 0 {
		return false, target.ErrInvalidArgument
	}
	leftInfo, leftErr := left.Stat()
	rightInfo, rightErr := right.Stat()
	if err := errors.Join(leftErr, rightErr, contextReady(ctx)); err != nil {
		return false, err
	}
	if leftInfo.Size() != rightInfo.Size() {
		return false, nil
	}
	size := leftInfo.Size()
	if size < 0 || size > maxSeparateDebugBytes || size > *remaining/2 {
		return false, fmt.Errorf("local debug comparison exceeds byte budget: %w", target.ErrUnsupported)
	}
	*remaining -= 2 * size
	leftData, rightData := make([]byte, 64<<10), make([]byte, 64<<10)
	for offset := int64(0); offset < size; {
		if err := contextReady(ctx); err != nil {
			return false, err
		}
		length := min(int64(len(leftData)), size-offset)
		for index, source := range []*os.File{left, right} {
			data := [][]byte{leftData, rightData}[index][:length]
			n, err := source.ReadAt(data, offset)
			if err != nil || n != len(data) {
				return false, errors.Join(err, io.ErrUnexpectedEOF)
			}
		}
		if !bytes.Equal(leftData[:length], rightData[:length]) {
			return false, nil
		}
		offset += length
	}
	for index, source := range []*os.File{left, right} {
		before := []os.FileInfo{leftInfo, rightInfo}[index]
		after, err := source.Stat()
		if err != nil {
			return false, err
		}
		if after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
			return false, fmt.Errorf("local debug candidate changed during comparison: %w", target.ErrStale)
		}
	}
	return true, contextReady(ctx)
}
