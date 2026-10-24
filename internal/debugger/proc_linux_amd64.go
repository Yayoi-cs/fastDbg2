package debugger

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"

	"fastdbg2/target"

	"golang.org/x/sys/unix"
)

const maxProcBytes = 32 << 20

type procMap struct {
	Start    target.Address
	End      target.Address
	Offset   uint64
	Inode    uint64
	DevMajor uint32
	DevMinor uint32
	Read     bool
	Write    bool
	Execute  bool
	Private  bool
	Path     string
}

func (m procMap) permissions() string {
	value := []byte("---s")
	if m.Read {
		value[0] = 'r'
	}
	if m.Write {
		value[1] = 'w'
	}
	if m.Execute {
		value[2] = 'x'
	}
	if m.Private {
		value[3] = 'p'
	}
	return string(value)
}

type procStat struct {
	PID       int
	Name      string
	State     byte
	Parent    int
	Group     int
	Session   int
	TTY       int64
	TTYGroup  int
	StartTime uint64
}

type stoppedProc struct {
	ctx          context.Context
	dir          *os.File
	identity     procStat
	tgid         int
	mountOnce    sync.Once
	mountData    []byte
	mountDevices map[uint64][2]uint32
	mountErr     error
	mapsOnce     sync.Once
	mapsData     []byte
	mapsEntries  []procMap
	mapsErr      error
}

func (c *Controller) verifyProcSnapshot(snapshot target.Snapshot, thread target.ThreadInfo) error {
	if c == nil || c.session == nil {
		return target.ErrInvalidState
	}
	if c.active != nil {
		return target.ErrBusy
	}
	if err := validateImageSnapshot(snapshot, thread); err != nil {
		return err
	}
	if _, err := c.session.ReadThreadRegisters(thread.Token); err != nil {
		return fmt.Errorf("validate selected thread token: %w", err)
	}
	current, err := c.session.Snapshot()
	if err != nil {
		return err
	}
	if current.Sequence != snapshot.Sequence || current.Memory != snapshot.Memory || current.Process != snapshot.Process || current.State != snapshot.State || current.Architecture != snapshot.Architecture {
		return fmt.Errorf("process snapshot changed while reading procfs: %w", target.ErrStale)
	}
	return validateImageSnapshot(current, thread)
}

func (c *Controller) withStoppedProc(ctx context.Context, snapshot target.Snapshot, thread target.ThreadInfo, read func(*stoppedProc) error) (err error) {
	if _, ok := c.session.(*qemuSession); ok {
		return fmt.Errorf("native process metadata is not guest kernel metadata: %w", target.ErrUnsupported)
	}
	if ctx == nil || read == nil {
		return target.ErrInvalidArgument
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.verifyProcSnapshot(snapshot, thread); err != nil {
		return err
	}
	proc, err := openStoppedProc(ctx, thread.TID)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, proc.dir.Close()) }()
	status, err := proc.status()
	if err != nil {
		return err
	}
	tgid, err := procPositiveID(status["Tgid"], "Tgid")
	if err != nil {
		return err
	}
	if tgid != c.session.PID() {
		return fmt.Errorf("procfs Tgid %d differs from primary PID %d: %w", tgid, c.session.PID(), target.ErrStale)
	}
	proc.tgid = tgid
	readErr := read(proc)
	identityErr := proc.verifyIdentity()
	snapshotErr := c.verifyProcSnapshot(snapshot, thread)
	return errors.Join(readErr, identityErr, snapshotErr, ctx.Err())
}

func openStoppedProc(ctx context.Context, tid int) (*stoppedProc, error) {
	if ctx == nil || tid <= 0 {
		return nil, target.ErrInvalidArgument
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	name := fmt.Sprintf("/proc/%d", tid)
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", name, err)
	}
	p := &stoppedProc{ctx: ctx, dir: os.NewFile(uintptr(fd), name)}
	data, err := p.readFile("stat")
	if err == nil {
		p.identity, err = parseProcStat(data)
		if err == nil && p.identity.PID != tid {
			err = fmt.Errorf("procfs PID %d differs from TID %d: %w", p.identity.PID, tid, target.ErrStale)
		}
	}
	if err != nil {
		return nil, errors.Join(err, p.dir.Close())
	}
	return p, nil
}

func (p *stoppedProc) verifyIdentity() error {
	data, err := p.readFile("stat")
	if err != nil {
		return err
	}
	current, err := parseProcStat(data)
	if err != nil {
		return err
	}
	if current.PID != p.identity.PID || current.StartTime != p.identity.StartTime {
		return fmt.Errorf("procfs task identity changed: %w", target.ErrStale)
	}
	if p.mountData != nil {
		current, err := p.readFile("mountinfo")
		if err != nil {
			return err
		}
		if !bytes.Equal(current, p.mountData) {
			return fmt.Errorf("mount namespace changed while reading mapped files: %w", target.ErrStale)
		}
	}
	if p.mapsData != nil {
		current, err := p.readFile("maps")
		if err != nil {
			return err
		}
		if !bytes.Equal(current, p.mapsData) {
			return fmt.Errorf("process mappings changed while reading procfs: %w", target.ErrStale)
		}
	}
	return nil
}

func validProcName(name string) bool {
	return name != "" && name != "." && !strings.HasPrefix(name, "/") && !strings.ContainsRune(name, 0) && path.Clean(name) == name && name != ".." && !strings.HasPrefix(name, "../")
}

func (p *stoppedProc) openFile(name string) (*os.File, error) {
	if p == nil || p.dir == nil || p.ctx == nil || !validProcName(name) {
		return nil, target.ErrInvalidArgument
	}
	if err := p.ctx.Err(); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(p.dir.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open procfs %q: %w", name, err)
	}
	return os.NewFile(uintptr(fd), p.dir.Name()+"/"+name), nil
}

func (p *stoppedProc) readFile(name string) (data []byte, err error) {
	file, err := p.openFile(name)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	data, err = io.ReadAll(io.LimitReader(file, maxProcBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read procfs %q: %w", name, err)
	}
	if len(data) > maxProcBytes {
		return nil, fmt.Errorf("procfs %q exceeds %d bytes: %w", name, maxProcBytes, target.ErrOverflow)
	}
	if err := p.ctx.Err(); err != nil {
		return nil, err
	}
	return data, nil
}

func (p *stoppedProc) readlink(name string) (string, error) {
	if p == nil || p.dir == nil || p.ctx == nil || !validProcName(name) {
		return "", target.ErrInvalidArgument
	}
	if err := p.ctx.Err(); err != nil {
		return "", err
	}
	for size := 256; size <= maxProcBytes; size *= 2 {
		buffer := make([]byte, size)
		n, err := unix.Readlinkat(int(p.dir.Fd()), name, buffer)
		if err != nil {
			return "", fmt.Errorf("read procfs link %q: %w", name, err)
		}
		if n < len(buffer) {
			if err := p.ctx.Err(); err != nil {
				return "", err
			}
			return string(buffer[:n]), nil
		}
	}
	return "", fmt.Errorf("procfs link %q exceeds %d bytes: %w", name, maxProcBytes, target.ErrOverflow)
}

func (p *stoppedProc) entries(name string) (entries []os.DirEntry, err error) {
	file, err := p.openFile(name)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	entries, err = file.ReadDir(65537)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read procfs directory %q: %w", name, err)
	}
	if len(entries) > 65536 {
		return nil, fmt.Errorf("procfs directory %q exceeds 65536 entries: %w", name, target.ErrOverflow)
	}
	return entries, p.ctx.Err()
}

func (p *stoppedProc) status() (map[string]string, error) {
	data, err := p.readFile("status")
	if err != nil {
		return nil, err
	}
	return parseProcStatus(data)
}

func (p *stoppedProc) maps() ([]procMap, error) {
	if err := p.loadMaps(); err != nil {
		return nil, err
	}
	return slices.Clone(p.mapsEntries), nil
}

func (p *stoppedProc) loadMaps() error {
	p.mapsOnce.Do(func() {
		p.mapsData, p.mapsErr = p.readFile("maps")
		if p.mapsErr == nil {
			p.mapsEntries, p.mapsErr = parseProcMaps(p.mapsData)
		}
	})
	return p.mapsErr
}

func (c *Controller) readProcessMaps(ctx context.Context, snapshot target.Snapshot, thread target.ThreadInfo) ([]procMap, error) {
	if remote, ok := c.session.(*qemuSession); ok {
		return remote.addressWalkMaps(ctx, snapshot, thread)
	}
	var maps []procMap
	err := c.withStoppedProc(ctx, snapshot, thread, func(p *stoppedProc) error {
		var err error
		maps, err = p.maps()
		return err
	})
	if err != nil {
		return nil, err
	}
	return maps, nil
}

func (p *stoppedProc) openMappedFile(mapping procMap) (*os.File, error) {
	if p == nil || p.dir == nil || p.ctx == nil || mapping.Start >= mapping.End || mapping.Inode == 0 {
		return nil, fmt.Errorf("mapping has no file identity: %w", target.ErrInvalidArgument)
	}
	name := fmt.Sprintf("map_files/%x-%x", mapping.Start, mapping.End)
	file, directErr := p.openMappedAt(int(p.dir.Fd()), name, false, mapping)
	if directErr == nil {
		return file, nil
	}
	if errors.Is(directErr, target.ErrStale) || errors.Is(directErr, target.ErrUnsupported) {
		return nil, directErr
	}
	if !strings.HasPrefix(mapping.Path, "/") || strings.ContainsRune(mapping.Path, 0) {
		return nil, directErr
	}
	rootFD, err := unix.Openat(int(p.dir.Fd()), "root", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.Join(directErr, err)
	}
	names := []string{strings.ReplaceAll(mapping.Path, `\012`, "\n")}
	if names[0] != mapping.Path {
		names = append(names, mapping.Path)
	}
	var failures []error
	for _, name := range names {
		file, err = p.openMappedAt(rootFD, name, true, mapping)
		if err == nil {
			if err := unix.Close(rootFD); err != nil {
				return nil, errors.Join(err, file.Close())
			}
			return file, nil
		}
		failures = append(failures, err)
	}
	return nil, errors.Join(directErr, errors.Join(failures...), unix.Close(rootFD))
}

func (p *stoppedProc) openMappedAt(dir int, name string, inRoot bool, mapping procMap) (*os.File, error) {
	if err := p.ctx.Err(); err != nil {
		return nil, err
	}
	var fd int
	var err error
	if inRoot {
		fd, err = unix.Openat2(dir, name, &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_IN_ROOT})
	} else {
		fd, err = unix.Openat(dir, name, unix.O_PATH|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		if !inRoot && (errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.ENOENT)) {
			err = errors.Join(target.ErrUnavailable, err)
		}
		return nil, fmt.Errorf("pin mapped file %q: %w", name, err)
	}
	pinned := os.NewFile(uintptr(fd), name)
	verify := verifyMappedFile
	if !inRoot {
		verify = p.verifyDirectMappedFile
	}
	if err := errors.Join(verify(pinned, mapping), p.ctx.Err()); err != nil {
		return nil, errors.Join(err, pinned.Close())
	}
	readFD, readErr := unix.Open(fmt.Sprintf("/proc/self/fd/%d", fd), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	closeErr := pinned.Close()
	if readErr != nil {
		return nil, errors.Join(fmt.Errorf("read mapped file %q: %w", name, readErr), closeErr)
	}
	file := os.NewFile(uintptr(readFD), name)
	if err := errors.Join(closeErr, verify(file, mapping), p.ctx.Err()); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
}

func (p *stoppedProc) verifyDirectMappedFile(file *os.File, mapping procMap) error {
	if file == nil {
		return target.ErrInvalidArgument
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return err
	}
	if stat.Ino != mapping.Inode {
		return fmt.Errorf("pinned VMA file inode differs from %d: %w", mapping.Inode, target.ErrStale)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("pinned VMA file is not regular: %w", target.ErrUnsupported)
	}
	if err := p.loadMaps(); err != nil {
		return err
	}
	index, found := slices.BinarySearchFunc(p.mapsEntries, mapping.Start, func(current procMap, start target.Address) int {
		return cmp.Compare(current.Start, start)
	})
	if !found {
		return fmt.Errorf("pinned VMA range is absent: %w", target.ErrStale)
	}
	if p.mapsEntries[index] != mapping {
		return fmt.Errorf("pinned VMA metadata changed: %w", target.ErrStale)
	}
	return nil
}

func verifyMappedFile(file *os.File, mapping procMap) error {
	if file == nil {
		return target.ErrInvalidArgument
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return err
	}
	if uint64(stat.Ino) != mapping.Inode || unix.Major(uint64(stat.Dev)) != mapping.DevMajor || unix.Minor(uint64(stat.Dev)) != mapping.DevMinor {
		return fmt.Errorf("candidate file identity differs from mapped %x:%x inode %d: %w", mapping.DevMajor, mapping.DevMinor, mapping.Inode, target.ErrUnavailable)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("mapped file is not regular: %w", target.ErrUnsupported)
	}
	return nil
}

func (p *stoppedProc) fileSuperblockMetadata(file *os.File) (uint32, uint32, uint64, error) {
	if p == nil || p.ctx == nil || file == nil {
		return 0, 0, 0, target.ErrInvalidArgument
	}
	if err := p.ctx.Err(); err != nil {
		return 0, 0, 0, err
	}
	var stat unix.Statx_t
	if err := unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_INO|unix.STATX_MNT_ID, &stat); err != nil {
		return 0, 0, 0, fmt.Errorf("mapped file mount identity: %w", err)
	}
	if stat.Mask&(unix.STATX_INO|unix.STATX_MNT_ID) != unix.STATX_INO|unix.STATX_MNT_ID || stat.Mnt_id == 0 {
		return 0, 0, 0, fmt.Errorf("mapped file mount identity is unavailable: %w", target.ErrUnavailable)
	}
	p.mountOnce.Do(func() {
		p.mountData, p.mountErr = p.readFile("mountinfo")
		if p.mountErr == nil {
			p.mountDevices, p.mountErr = parseProcMountDevices(p.mountData)
		}
	})
	if p.mountErr != nil {
		return 0, 0, 0, p.mountErr
	}
	device, ok := p.mountDevices[stat.Mnt_id]
	if !ok {
		return 0, 0, 0, fmt.Errorf("mapped file mount ID %d is absent from target mountinfo: %w", stat.Mnt_id, target.ErrUnavailable)
	}
	return device[0], device[1], stat.Ino, nil
}

func parseProcMountDevices(data []byte) (map[uint64][2]uint32, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' || bytes.IndexByte(data, 0) >= 0 {
		return nil, fmt.Errorf("malformed procfs mountinfo: %w", target.ErrInvalidArgument)
	}
	result := make(map[uint64][2]uint32)
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		left, right, found := strings.Cut(line, " - ")
		fields := strings.Fields(left)
		if !found || len(fields) < 6 || len(strings.Fields(right)) < 3 {
			return nil, fmt.Errorf("malformed procfs mountinfo line: %w", target.ErrInvalidArgument)
		}
		id, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || id == 0 {
			return nil, errors.Join(target.ErrInvalidArgument, err)
		}
		if _, found := result[id]; found {
			return nil, fmt.Errorf("duplicate mount ID %d: %w", id, target.ErrInvalidArgument)
		}
		if _, err := strconv.ParseUint(fields[1], 10, 64); err != nil {
			return nil, err
		}
		major, minor, found := strings.Cut(fields[2], ":")
		if !found {
			return nil, target.ErrInvalidArgument
		}
		devMajor, err := strconv.ParseUint(major, 10, 32)
		if err != nil {
			return nil, err
		}
		devMinor, err := strconv.ParseUint(minor, 10, 32)
		if err != nil {
			return nil, err
		}
		result[id] = [2]uint32{uint32(devMajor), uint32(devMinor)}
	}
	return result, nil
}

func procPositiveID(value, name string) (int, error) {
	if value == "" || strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, fmt.Errorf("invalid procfs %s %q: %w", name, value, target.ErrInvalidArgument)
	}
	n, err := strconv.ParseUint(value, 10, strconv.IntSize-1)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("invalid procfs %s %q: %w", name, value, errors.Join(target.ErrInvalidArgument, err))
	}
	return int(n), nil
}

func parseProcStat(data []byte) (procStat, error) {
	var result procStat
	text := string(data)
	first := strings.Index(text, " (")
	last := strings.LastIndex(text, ") ")
	if first < 1 || last < first+2 {
		return result, fmt.Errorf("malformed procfs stat: %w", target.ErrInvalidArgument)
	}
	pid, err := procPositiveID(text[:first], "PID")
	if err != nil {
		return result, err
	}
	fields := strings.Fields(text[last+2:])
	if len(fields) < 20 || len(fields[0]) != 1 || !strings.ContainsRune("RSDZTtXxKWPI", rune(fields[0][0])) {
		return result, fmt.Errorf("malformed procfs stat fields: %w", target.ErrInvalidArgument)
	}
	values := make([]int64, 5)
	for i := range values {
		values[i], err = strconv.ParseInt(fields[i+1], 10, 64)
		if err != nil {
			return result, fmt.Errorf("invalid procfs stat field %d: %w", i+4, err)
		}
	}
	for _, i := range []int{0, 1, 2} {
		if values[i] < 0 || uint64(values[i]) > uint64(^uint(0)>>1) {
			return result, fmt.Errorf("invalid procfs stat process ID: %w", target.ErrInvalidArgument)
		}
	}
	if values[4] < -1 || values[4] > int64(^uint(0)>>1) {
		return result, fmt.Errorf("invalid procfs stat TTY group: %w", target.ErrInvalidArgument)
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return result, fmt.Errorf("invalid procfs start time: %w", err)
	}
	return procStat{PID: pid, Name: text[first+2 : last], State: fields[0][0], Parent: int(values[0]), Group: int(values[1]), Session: int(values[2]), TTY: values[3], TTYGroup: int(values[4]), StartTime: start}, nil
}

func parseProcStatus(data []byte) (map[string]string, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' || bytes.IndexByte(data, 0) >= 0 {
		return nil, fmt.Errorf("malformed procfs status: %w", target.ErrInvalidArgument)
	}
	result := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok || name == "" || strings.ContainsAny(name, " \t\r") {
			return nil, fmt.Errorf("malformed procfs status line %q: %w", line, target.ErrInvalidArgument)
		}
		if _, found := result[name]; found {
			return nil, fmt.Errorf("duplicate procfs status key %q: %w", name, target.ErrInvalidArgument)
		}
		result[name] = strings.TrimSpace(value)
	}
	return result, nil
}

func parseProcMaps(data []byte) ([]procMap, error) {
	if len(data) == 0 {
		return []procMap{}, nil
	}
	if data[len(data)-1] != '\n' || bytes.IndexByte(data, 0) >= 0 {
		return nil, fmt.Errorf("malformed procfs maps: %w", target.ErrInvalidArgument)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	result := make([]procMap, 0, len(lines))
	for index, line := range lines {
		fields := make([]string, 5)
		rest := line
		for i := range fields {
			rest = strings.TrimLeft(rest, " \t")
			end := strings.IndexAny(rest, " \t")
			if end < 0 {
				fields[i], rest = rest, ""
			} else {
				fields[i], rest = rest[:end], rest[end:]
			}
		}
		mapping, err := parseProcMapFields(fields, strings.TrimLeft(rest, " \t"))
		if err != nil {
			return nil, fmt.Errorf("procfs maps line %d: %w", index+1, err)
		}
		if len(result) > 0 && mapping.Start < result[len(result)-1].End {
			return nil, fmt.Errorf("procfs maps overlap or are unordered at line %d: %w", index+1, target.ErrInvalidArgument)
		}
		result = append(result, mapping)
	}
	return result, nil
}

func parseProcMapFields(fields []string, name string) (procMap, error) {
	var result procMap
	if len(fields) != 5 {
		return result, target.ErrInvalidArgument
	}
	start, end, ok := strings.Cut(fields[0], "-")
	if !ok {
		return result, target.ErrInvalidArgument
	}
	left, err := strconv.ParseUint(start, 16, 64)
	if err != nil {
		return result, err
	}
	right, err := strconv.ParseUint(end, 16, 64)
	if err != nil || left >= right {
		return result, errors.Join(target.ErrInvalidArgument, err)
	}
	permissions := fields[1]
	if len(permissions) != 4 || !strings.ContainsRune("r-", rune(permissions[0])) || !strings.ContainsRune("w-", rune(permissions[1])) || !strings.ContainsRune("x-", rune(permissions[2])) || !strings.ContainsRune("ps", rune(permissions[3])) {
		return result, fmt.Errorf("invalid permissions %q: %w", permissions, target.ErrInvalidArgument)
	}
	offset, err := strconv.ParseUint(fields[2], 16, 64)
	if err != nil {
		return result, err
	}
	major, minor, ok := strings.Cut(fields[3], ":")
	if !ok {
		return result, target.ErrInvalidArgument
	}
	devMajor, err := strconv.ParseUint(major, 16, 32)
	if err != nil {
		return result, err
	}
	devMinor, err := strconv.ParseUint(minor, 16, 32)
	if err != nil {
		return result, err
	}
	inode, err := strconv.ParseUint(fields[4], 10, 64)
	if err != nil {
		return result, err
	}
	return procMap{Start: target.Address(left), End: target.Address(right), Offset: offset, Inode: inode, DevMajor: uint32(devMajor), DevMinor: uint32(devMinor), Read: permissions[0] == 'r', Write: permissions[1] == 'w', Execute: permissions[2] == 'x', Private: permissions[3] == 'p', Path: name}, nil
}
