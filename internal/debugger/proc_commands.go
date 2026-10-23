package debugger

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"

	"fastdbg2/display"
	"fastdbg2/internal/cli"
	"fastdbg2/target"

	"golang.org/x/sys/unix"
)

type procField struct {
	label string
	value string
	err   error
}

type procSection struct {
	name   string
	fields []procField
}

type procFD struct {
	number int
	path   string
	info   map[string]string
	err    error
}

func (c *Controller) showVMMap(ctx context.Context, rawArgs string) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	args, err := cli.ParseArgs(rawArgs)
	if err != nil {
		return err
	}
	if len(args) > 1 {
		return fmt.Errorf("usage: vmmap [PATH-FILTER]: %w", target.ErrInvalidArgument)
	}
	snapshot, thread, err := c.stopped()
	if err != nil {
		return err
	}
	maps, err := c.readProcessMaps(ctx, snapshot, thread)
	if err != nil {
		return err
	}
	filter := ""
	if len(args) == 1 {
		filter = args[0]
	}
	text, err := renderVMMap(ctx, maps, filter, display.OutputWidth(c.out), c.renderer)
	if err != nil {
		return err
	}
	return c.publishVMMap(ctx, snapshot, thread, text)
}

func (c *Controller) showFDs(ctx context.Context, rawArgs string) error {
	selected := -1
	if rawArgs = strings.TrimSpace(rawArgs); rawArgs != "" {
		var err error
		selected, err = procFDNumber(rawArgs)
		if err != nil {
			return fmt.Errorf("usage: fd [NUMBER]: %w", err)
		}
	}
	snapshot, thread, err := c.stopped()
	if err != nil {
		return err
	}
	var descriptors []procFD
	err = c.withStoppedProc(ctx, snapshot, thread, func(p *stoppedProc) error {
		var err error
		descriptors, err = readProcFDs(p)
		return err
	})
	if err != nil {
		return err
	}
	if selected >= 0 {
		index := slices.IndexFunc(descriptors, func(fd procFD) bool { return fd.number == selected })
		if index < 0 {
			return fmt.Errorf("file descriptor %d: %w", selected, target.ErrNotFound)
		}
		descriptors = descriptors[index : index+1]
	}
	section := procFDSection(descriptors)
	return c.publishProcSections(ctx, snapshot, thread, []procSection{section})
}

func (c *Controller) showProcInfo(ctx context.Context) error {
	snapshot, thread, err := c.stopped()
	if err != nil {
		return err
	}
	var sections []procSection
	err = c.withStoppedProc(ctx, snapshot, thread, func(p *stoppedProc) error {
		status, err := p.status()
		if err != nil {
			return err
		}
		groups := make([][]procSection, 4)
		var descriptors []procFD
		var descriptorErr error
		var workers sync.WaitGroup
		workers.Add(4)
		go func() {
			defer workers.Done()
			groups[0] = readProcMain(p, status)
		}()
		go func() {
			defer workers.Done()
			groups[1] = readProcRelations(p, snapshot)
		}()
		go func() {
			defer workers.Done()
			groups[2] = readProcNamespaces(p, status)
		}()
		go func() {
			defer workers.Done()
			descriptors, descriptorErr = readProcFDs(p)
			if descriptorErr != nil {
				groups[3] = []procSection{{name: "File Descriptors", fields: []procField{{label: "Descriptors", err: descriptorErr}}}}
				return
			}
			groups[3] = []procSection{procFDSection(descriptors)}
		}()
		workers.Wait()
		for _, group := range groups {
			sections = append(sections, group...)
		}
		sections = append(sections, readProcNetwork(p, descriptors, descriptorErr))
		return nil
	})
	if err != nil {
		return err
	}
	return c.publishProcSections(ctx, snapshot, thread, sections)
}

func (c *Controller) writeProcSections(sections []procSection) error {
	view := c.metadataView()
	err := view.procSections(context.Background(), sections)
	return errors.Join(err, c.writef("%s", view.output.String()))
}

func procLinkField(p *stoppedProc, label, name string) procField {
	value, err := p.readlink(name)
	return procField{label: label, value: strconv.Quote(value), err: err}
}

func procCommandLine(p *stoppedProc) procField {
	data, err := p.readFile("cmdline")
	if err != nil {
		return procField{label: "Command Line", err: err}
	}
	if len(data) == 0 {
		return procField{label: "Command Line", value: "[]"}
	}
	if data[len(data)-1] != 0 {
		return procField{label: "Command Line", err: fmt.Errorf("cmdline is not NUL terminated: %w", target.ErrInvalidArgument)}
	}
	return procField{label: "Command Line", value: fmt.Sprintf("%q", strings.Split(string(data[:len(data)-1]), "\x00"))}
}

func readProcMain(p *stoppedProc, status map[string]string) []procSection {
	main := procSection{name: "Process Information", fields: []procField{
		{label: "Selected TID", value: strconv.Itoa(p.identity.PID)},
		{label: "Name", value: strconv.Quote(p.identity.Name)},
		{label: "Kernel State", value: strconv.Quote(string(p.identity.State))},
		{label: "Start Time (clock ticks)", value: strconv.FormatUint(p.identity.StartTime, 10)},
		procLinkField(p, "Executable", "exe"), procCommandLine(p),
		procLinkField(p, "Current Working Directory", "cwd"), procLinkField(p, "Root Directory", "root"),
	}}
	for _, key := range []string{"Tgid", "Pid", "PPid", "TracerPid", "Uid", "Gid", "Groups", "FDSize", "Threads", "Seccomp", "Seccomp_filters", "NoNewPrivs", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		value, ok := status[key]
		field := procField{label: key, value: strconv.Quote(value)}
		if !ok {
			field.err = fmt.Errorf("status field %q: %w", key, target.ErrUnavailable)
		}
		main.fields = append(main.fields, field)
	}
	groups := procSection{name: "Process Groups", fields: []procField{
		{label: "Process Group ID", value: strconv.Itoa(p.identity.Group)},
		{label: "Session ID", value: strconv.Itoa(p.identity.Session)},
		{label: "TTY Process Group ID", value: strconv.Itoa(p.identity.TTYGroup)},
		{label: "TTY Device Number", value: strconv.FormatInt(p.identity.TTY, 10)},
	}}
	if p.identity.TTY != 0 {
		encoded := uint32(p.identity.TTY)
		major := (encoded >> 8) & 0xfff
		minor := (encoded & 0xff) | ((encoded >> 12) & 0xfff00)
		groups.fields = append(groups.fields, procField{label: "TTY Device Major:Minor", value: fmt.Sprintf("%d:%d", major, minor)})
	}
	return []procSection{main, groups}
}

func relatedProcFields(ctx context.Context, pid, expectedParent int) []procField {
	if pid <= 0 {
		return []procField{{label: "Process", value: "none"}}
	}
	p, err := openStoppedProc(ctx, pid)
	if err != nil {
		return []procField{{label: fmt.Sprintf("PID %d", pid), err: err}}
	}
	if expectedParent > 0 && p.identity.Parent != expectedParent {
		return []procField{{label: fmt.Sprintf("PID %d", pid), err: errors.Join(fmt.Errorf("child parent is %d, expected %d: %w", p.identity.Parent, expectedParent, target.ErrStale), p.dir.Close())}}
	}
	fields := []procField{
		{label: "PID", value: strconv.Itoa(pid)},
		{label: "Start Time (clock ticks)", value: strconv.FormatUint(p.identity.StartTime, 10)},
		{label: "Name", value: strconv.Quote(p.identity.Name)},
		procLinkField(p, "Executable", "exe"), procCommandLine(p),
	}
	if err := errors.Join(p.verifyIdentity(), p.dir.Close()); err != nil {
		return []procField{{label: fmt.Sprintf("PID %d", pid), err: err}}
	}
	return fields
}

func readProcRelations(p *stoppedProc, snapshot target.Snapshot) []procSection {
	sections := []procSection{{name: "Parent Process Information", fields: relatedProcFields(p.ctx, p.identity.Parent, 0)}}
	for _, item := range []struct {
		name string
		pid  int
	}{{"Process Group Leader", p.identity.Group}, {"Session Leader", p.identity.Session}, {"TTY Process Group Leader", p.identity.TTYGroup}} {
		sections = append(sections, procSection{name: item.name, fields: relatedProcFields(p.ctx, item.pid, 0)})
	}
	threads := procSection{name: "Thread Information"}
	children := procSection{name: "Child Process Information"}
	seen := make(map[int]bool)
	var childIDs []int
	for _, thread := range snapshot.Threads {
		if thread.Process != snapshot.Process {
			continue
		}
		threads.fields = append(threads.fields, procField{label: fmt.Sprintf("Thread %d", thread.Ref.ID), value: fmt.Sprintf("tid=%d state=%s stop=%s name=%q exiting=%t listening=%t", thread.TID, thread.State, thread.Stop.Reason, thread.Name, thread.Exiting, thread.Listening)})
		data, err := p.readFile(fmt.Sprintf("task/%d/children", thread.TID))
		if err != nil {
			children.fields = append(children.fields, procField{label: fmt.Sprintf("Children of TID %d", thread.TID), err: err})
			continue
		}
		for _, token := range strings.Fields(string(data)) {
			child, err := procPositiveID(token, "child PID")
			if err != nil {
				children.fields = append(children.fields, procField{label: fmt.Sprintf("Children of TID %d", thread.TID), err: err})
				continue
			}
			if !seen[child] {
				seen[child] = true
				childIDs = append(childIDs, child)
			}
		}
	}
	slices.Sort(childIDs)
	children.fields = append(children.fields, procField{label: "Reported Child IDs", value: fmt.Sprint(childIDs)})
	sections = append(sections, children, threads)
	for _, pid := range childIDs {
		sections = append(sections, procSection{name: fmt.Sprintf("Child PID %d", pid), fields: relatedProcFields(p.ctx, pid, p.tgid)})
	}
	data, err := p.readFile("stat")
	var current procStat
	if err == nil {
		current, err = parseProcStat(data)
		if err == nil && (current.Parent != p.identity.Parent || current.Group != p.identity.Group || current.Session != p.identity.Session || current.TTYGroup != p.identity.TTYGroup) {
			err = fmt.Errorf("process relationships changed: %w", target.ErrStale)
		}
	}
	if err != nil {
		return []procSection{{name: "Process Relationships", fields: []procField{{label: "Relationships", err: err}}}}
	}
	return sections
}

func readProcNamespaces(p *stoppedProc, status map[string]string) []procSection {
	namespaces := procSection{name: "Namespace Information"}
	init, initErr := openStoppedProc(p.ctx, 1)
	for _, name := range []string{"cgroup", "ipc", "mnt", "net", "pid", "pid_for_children", "time", "time_for_children", "user", "uts"} {
		value, err := p.readlink("ns/" + name)
		field := procField{label: name, value: strconv.Quote(value), err: err}
		if err == nil {
			if initErr != nil {
				field.value += "; PID 1 comparison unavailable: " + strconv.Quote(initErr.Error())
			} else {
				other, otherErr := init.readlink("ns/" + name)
				if otherErr != nil {
					field.value += "; PID 1 comparison unavailable: " + strconv.Quote(otherErr.Error())
				} else {
					field.value += fmt.Sprintf("; same-as-visible-PID-1=%t", value == other)
				}
			}
		}
		namespaces.fields = append(namespaces.fields, field)
	}
	if init != nil {
		if err := errors.Join(init.verifyIdentity(), init.dir.Close()); err != nil {
			for i := range namespaces.fields {
				namespaces.fields[i].err = errors.Join(namespaces.fields[i].err, err)
			}
		}
	}
	pid := procSection{name: "Pid Namespace Information"}
	for _, key := range []string{"NStgid", "NSpid", "NSpgid", "NSsid"} {
		value, ok := status[key]
		field := procField{label: key, value: strconv.Quote(value)}
		if !ok {
			field.err = fmt.Errorf("status field %q: %w", key, target.ErrUnavailable)
		}
		pid.fields = append(pid.fields, field)
	}
	user := procSection{name: "User Namespace Information"}
	for _, name := range []string{"uid_map", "gid_map"} {
		data, err := p.readFile(name)
		var entries [][3]uint64
		if err == nil {
			entries, err = parseIDMap(data)
		}
		if err != nil {
			user.fields = append(user.fields, procField{label: name, err: err})
			continue
		}
		if len(entries) == 0 {
			user.fields = append(user.fields, procField{label: name, value: "[]"})
		}
		for _, entry := range entries {
			user.fields = append(user.fields, procField{label: name + " inside:outside:count", value: fmt.Sprintf("%d:%d:%d", entry[0], entry[1], entry[2])})
		}
	}
	return []procSection{namespaces, pid, user}
}

func parseIDMap(data []byte) ([][3]uint64, error) {
	var result [][3]uint64
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, fmt.Errorf("invalid user namespace map line %q: %w", line, target.ErrInvalidArgument)
		}
		var entry [3]uint64
		for i := range entry {
			value, err := strconv.ParseUint(fields[i], 10, 32)
			if err != nil {
				return nil, err
			}
			entry[i] = value
		}
		if entry[2] == 0 || entry[0]+entry[2] > 1<<32 || entry[1]+entry[2] > 1<<32 {
			return nil, fmt.Errorf("user namespace map range overflows: %w", target.ErrInvalidArgument)
		}
		result = append(result, entry)
	}
	return result, nil
}

func procFDNumber(value string) (int, error) {
	if value == "" || strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, target.ErrInvalidArgument
	}
	number, err := strconv.ParseUint(value, 10, strconv.IntSize-1)
	if err != nil {
		return 0, errors.Join(target.ErrInvalidArgument, err)
	}
	return int(number), nil
}

func readProcFDs(p *stoppedProc) ([]procFD, error) {
	entries, err := p.entries("fd")
	if err != nil {
		return nil, err
	}
	result := make([]procFD, 0, len(entries))
	for _, entry := range entries {
		number, err := procFDNumber(entry.Name())
		if err != nil {
			return nil, fmt.Errorf("invalid procfs FD entry %q: %w", entry.Name(), err)
		}
		result = append(result, readProcFD(p, number))
	}
	slices.SortFunc(result, func(a, b procFD) int { return a.number - b.number })
	return result, nil
}

func readProcFD(p *stoppedProc, number int) procFD {
	result := procFD{number: number}
	name := "fd/" + strconv.Itoa(number)
	result.path, result.err = p.readlink(name)
	if result.err != nil {
		return result
	}
	fd, err := unix.Openat(int(p.dir.Fd()), name, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		result.err = fmt.Errorf("pin file descriptor %d: %w", number, err)
		return result
	}
	var identity unix.Stat_t
	if err := unix.Fstat(fd, &identity); err != nil {
		result.err = errors.Join(err, unix.Close(fd))
		return result
	}
	infoName := "fdinfo/" + strconv.Itoa(number)
	data, err := p.readFile(infoName)
	if err == nil {
		result.info, err = parseProcFDInfo(data)
	}
	if err == nil {
		inode, parseErr := strconv.ParseUint(result.info["ino"], 10, 64)
		if parseErr != nil || inode != identity.Ino {
			err = errors.Join(fmt.Errorf("file descriptor %d identity changed: %w", number, target.ErrStale), parseErr)
		}
	}
	currentPath, linkErr := p.readlink(name)
	currentInfo, infoErr := p.readFile(infoName)
	if linkErr == nil && currentPath != result.path {
		linkErr = fmt.Errorf("file descriptor %d link changed: %w", number, target.ErrStale)
	}
	if infoErr == nil && string(currentInfo) != string(data) {
		infoErr = fmt.Errorf("file descriptor %d metadata changed: %w", number, target.ErrStale)
	}
	result.err = errors.Join(err, linkErr, infoErr, unix.Close(fd))
	return result
}

func parseProcFDInfo(data []byte) (map[string]string, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return nil, fmt.Errorf("malformed procfs fdinfo: %w", target.ErrInvalidArgument)
	}
	result := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok || name == "" {
			return nil, fmt.Errorf("malformed procfs fdinfo line %q: %w", line, target.ErrInvalidArgument)
		}
		if name != "pos" && name != "flags" && name != "mnt_id" && name != "ino" {
			continue
		}
		if _, found := result[name]; found {
			return nil, fmt.Errorf("duplicate procfs fdinfo key %q: %w", name, target.ErrInvalidArgument)
		}
		value = strings.TrimSpace(value)
		base := 10
		if name == "flags" {
			base = 8
		}
		if _, err := strconv.ParseUint(value, base, 64); err != nil {
			return nil, fmt.Errorf("invalid procfs fdinfo %q: %w", name, err)
		}
		result[name] = value
	}
	for _, key := range []string{"pos", "flags", "mnt_id", "ino"} {
		if _, ok := result[key]; !ok {
			return nil, fmt.Errorf("missing procfs fdinfo field %q: %w", key, target.ErrUnavailable)
		}
	}
	return result, nil
}

func procFDSection(descriptors []procFD) procSection {
	section := procSection{name: "File Descriptors"}
	if len(descriptors) == 0 {
		section.fields = append(section.fields, procField{label: "Descriptors", value: "[]"})
	}
	for _, descriptor := range descriptors {
		value := strconv.Quote(descriptor.path)
		for _, key := range []string{"pos", "flags", "mnt_id", "ino"} {
			if data, ok := descriptor.info[key]; ok {
				value += fmt.Sprintf(" %s=%q", key, data)
			}
		}
		section.fields = append(section.fields, procField{label: fmt.Sprintf("FD %d", descriptor.number), value: value, err: descriptor.err})
	}
	return section
}

func socketInode(name string) (uint64, bool) {
	if !strings.HasPrefix(name, "socket:[") || !strings.HasSuffix(name, "]") {
		return 0, false
	}
	value := strings.TrimSuffix(strings.TrimPrefix(name, "socket:["), "]")
	inode, err := strconv.ParseUint(value, 10, 64)
	return inode, err == nil && inode > 0
}

func readProcNetwork(p *stoppedProc, descriptors []procFD, descriptorErr error) procSection {
	section := procSection{name: "Network Connections"}
	if descriptorErr != nil {
		section.fields = append(section.fields, procField{label: "Socket descriptors", err: descriptorErr})
		return section
	}
	wanted := make(map[uint64]bool)
	for _, descriptor := range descriptors {
		if descriptor.err != nil {
			section.fields = append(section.fields, procField{label: fmt.Sprintf("FD %d socket identity", descriptor.number), err: descriptor.err})
			continue
		}
		if inode, ok := socketInode(descriptor.path); ok {
			wanted[inode] = true
		}
	}
	if len(wanted) == 0 {
		section.fields = append(section.fields, procField{label: "Reported socket inodes", value: "[]"})
		return section
	}
	connections := make(map[uint64][]string)
	incomplete := false
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6", "unix"} {
		data, err := p.readFile("net/" + name)
		var records map[uint64][]string
		if err == nil {
			records, err = parseProcNetwork(name, data)
		}
		if err != nil {
			incomplete = true
			section.fields = append(section.fields, procField{label: name + " table", err: err})
			continue
		}
		for inode, values := range records {
			if wanted[inode] {
				connections[inode] = append(connections[inode], values...)
			}
		}
	}
	var inodes []uint64
	for inode := range wanted {
		inodes = append(inodes, inode)
	}
	slices.Sort(inodes)
	for _, inode := range inodes {
		values := connections[inode]
		if len(values) == 0 {
			if incomplete {
				section.fields = append(section.fields, procField{label: fmt.Sprintf("Socket inode %d", inode), err: fmt.Errorf("connection tables are incomplete: %w", target.ErrUnavailable)})
				continue
			}
			values = []string{"not present in the tcp/tcp6/udp/udp6/unix tables"}
		}
		for _, value := range values {
			section.fields = append(section.fields, procField{label: fmt.Sprintf("Socket inode %d", inode), value: value})
		}
	}
	return section
}

func parseProcNetwork(protocol string, data []byte) (map[uint64][]string, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return nil, fmt.Errorf("invalid procfs %s table: %w", protocol, target.ErrInvalidArgument)
	}
	if protocol != "tcp" && protocol != "tcp6" && protocol != "udp" && protocol != "udp6" && protocol != "unix" {
		return nil, target.ErrInvalidArgument
	}
	result := make(map[uint64][]string)
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	header := strings.Fields(lines[0])
	if protocol == "unix" {
		want := []string{"Num", "RefCount", "Protocol", "Flags", "Type", "St", "Inode", "Path"}
		if !slices.Equal(header, want) {
			return nil, fmt.Errorf("invalid procfs unix header: %w", target.ErrInvalidArgument)
		}
	} else if len(header) < 4 || header[0] != "sl" || header[1] != "local_address" || (header[2] != "rem_address" && header[2] != "remote_address") || header[3] != "st" || !slices.Contains(header, "inode") {
		return nil, fmt.Errorf("invalid procfs %s header: %w", protocol, target.ErrInvalidArgument)
	}
	for index, line := range lines[1:] {
		fields := strings.Fields(line)
		if protocol == "unix" {
			if len(fields) < 7 {
				return nil, fmt.Errorf("invalid procfs unix line %d: %w", index+2, target.ErrInvalidArgument)
			}
			inode, err := strconv.ParseUint(fields[6], 10, 64)
			if err != nil {
				return nil, err
			}
			var path string
			if len(fields) > 7 {
				rest := line
				for range 7 {
					rest = strings.TrimLeft(rest, " \t")
					end := strings.IndexAny(rest, " \t")
					if end < 0 {
						return nil, target.ErrInvalidArgument
					}
					rest = rest[end:]
				}
				path = strings.TrimLeft(rest, " \t")
			}
			result[inode] = append(result[inode], fmt.Sprintf("unix type=%q state=%q flags=%q path=%q", fields[4], fields[5], fields[3], path))
			continue
		}
		if len(fields) < 10 {
			return nil, fmt.Errorf("invalid procfs %s line %d: %w", protocol, index+2, target.ErrInvalidArgument)
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			return nil, err
		}
		local, err := decodeProcAddress(fields[1], strings.HasSuffix(protocol, "6"))
		if err != nil {
			return nil, err
		}
		remote, err := decodeProcAddress(fields[2], strings.HasSuffix(protocol, "6"))
		if err != nil {
			return nil, err
		}
		state, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil || len(fields[3]) != 2 {
			return nil, errors.Join(target.ErrInvalidArgument, err)
		}
		result[inode] = append(result[inode], fmt.Sprintf("%s %s -> %s state=0x%02x", protocol, local, remote, state))
	}
	return result, nil
}

func decodeProcAddress(value string, ipv6 bool) (string, error) {
	address, port, ok := strings.Cut(value, ":")
	if !ok || len(port) != 4 {
		return "", fmt.Errorf("invalid procfs network address %q: %w", value, target.ErrInvalidArgument)
	}
	raw, err := hex.DecodeString(address)
	if err != nil || (!ipv6 && len(raw) != 4) || (ipv6 && len(raw) != 16) {
		return "", errors.Join(target.ErrInvalidArgument, err)
	}
	for i := 0; i < len(raw); i += 4 {
		raw[i], raw[i+3] = raw[i+3], raw[i]
		raw[i+1], raw[i+2] = raw[i+2], raw[i+1]
	}
	number, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(net.IP(raw).String(), strconv.FormatUint(number, 10)), nil
}
