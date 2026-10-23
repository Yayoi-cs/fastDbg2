package debugger

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"fastdbg2/target"

	"golang.org/x/sys/unix"
)

func procTestDirectory(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".cache", "fastdbg-amd64-command-port", "process"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(root, "test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return dir
}

func procStatFixture(pid int, name string, start uint64) string {
	fields := []string{"t", "11", "22", "33", "0", "-1"}
	for len(fields) < 19 {
		fields = append(fields, "0")
	}
	fields = append(fields, strconv.FormatUint(start, 10), "0", "0")
	return fmt.Sprintf("%d (%s) %s\n", pid, name, strings.Join(fields, " "))
}

func TestProcMapsStrictParsing(t *testing.T) {
	data := "00400000-00401000 r-xp 00000000 08:01 42 /a path \\012 name\n00401000-00402000 rw-s 00001000 00:00 0\n"
	maps, err := parseProcMaps([]byte(data))
	if err != nil || len(maps) != 2 {
		t.Fatalf("maps=%+v err=%v", maps, err)
	}
	if maps[0].Start != 0x400000 || maps[0].End != 0x401000 || maps[0].Offset != 0 || maps[0].DevMajor != 8 || maps[0].DevMinor != 1 || maps[0].Inode != 42 || !maps[0].Read || !maps[0].Execute || maps[0].Write || !maps[0].Private || maps[0].Path != `/a path \012 name` {
		t.Fatalf("first=%+v", maps[0])
	}
	if maps[1].permissions() != "rw-s" || maps[1].Path != "" {
		t.Fatalf("second=%+v", maps[1])
	}
	if empty, err := parseProcMaps(nil); err != nil || len(empty) != 0 {
		t.Fatalf("empty=%v %v", empty, err)
	}
	for _, input := range []string{
		"1000-2000 r-xp 0 00:00 0", "1000-2000 r-xp 0 00:00 0\x00\n", "1000-1000 r-xp 0 00:00 0\n",
		"2000-1000 r-xp 0 00:00 0\n", "1000-2000 r-xq 0 00:00 0\n", "1000-2000 ax-p 0 00:00 0\n",
		"1000-2000 r-xp 0 ff 0\n", "1000-2000 r-xp 0 100000000:00 0\n", "1000-2000 r-xp 0 00:00 -1\n",
		"1000-3000 r-xp 0 00:00 0\n2000-4000 rw-p 0 00:00 0\n", "\n", "1000-2000 r-xp\n",
	} {
		if parsed, err := parseProcMaps([]byte(input)); err == nil || parsed != nil {
			t.Errorf("accepted %q: %+v %v", input, parsed, err)
		}
	}
}

func TestProcStatHandlesExactTaskNameAndIdentity(t *testing.T) {
	data := procStatFixture(123, "a ) \\ b\n\x1b[31m", 987)
	stat, err := parseProcStat([]byte(data))
	if err != nil || stat.PID != 123 || stat.StartTime != 987 || stat.Parent != 11 || stat.Group != 22 || stat.Session != 33 || stat.TTYGroup != -1 || stat.Name != "a ) \\ b\n\x1b[31m" {
		t.Fatalf("stat=%+v err=%v", stat, err)
	}
	for _, input := range []string{"", "1 bad\n", "0 (x) t 0\n", "-1 (x) t 0\n", "1 () t 0\n", strings.Replace(data, "987", "bad", 1)} {
		if _, err := parseProcStat([]byte(input)); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
}

func TestProcStatusAndFDInfoParsing(t *testing.T) {
	status, err := parseProcStatus([]byte("Name:\ta\\n b\nTgid:\t123\n"))
	if err != nil || status["Name"] != `a\n b` || status["Tgid"] != "123" {
		t.Fatalf("status=%v err=%v", status, err)
	}
	for _, input := range []string{"", "Name:\tx", "Name\tx\n", "Name:\tx\nName:\ty\n", "\x00:\tx\n"} {
		if _, err := parseProcStatus([]byte(input)); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
	fdinfo := "pos:\t0\nflags:\t02000002\nmnt_id:\t1\nino:\t42\ntfd: 5 events: 19\ntfd: 6 events: 19\n"
	info, err := parseProcFDInfo([]byte(fdinfo))
	if err != nil || len(info) != 4 || info["flags"] != "02000002" {
		t.Fatalf("fdinfo=%v err=%v", info, err)
	}
	for _, input := range []string{"", "pos:\t0\n", fdinfo + "ino:\t43\n", strings.Replace(fdinfo, "02000002", "09", 1)} {
		if _, err := parseProcFDInfo([]byte(input)); err == nil {
			t.Errorf("accepted fdinfo %q", input)
		}
	}
}

func TestProcIdentityAndReadBounds(t *testing.T) {
	dir := procTestDirectory(t)
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(procStatFixture(123, "x", 42)), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	p := &stoppedProc{ctx: context.Background(), dir: file, identity: procStat{PID: 123, StartTime: 42}}
	if err := p.verifyIdentity(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(procStatFixture(123, "x", 43)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.verifyIdentity(); !errors.Is(err, target.ErrStale) {
		t.Fatalf("identity error=%v", err)
	}
	for _, path := range []string{"", ".", "..", "../stat", "/etc/passwd", "x/../../stat", "a/./b", "a\x00"} {
		if _, err := p.openFile(path); !errors.Is(err, target.ErrInvalidArgument) {
			t.Errorf("open %q: %v", path, err)
		}
		if _, err := p.readlink(path); !errors.Is(err, target.ErrInvalidArgument) {
			t.Errorf("link %q: %v", path, err)
		}
	}
	large, err := os.Create(filepath.Join(dir, "large"))
	if err != nil {
		t.Fatal(err)
	}
	if err := large.Truncate(maxProcBytes + 1); err != nil {
		t.Fatal(err)
	}
	large.Close()
	if _, err := p.readFile("large"); !errors.Is(err, target.ErrOverflow) {
		t.Fatalf("large read=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.ctx = ctx
	if _, err := p.readFile("stat"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled read=%v", err)
	}
}

func TestProcMapSnapshotIsImmutableAndRevalidated(t *testing.T) {
	dir := procTestDirectory(t)
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(procStatFixture(123, "x", 42)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "maps"), []byte("1000-2000 r-xp 0 00:00 0 /original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	p := &stoppedProc{ctx: context.Background(), dir: file, identity: procStat{PID: 123, StartTime: 42}}
	maps, err := p.maps()
	if err != nil {
		t.Fatal(err)
	}
	maps[0].Path = "/modified"
	again, err := p.maps()
	if err != nil || again[0].Path != "/original" {
		t.Fatalf("maps cache mutated: %+v error=%v", again, err)
	}
	if err := p.verifyIdentity(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "maps"), []byte("1000-2000 rwxp 0 00:00 0 /original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.verifyIdentity(); !errors.Is(err, target.ErrStale) {
		t.Fatalf("changed map error=%v", err)
	}
}

func TestProcMappedFileFallbackRequiresExactDeviceAndInode(t *testing.T) {
	dir := procTestDirectory(t)
	root := filepath.Join(dir, "filesystem")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root, filepath.Join(dir, "root")); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(root, "mapped")
	if err := os.WriteFile(name, []byte("exact"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Stat(name, &stat); err != nil {
		t.Fatal(err)
	}
	directory, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	p := &stoppedProc{ctx: context.Background(), dir: directory}
	mapping := procMap{Start: 0x1000, End: 0x2000, Inode: stat.Ino, DevMajor: unix.Major(uint64(stat.Dev)), DevMinor: unix.Minor(uint64(stat.Dev)), Path: "/mapped"}
	file, err := p.openMappedFile(mapping)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(file)
	file.Close()
	if err != nil || string(data) != "exact" {
		t.Fatalf("data=%q err=%v", data, err)
	}
	mapping.Inode++
	if file, err := p.openMappedFile(mapping); !errors.Is(err, target.ErrUnavailable) || file != nil {
		t.Fatalf("mismatch file=%v err=%v", file, err)
	}
	mapping.Inode--
	mapping.Path += " (deleted)"
	if file, err := p.openMappedFile(mapping); err == nil || file != nil {
		t.Fatalf("deleted strip fallback: file=%v err=%v", file, err)
	}
	if err := os.Rename(name, name+".old"); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(name, 0o600); err != nil {
		t.Fatal(err)
	}
	mapping.Path = "/mapped"
	if file, err := p.openMappedFile(mapping); !errors.Is(err, target.ErrUnavailable) || file != nil {
		t.Fatalf("FIFO replacement file=%v err=%v", file, err)
	}
}

func TestProcMappedPathEscapesNeedProvenIdentity(t *testing.T) {
	for _, name := range []string{"has\nnewline", `has\012literal`} {
		t.Run(strconv.Quote(name), func(t *testing.T) {
			dir := procTestDirectory(t)
			root := filepath.Join(dir, "filesystem")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(root, filepath.Join(dir, "root")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, name), []byte("mapped"), 0o600); err != nil {
				t.Fatal(err)
			}
			var stat unix.Stat_t
			if err := unix.Stat(filepath.Join(root, name), &stat); err != nil {
				t.Fatal(err)
			}
			directory, err := os.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer directory.Close()
			p := &stoppedProc{ctx: context.Background(), dir: directory}
			mapping := procMap{Start: 0x1000, End: 0x2000, Inode: stat.Ino, DevMajor: unix.Major(uint64(stat.Dev)), DevMinor: unix.Minor(uint64(stat.Dev)), Path: "/" + strings.ReplaceAll(name, "\n", `\012`)}
			file, err := p.openMappedFile(mapping)
			if err != nil {
				t.Fatal(err)
			}
			file.Close()
		})
	}
}

func TestProcSuperblockMetadataCannotReplaceFileIdentity(t *testing.T) {
	dir := procTestDirectory(t)
	root := filepath.Join(dir, "filesystem")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root, filepath.Join(dir, "root")); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(filepath.Join(root, "candidate"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var stat unix.Statx_t
	if err := unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_INO|unix.STATX_MNT_ID, &stat); err != nil {
		t.Fatal(err)
	}
	deviceMajor, deviceMinor := uint32(8), uint32(123)
	if stat.Dev_major == deviceMajor && stat.Dev_minor == deviceMinor {
		deviceMinor++
	}
	data := fmt.Sprintf("%d 1 %d:%d /subvolume-a / rw - btrfs /dev/test rw,subvolid=123\n", stat.Mnt_id, deviceMajor, deviceMinor)
	if err := os.WriteFile(filepath.Join(dir, "mountinfo"), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	directory, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	p := &stoppedProc{ctx: context.Background(), dir: directory}
	major, minor, inode, err := p.fileSuperblockMetadata(file)
	if err != nil || major != deviceMajor || minor != deviceMinor || inode != stat.Ino {
		t.Fatalf("metadata=%d:%d inode=%d error=%v", major, minor, inode, err)
	}
	mapping := procMap{Start: 0x1000, End: 0x2000, Inode: inode, DevMajor: major, DevMinor: minor, Path: "/candidate"}
	if opened, err := p.openMappedFile(mapping); opened != nil || !errors.Is(err, target.ErrUnavailable) || errors.Is(err, target.ErrStale) {
		t.Fatalf("metadata-only match accepted: file=%v err=%v", opened, err)
	}
}

func TestProcDirectMappedFileUsesExactVMAAnchor(t *testing.T) {
	dir := procTestDirectory(t)
	if err := os.Mkdir(filepath.Join(dir, "map_files"), 0o700); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(dir, "source")
	if err := os.WriteFile(name, []byte("pinned-source"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Stat(name, &stat); err != nil {
		t.Fatal(err)
	}
	mapping := procMap{Start: 0x1000, End: 0x2000, Inode: stat.Ino, DevMajor: 8, DevMinor: 123, Read: true, Private: true, Path: "/source"}
	if unix.Major(uint64(stat.Dev)) == mapping.DevMajor && unix.Minor(uint64(stat.Dev)) == mapping.DevMinor {
		mapping.DevMinor++
	}
	data := fmt.Sprintf("1000-2000 r--p 0 %x:%x %d /source\n", mapping.DevMajor, mapping.DevMinor, mapping.Inode)
	if err := os.WriteFile(filepath.Join(dir, "maps"), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(name, filepath.Join(dir, "map_files", "1000-2000")); err != nil {
		t.Fatal(err)
	}
	directory, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	p := &stoppedProc{ctx: context.Background(), dir: directory}
	file, err := p.openMappedFile(mapping)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := io.ReadAll(file)
	file.Close()
	if err != nil || string(actual) != "pinned-source" {
		t.Fatalf("source=%q err=%v", actual, err)
	}
	mapping.Offset = 4096
	if file, err := p.openMappedFile(mapping); file != nil || !errors.Is(err, target.ErrStale) {
		t.Fatalf("mismatched VMA accepted: file=%v err=%v", file, err)
	}
}

func TestProcMissingMappingAuthorityIsTypedUnavailable(t *testing.T) {
	dir := procTestDirectory(t)
	directory, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	p := &stoppedProc{ctx: context.Background(), dir: directory}
	file, err := p.openMappedFile(procMap{Start: 0x1000, End: 0x2000, Inode: 42})
	if file != nil || !errors.Is(err, target.ErrUnavailable) || !errors.Is(err, unix.ENOENT) {
		t.Fatalf("file=%v err=%v", file, err)
	}
}

func TestProcMountInfoParsesExactMountIDs(t *testing.T) {
	input := "40 1 0:33 /@ / rw,noatime shared:1 - btrfs /dev/example rw,subvolid=256\n41 40 8:12 / /other\\040dir rw - ext4 /dev/other rw\n"
	devices, err := parseProcMountDevices([]byte(input))
	if err != nil || devices[40] != [2]uint32{0, 33} || devices[41] != [2]uint32{8, 12} {
		t.Fatalf("devices=%v err=%v", devices, err)
	}
	for _, bad := range []string{"", "40 1 0:33 / / rw\n", "0 1 0:33 / / rw - btrfs /dev/x rw\n", input + strings.Split(input, "\n")[0] + "\n", "40 1 bad / / rw - btrfs /dev/x rw\n"} {
		if _, err := parseProcMountDevices([]byte(bad)); err == nil {
			t.Errorf("accepted mountinfo %q", bad)
		}
	}
}

func TestProcSnapshotProofRejectsMutationAndCancellation(t *testing.T) {
	for _, mutation := range []string{"memory", "sequence", "thread", "cancel"} {
		t.Run(mutation, func(t *testing.T) {
			c, s := runningController(t, io.Discard)
			s.pid = os.Getpid()
			s.snapshot.Threads[0].TID = s.pid
			snapshot := s.snapshot
			thread := snapshot.Threads[0]
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			called := false
			err := c.withStoppedProc(ctx, snapshot, thread, func(p *stoppedProc) error {
				called = true
				if p.identity.PID != os.Getpid() {
					t.Fatalf("proc=%+v", p.identity)
				}
				switch mutation {
				case "memory":
					s.snapshot.Memory.Revision++
				case "sequence":
					s.snapshot.Sequence++
				case "thread":
					s.snapshot.Threads[0].Token.Registers++
				case "cancel":
					cancel()
				}
				return nil
			})
			if !called || err == nil {
				t.Fatalf("called=%t error=%v", called, err)
			}
			if mutation != "cancel" && !errors.Is(err, target.ErrStale) {
				t.Fatalf("error=%v", err)
			}
			if mutation == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestProcProofDoesNotPublishStaleMaps(t *testing.T) {
	var output bytes.Buffer
	c, s := runningController(t, &output)
	s.pid = os.Getpid()
	s.snapshot.Threads[0].TID = os.Getpid()
	snapshot, thread, err := c.stopped()
	if err != nil {
		t.Fatal(err)
	}
	s.snapshot.Memory.Revision++
	maps, err := c.readProcessMaps(context.Background(), snapshot, thread)
	if maps != nil || !errors.Is(err, target.ErrStale) || output.Len() != 0 {
		t.Fatalf("maps=%v err=%v output=%q", maps, err, output.String())
	}
}

func TestProcOutputEscapesMetadataAndPreservesErrors(t *testing.T) {
	var output bytes.Buffer
	c := &Controller{out: &output}
	source := errors.New("bad\n\x1b[31m")
	err := c.writeProcSections([]procSection{{name: "test", fields: []procField{{label: "link", value: strconv.Quote("/tmp/a\n\x1b[31m")}, {label: "unknown", err: source}}}})
	if !errors.Is(err, source) || strings.ContainsRune(output.String(), '\x1b') || !strings.Contains(output.String(), `\n\x1b`) || !strings.Contains(output.String(), "unavailable") {
		t.Fatalf("output=%q err=%v", output.String(), err)
	}
	c.out = commandFailureWriter{}
	if err := c.writeProcSections([]procSection{{name: "test"}}); err == nil {
		t.Fatal("output failure lost")
	}
}

type commandFailureWriter struct{}

func (commandFailureWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestProcNamespaceAndNetworkParsers(t *testing.T) {
	entries, err := parseIDMap([]byte("0 0 4294967295\n1 2 3\n"))
	if err != nil || !reflect.DeepEqual(entries, [][3]uint64{{0, 0, 4294967295}, {1, 2, 3}}) {
		t.Fatalf("entries=%v error=%v", entries, err)
	}
	for _, input := range []string{"1 2\n", "-1 2 3\n", "1 2 0\n", "4294967295 0 2\n", "0 4294967296 1\n"} {
		if _, err := parseIDMap([]byte(input)); err == nil {
			t.Errorf("accepted map %q", input)
		}
	}
	for _, test := range []struct {
		value string
		v6    bool
		want  string
	}{{"0100007F:1F90", false, "127.0.0.1:8080"}, {"00000000000000000000000001000000:0050", true, "[::1]:80"}} {
		value, err := decodeProcAddress(test.value, test.v6)
		if err != nil || value != test.want {
			t.Errorf("%s=%q %v", test.value, value, err)
		}
	}
	for _, value := range []string{"", "0100007F:GGGG", "0100007F:1", "0000:1234"} {
		if _, err := decodeProcAddress(value, false); err == nil {
			t.Errorf("accepted address %q", value)
		}
	}
	tcp := "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n0: 0100007F:1F90 00000000:0000 0A 0:0 0:0 0 1000 0 42\n"
	records, err := parseProcNetwork("tcp", []byte(tcp))
	if err != nil || len(records[42]) != 1 || !strings.Contains(records[42][0], "127.0.0.1:8080") {
		t.Fatalf("records=%v err=%v", records, err)
	}
	unixData := "Num RefCount Protocol Flags Type St Inode Path\n0: 2 0 0 0001 03 43 /has space\n"
	records, err = parseProcNetwork("unix", []byte(unixData))
	if err != nil || len(records[43]) != 1 || !strings.Contains(records[43][0], `path="/has space"`) {
		t.Fatalf("records=%v err=%v", records, err)
	}
	if _, err := parseProcNetwork("tcp", []byte("header\nmalformed\n")); err == nil {
		t.Fatal("accepted malformed connection")
	}
}

func TestProcNetworkUnavailableTableIsNotAbsence(t *testing.T) {
	dir := procTestDirectory(t)
	if err := os.Mkdir(filepath.Join(dir, "net"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
		if err := os.WriteFile(filepath.Join(dir, "net", name), []byte("sl local_address rem_address st inode\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	file, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	p := &stoppedProc{ctx: context.Background(), dir: file}
	section := readProcNetwork(p, []procFD{{number: 7, path: "socket:[42]"}}, nil)
	var output bytes.Buffer
	c := &Controller{out: &output}
	if err := c.writeProcSections([]procSection{section}); !errors.Is(err, target.ErrUnavailable) {
		t.Fatalf("error=%v output=%s", err, output.String())
	}
	if strings.Contains(output.String(), "not present") || !strings.Contains(output.String(), "incomplete") {
		t.Fatalf("output=%s", output.String())
	}
}

func TestProcCommandsLiveNative(t *testing.T) {
	for _, pie := range []bool{false, true} {
		t.Run(fmt.Sprintf("pie=%t", pie), func(t *testing.T) {
			f := newExpansionIntegration(t, pie)
			f.breakpoint(t)
			ctx := context.Background()
			f.output.Reset()
			if err := f.controller.showVMMap(ctx, ""); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(f.output.String(), "[vmmap]") || !strings.Contains(f.output.String(), `"[stack]"`) || !strings.Contains(f.output.String(), "r-xp") {
				t.Fatalf("maps=%s", f.output.String())
			}
			f.output.Reset()
			if err := f.controller.showFDs(ctx, "0"); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(f.output.String(), "FD 0") || strings.Contains(f.output.String(), "FD 1") {
				t.Fatalf("fds=%s", f.output.String())
			}
			f.output.Reset()
			if err := f.controller.showProcInfo(ctx); err != nil {
				t.Fatalf("proc-info: %v\n%s", err, f.output.String())
			}
			for _, heading := range []string{"[Process Information]", "[Thread Information]", "[Namespace Information]", "[File Descriptors]", "[Network Connections]"} {
				if !strings.Contains(f.output.String(), heading) {
					t.Errorf("missing %s: %s", heading, f.output.String())
				}
			}
			if strings.ContainsRune(f.output.String(), '\x1b') {
				t.Fatal("unexpected terminal escapes")
			}
		})
	}
}
