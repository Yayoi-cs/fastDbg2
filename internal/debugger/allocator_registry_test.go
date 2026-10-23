package debugger

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"fastdbg2/target"
	"golang.org/x/sys/unix"
)

func allocatorRegistryTestProfile(t testing.TB) allocatorProfile {
	t.Helper()
	profile, err := parseAllocatorProfile([]byte(builtInAllocatorProfile))
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func allocatorRegistryTestData(t testing.TB, profile allocatorProfile) []byte {
	t.Helper()
	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func allocatorRegistryTestWrite(t testing.TB, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAllocatorProfileStrictParserRoundTrip(t *testing.T) {
	profile := allocatorRegistryTestProfile(t)
	data := allocatorRegistryTestData(t, profile)
	got, err := parseAllocatorProfile(append(data, '\n', '\t', ' '))
	if err != nil || !reflect.DeepEqual(got, profile) {
		t.Fatalf("round trip changed profile: error=%v", err)
	}
}

func allocatorProfileStructFields(t *testing.T, data []byte, valueType reflect.Type, path []string, fields *[][]string) {
	t.Helper()
	if valueType.Kind() == reflect.Pointer {
		if bytes.Equal(data, []byte("null")) {
			return
		}
		valueType = valueType.Elem()
	}
	if valueType.Kind() != reflect.Struct && valueType.Kind() != reflect.Map {
		return
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	if valueType.Kind() == reflect.Map {
		var names []string
		for name := range object {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			allocatorProfileStructFields(t, object[name], valueType.Elem(), append(slices.Clone(path), name), fields)
		}
		return
	}
	for index := 0; index < valueType.NumField(); index++ {
		field := valueType.Field(index)
		if !field.IsExported() {
			continue
		}
		name := strings.SplitN(field.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		next := append(slices.Clone(path), name)
		*fields = append(*fields, next)
		allocatorProfileStructFields(t, object[name], field.Type, next, fields)
	}
}

func allocatorProfileRemoveJSONField(t *testing.T, data []byte, path []string) []byte {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	if len(path) == 1 {
		delete(object, path[0])
	} else {
		object[path[0]] = allocatorProfileRemoveJSONField(t, object[path[0]], path[1:])
	}
	result, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestAllocatorProfileStrictParserRequiresEveryStructField(t *testing.T) {
	profile := allocatorRegistryTestProfile(t)
	data := allocatorRegistryTestData(t, profile)
	var fields [][]string
	allocatorProfileStructFields(t, data, reflect.TypeOf(profile), nil, &fields)
	if len(fields) < 100 {
		t.Fatalf("incomplete struct-field inventory: %d", len(fields))
	}
	for _, field := range fields {
		changed := allocatorProfileRemoveJSONField(t, data, field)
		if _, err := parseAllocatorProfile(changed); !errors.Is(err, target.ErrInvalidArgument) || !strings.Contains(err.Error(), "missing allocator profile field") {
			t.Fatalf("omitted %q accepted or silently defaulted: %v", strings.Join(field, "."), err)
		}
	}
}

func TestAllocatorProfileStrictParserRejectsDuplicateAndUnknownFields(t *testing.T) {
	profile := allocatorRegistryTestProfile(t)
	data := string(allocatorRegistryTestData(t, profile))
	symbol, err := json.Marshal(profile.Symbols["main_arena"])
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		data string
	}{
		{"duplicate-root", data[:len(data)-1] + `,"Name":"duplicate"}`},
		{"duplicate-escaped", data[:len(data)-1] + `,"N\u0061me":"duplicate"}`},
		{"case-alias", data[:len(data)-1] + `,"name":"alias"}`},
		{"unknown-root", data[:len(data)-1] + `,"Unknown":123}`},
		{"duplicate-constant", strings.Replace(data, `"Alignment":16`, `"Alignment":16,"Alignment":16`, 1)},
		{"duplicate-map", strings.Replace(data, `"main_arena":`, `"main_arena":`+string(symbol)+`,"main_arena":`, 1)},
		{"unknown-nested", strings.Replace(data, `"offset":`, `"unknown":`, 1)},
		{"case-alias-nested", strings.Replace(data, `"offset":`, `"Offset":`, 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.data == data {
				t.Fatal("test did not change profile")
			}
			if _, err := parseAllocatorProfile([]byte(test.data)); !errors.Is(err, target.ErrInvalidArgument) {
				t.Fatalf("invalid JSON profile accepted: %v", err)
			}
		})
	}
}

func TestAllocatorProfileStrictParserRejectsMalformedValues(t *testing.T) {
	profile := allocatorRegistryTestProfile(t)
	data := string(allocatorRegistryTestData(t, profile))
	name, _ := json.Marshal(profile.Name)
	for _, test := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"root-null", []byte(`null`)},
		{"root-array", []byte(`[]`)},
		{"root-string", []byte(`"profile"`)},
		{"truncated", []byte(data[:len(data)-1])},
		{"trailing-object", []byte(data + `{}`)},
		{"trailing-null", []byte(data + `null`)},
		{"trailing-garbage", []byte(data + `garbage`)},
		{"invalid-utf8", append([]byte(data), 0xff)},
		{"null-string", []byte(strings.Replace(data, `"Name":`+string(name), `"Name":null`, 1))},
		{"null-scalar", []byte(strings.Replace(data, `"Alignment":16`, `"Alignment":null`, 1))},
		{"float-integer", []byte(strings.Replace(data, `"Alignment":16`, `"Alignment":16.0`, 1))},
		{"exponent-integer", []byte(strings.Replace(data, `"Alignment":16`, `"Alignment":16e0`, 1))},
		{"signed-unsigned", []byte(strings.Replace(data, `"Alignment":16`, `"Alignment":-16`, 1))},
		{"overflow-integer", []byte(strings.Replace(data, `"Alignment":16`, `"Alignment":18446744073709551616`, 1))},
		{"wrong-string", []byte(strings.Replace(data, `"Name":`+string(name), `"Name":12`, 1))},
		{"empty-required-name", []byte(strings.Replace(data, `"Name":`+string(name), `"Name":""`, 1))},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseAllocatorProfile(test.data); !errors.Is(err, target.ErrInvalidArgument) {
				t.Fatalf("malformed profile accepted: %v", err)
			}
		})
	}
}

func TestAllocatorProfileStrictParserEnforcesBudgets(t *testing.T) {
	profile := allocatorRegistryTestProfile(t)
	profile.Name = strings.Repeat("x", maxAllocatorProfileStringBytes+1)
	if _, err := parseAllocatorProfile(allocatorRegistryTestData(t, profile)); !errors.Is(err, target.ErrUnsupported) {
		t.Fatalf("unbounded string: %v", err)
	}
	if _, err := parseAllocatorProfile(bytes.Repeat([]byte{' '}, maxAllocatorProfileBytes+1)); !errors.Is(err, target.ErrUnsupported) {
		t.Fatalf("unbounded bytes: %v", err)
	}
	profile = allocatorRegistryTestProfile(t)
	for index := 0; index < maxAllocatorProfileObjectFields; index++ {
		profile.Symbols["extra"+strconv.Itoa(index)] = allocatorSymbol{Size: 8, Type: 1}
	}
	if _, err := parseAllocatorProfile(allocatorRegistryTestData(t, profile)); !errors.Is(err, target.ErrUnsupported) {
		t.Fatalf("unbounded fields: %v", err)
	}
	type recursive struct{ Next *recursive }
	for _, test := range []struct {
		name   string
		data   string
		typeOf reflect.Type
	}{
		{"depth", strings.Repeat(`{"Next":`, maxAllocatorProfileDepth+2) + `null` + strings.Repeat("}", maxAllocatorProfileDepth+2), reflect.TypeOf(recursive{})},
		{"elements", `[` + strings.Repeat("0,", maxAllocatorProfileFields) + `0]`, reflect.TypeOf([]uint64{})},
	} {
		t.Run(test.name, func(t *testing.T) {
			decoder := json.NewDecoder(strings.NewReader(test.data))
			decoder.UseNumber()
			remaining := maxAllocatorProfileFields
			if err := scanAllocatorProfileJSON(decoder, test.typeOf, 0, &remaining); !errors.Is(err, target.ErrUnsupported) {
				t.Fatalf("unbounded recursive metadata: %v", err)
			}
		})
	}
}

func TestAllocatorRegistryPathUsesExactLowercasePairAndLiteralDirectory(t *testing.T) {
	profile := allocatorRegistryTestProfile(t)
	directory := elfSourceTestDirectory(t)
	t.Chdir(directory)
	t.Setenv("FASTDBG_ALLOCATOR_PROFILE_DIR", "")
	path, err := allocatorRegistryPath(profile.LibcBuildID, profile.LoaderBuildID)
	name := profile.LibcBuildID + "." + profile.LoaderBuildID + ".json"
	if err != nil || path != filepath.Join(directory, ".libc", "profiles", name) {
		t.Fatalf("path=%q error=%v", path, err)
	}
	t.Setenv("FASTDBG_ALLOCATOR_PROFILE_DIR", "$HOME/explicit")
	path, err = allocatorRegistryPath(profile.LibcBuildID, profile.LoaderBuildID)
	if err != nil || path != filepath.Join(directory, "$HOME", "explicit", name) {
		t.Fatalf("environment expansion or path guessing: path=%q error=%v", path, err)
	}
	for _, id := range []string{"", "ab", strings.Repeat("1", 33), strings.Repeat("z", 40), "../" + profile.LibcBuildID, strings.ToUpper(profile.LibcBuildID), strings.Repeat("ab", 129)} {
		if _, err := allocatorRegistryPath(id, profile.LoaderBuildID); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("invalid build ID %q accepted: %v", id, err)
		}
		if _, err := allocatorRegistryPath(profile.LibcBuildID, id); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("invalid loader ID %q accepted: %v", id, err)
		}
	}
	if _, err := allocatorRegistryPath(strings.Repeat("ab", 64), strings.Repeat("cd", 64)); !errors.Is(err, target.ErrUnsupported) {
		t.Fatalf("oversized filename truncated: %v", err)
	}
}

func TestAllocatorRegistryMissingDoesNotScanOrWrite(t *testing.T) {
	profile := allocatorRegistryTestProfile(t)
	directory := elfSourceTestDirectory(t)
	t.Setenv("FASTDBG_ALLOCATOR_PROFILE_DIR", filepath.Join(directory, "missing"))
	result, err := loadAllocatorRegistryProfile(context.Background(), profile.LibcBuildID, profile.LoaderBuildID)
	if result != nil || !errors.Is(err, target.ErrNotFound) {
		t.Fatalf("missing=%+v error=%v", result, err)
	}
	if _, err := os.Stat(filepath.Join(directory, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing registry created: %v", err)
	}
	t.Setenv("FASTDBG_ALLOCATOR_PROFILE_DIR", directory)
	allocatorRegistryTestWrite(t, filepath.Join(directory, profile.LibcBuildID+".json"), allocatorRegistryTestData(t, profile))
	allocatorRegistryTestWrite(t, filepath.Join(directory, "glibc-2.44.json"), allocatorRegistryTestData(t, profile))
	result, err = loadAllocatorRegistryProfile(context.Background(), profile.LibcBuildID, profile.LoaderBuildID)
	if result != nil || !errors.Is(err, target.ErrNotFound) {
		t.Fatalf("nonexact registry candidate inferred: profile=%+v error=%v", result, err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 2 {
		t.Fatalf("registry lookup wrote files: entries=%v error=%v", entries, err)
	}
}

func TestAllocatorRegistryLoadsExactPairAndRejectsWrongMetadata(t *testing.T) {
	profile := allocatorRegistryTestProfile(t)
	directory := elfSourceTestDirectory(t)
	t.Setenv("FASTDBG_ALLOCATOR_PROFILE_DIR", directory)
	path, err := allocatorRegistryPath(profile.LibcBuildID, profile.LoaderBuildID)
	if err != nil {
		t.Fatal(err)
	}
	allocatorRegistryTestWrite(t, path, allocatorRegistryTestData(t, profile))
	loaded, err := loadAllocatorRegistryProfile(context.Background(), profile.LibcBuildID, profile.LoaderBuildID)
	if err != nil || loaded == nil || !reflect.DeepEqual(*loaded, profile) {
		t.Fatalf("profile mismatch: error=%v", err)
	}
	for _, loader := range []bool{false, true} {
		changed := profile
		if loader {
			changed.LoaderBuildID = strings.Repeat("12", 20)
		} else {
			changed.LibcBuildID = strings.Repeat("12", 20)
		}
		allocatorRegistryTestWrite(t, path, allocatorRegistryTestData(t, changed))
		if loaded, err := loadAllocatorRegistryProfile(context.Background(), profile.LibcBuildID, profile.LoaderBuildID); loaded != nil || !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("wrong exact pair accepted: loaded=%+v error=%v", loaded, err)
		}
	}
}

func TestAllocatorRegistryCacheReturnsIndependentCopies(t *testing.T) {
	profile := allocatorRegistryTestProfile(t)
	path := filepath.Join(elfSourceTestDirectory(t), "profile.json")
	allocatorRegistryTestWrite(t, path, allocatorRegistryTestData(t, profile))
	cache := &allocatorRegistryProfileCache{}
	first, err := loadAllocatorRegistryProfileFile(context.Background(), path, profile.LibcBuildID, profile.LoaderBuildID, cache)
	if err != nil {
		t.Fatal(err)
	}
	first.Name = "caller-change"
	clear(first.Layout.Arena.Fields)
	clear(first.Layout.Chunk.Fields)
	clear(first.Layout.Tcache.Fields)
	clear(first.Layout.TcacheEntry.Fields)
	clear(first.MallocPar.Fields)
	clear(first.HeapInfo.Fields)
	clear(first.Symbols)
	for index := 0; index < 5; index++ {
		loaded, err := loadAllocatorRegistryProfileFile(context.Background(), path, profile.LibcBuildID, profile.LoaderBuildID, cache)
		if err != nil || loaded == nil || !reflect.DeepEqual(*loaded, profile) || len(cache.values) != 1 {
			t.Fatalf("cached profile mutated: error=%v entries=%d", err, len(cache.values))
		}
	}
}

func TestAllocatorRegistryCacheInvalidatesContentRewriteWithRestoredMtime(t *testing.T) {
	profile := allocatorRegistryTestProfile(t)
	path := filepath.Join(elfSourceTestDirectory(t), "profile.json")
	allocatorRegistryTestWrite(t, path, allocatorRegistryTestData(t, profile))
	cache := &allocatorRegistryProfileCache{}
	if _, err := loadAllocatorRegistryProfileFile(context.Background(), path, profile.LibcBuildID, profile.LoaderBuildID, cache); err != nil {
		t.Fatal(err)
	}
	source, err := openRegularELFSource(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	before, err := allocatorRegistrySourceKey(source, profile.LibcBuildID, profile.LoaderBuildID)
	if err != nil {
		t.Fatal(err)
	}
	profile.Name = strings.Repeat("x", len(profile.Name))
	allocatorRegistryTestWrite(t, path, allocatorRegistryTestData(t, profile))
	mtime := time.Unix(before.modified.Sec, before.modified.Nsec)
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	after, err := allocatorRegistrySourceKey(source, profile.LibcBuildID, profile.LoaderBuildID)
	if err != nil || after.modified != before.modified || after.size != before.size || after.changed == before.changed {
		t.Fatalf("rewrite fixture did not preserve size/mtime and change ctime: before=%+v after=%+v error=%v", before, after, err)
	}
	if err := verifyAllocatorRegistrySource(context.Background(), source, before); !errors.Is(err, target.ErrStale) {
		t.Fatalf("content rewrite not stale: %v", err)
	}
	loaded, err := loadAllocatorRegistryProfileFile(context.Background(), path, profile.LibcBuildID, profile.LoaderBuildID, cache)
	if err != nil || loaded == nil || loaded.Name != profile.Name || len(cache.values) != 2 {
		t.Fatalf("stale cache reused: loaded=%+v entries=%d error=%v", loaded, len(cache.values), err)
	}
}

func TestAllocatorRegistryCacheInvalidatesPathReplacement(t *testing.T) {
	profile := allocatorRegistryTestProfile(t)
	path := filepath.Join(elfSourceTestDirectory(t), "profile.json")
	allocatorRegistryTestWrite(t, path, allocatorRegistryTestData(t, profile))
	cache := &allocatorRegistryProfileCache{}
	if _, err := loadAllocatorRegistryProfileFile(context.Background(), path, profile.LibcBuildID, profile.LoaderBuildID, cache); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	profile.Name += "-replacement"
	allocatorRegistryTestWrite(t, path, allocatorRegistryTestData(t, profile))
	loaded, err := loadAllocatorRegistryProfileFile(context.Background(), path, profile.LibcBuildID, profile.LoaderBuildID, cache)
	if err != nil || loaded == nil || loaded.Name != profile.Name || len(cache.values) != 2 {
		t.Fatalf("replacement reused cached inode: loaded=%+v error=%v", loaded, err)
	}
}

func TestAllocatorRegistryCachedEntryDoesNotHideMissingOrCorruptFile(t *testing.T) {
	profile := allocatorRegistryTestProfile(t)
	path := filepath.Join(elfSourceTestDirectory(t), "profile.json")
	allocatorRegistryTestWrite(t, path, allocatorRegistryTestData(t, profile))
	cache := &allocatorRegistryProfileCache{}
	if _, err := loadAllocatorRegistryProfileFile(context.Background(), path, profile.LibcBuildID, profile.LoaderBuildID, cache); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if loaded, err := loadAllocatorRegistryProfileFile(context.Background(), path, profile.LibcBuildID, profile.LoaderBuildID, cache); loaded != nil || !errors.Is(err, target.ErrNotFound) {
		t.Fatalf("removed source served from cache: loaded=%+v error=%v", loaded, err)
	}
	allocatorRegistryTestWrite(t, path, []byte(`{"invalid":"replacement"}`))
	if loaded, err := loadAllocatorRegistryProfileFile(context.Background(), path, profile.LibcBuildID, profile.LoaderBuildID, cache); loaded != nil || !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("corrupt source hidden by cache: loaded=%+v error=%v", loaded, err)
	}
}

func TestAllocatorRegistryCacheIsBoundedAndKeyIncludesCompletePair(t *testing.T) {
	cache := &allocatorRegistryProfileCache{}
	for index := 0; index <= maxAllocatorRegistryProfiles; index++ {
		key := allocatorRegistryKey{libcID: fmt.Sprintf("%040x", index+1), loaderID: strings.Repeat("ab", 20), device: 1, inode: 2}
		cache.put(key, allocatorProfile{Name: strconv.Itoa(index)})
		cache.put(key, allocatorProfile{Name: "must-not-replace"})
		if got, ok := cache.get(key); !ok || got.Name != strconv.Itoa(index) || len(cache.values) > maxAllocatorRegistryProfiles {
			t.Fatalf("cache insert=%+v found=%v entries=%d", got, ok, len(cache.values))
		}
	}
	first := allocatorRegistryKey{libcID: fmt.Sprintf("%040x", 1), loaderID: strings.Repeat("ab", 20), device: 1, inode: 2}
	if _, ok := cache.get(first); ok || len(cache.values) != maxAllocatorRegistryProfiles {
		t.Fatalf("oldest profile not evicted: found=%v entries=%d", ok, len(cache.values))
	}
	latest := allocatorRegistryKey{libcID: fmt.Sprintf("%040x", maxAllocatorRegistryProfiles+1), loaderID: strings.Repeat("ab", 20), device: 1, inode: 2}
	latest.loaderID = strings.Repeat("cd", 20)
	if _, ok := cache.get(latest); ok {
		t.Fatal("different loader pair reused cached metadata")
	}
}

func TestAllocatorRegistryConcurrentHotCacheReadsRemainIndependent(t *testing.T) {
	profile := allocatorRegistryTestProfile(t)
	path := filepath.Join(elfSourceTestDirectory(t), "profile.json")
	allocatorRegistryTestWrite(t, path, allocatorRegistryTestData(t, profile))
	cache := &allocatorRegistryProfileCache{}
	if _, err := loadAllocatorRegistryProfileFile(context.Background(), path, profile.LibcBuildID, profile.LoaderBuildID, cache); err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	failures := make(chan error, 8)
	for worker := 0; worker < cap(failures); worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := 0; index < 8; index++ {
				loaded, err := loadAllocatorRegistryProfileFile(context.Background(), path, profile.LibcBuildID, profile.LoaderBuildID, cache)
				if err != nil || loaded == nil || !reflect.DeepEqual(*loaded, profile) {
					failures <- fmt.Errorf("concurrent profile differs: %w", err)
					return
				}
				clear(loaded.Symbols)
				clear(loaded.Layout.Arena.Fields)
			}
		}()
	}
	workers.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
}

func TestAllocatorRegistryRejectsSpecialAndOversizedFiles(t *testing.T) {
	profile := allocatorRegistryTestProfile(t)
	for _, kind := range []string{"fifo", "directory", "oversized", "empty", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(elfSourceTestDirectory(t), "profile.json")
			var err error
			switch kind {
			case "fifo":
				err = unix.Mkfifo(path, 0o600)
			case "directory":
				err = os.Mkdir(path, 0o700)
			case "oversized":
				err = os.WriteFile(path, make([]byte, maxAllocatorProfileBytes+1), 0o600)
			case "empty":
				err = os.WriteFile(path, nil, 0o600)
			case "malformed":
				err = os.WriteFile(path, []byte(`{"Name":"incomplete"}`), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			cache := &allocatorRegistryProfileCache{}
			loaded, err := loadAllocatorRegistryProfileFile(context.Background(), path, profile.LibcBuildID, profile.LoaderBuildID, cache)
			if loaded != nil || err == nil || errors.Is(err, target.ErrNotFound) || len(cache.values) != 0 {
				t.Fatalf("invalid registry source accepted: loaded=%+v error=%v", loaded, err)
			}
		})
	}
}

func TestAllocatorRegistryCancellationIsNeverAProfileMiss(t *testing.T) {
	profile := allocatorRegistryTestProfile(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if loaded, err := loadAllocatorRegistryProfile(ctx, profile.LibcBuildID, profile.LoaderBuildID); loaded != nil || !errors.Is(err, context.Canceled) || errors.Is(err, target.ErrNotFound) {
		t.Fatalf("cancellation misreported: loaded=%+v error=%v", loaded, err)
	}
	if loaded, err := loadAllocatorRegistryProfile(nil, profile.LibcBuildID, profile.LoaderBuildID); loaded != nil || !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("nil context accepted: loaded=%+v error=%v", loaded, err)
	}
	base, lateCancel := context.WithCancel(context.Background())
	defer lateCancel()
	late := &allocatorRegistryCancelContext{Context: base, cancel: lateCancel, limit: 2}
	path := filepath.Join(elfSourceTestDirectory(t), "does-not-exist.json")
	loaded, err := loadAllocatorRegistryProfileFile(late, path, profile.LibcBuildID, profile.LoaderBuildID, &allocatorRegistryProfileCache{})
	if loaded != nil || !errors.Is(err, context.Canceled) || errors.Is(err, target.ErrNotFound) {
		t.Fatalf("cancellation during missing-path lookup hidden: loaded=%+v error=%v", loaded, err)
	}
}

type allocatorRegistryCancelContext struct {
	context.Context
	cancel context.CancelFunc
	checks int
	limit  int
}

func (ctx *allocatorRegistryCancelContext) Err() error {
	ctx.checks++
	if ctx.checks >= ctx.limit {
		ctx.cancel()
	}
	return ctx.Context.Err()
}

func BenchmarkAllocatorRegistryProfile(b *testing.B) {
	profile := allocatorRegistryTestProfile(b)
	data := allocatorRegistryTestData(b, profile)
	root, err := filepath.Abs(filepath.Join("..", "..", ".cache", "deterministic-foundations", "allocator-registry", "bench"))
	if err != nil {
		b.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		b.Fatal(err)
	}
	directory, err := os.MkdirTemp(root, "registry-")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			b.Error(err)
		}
	})
	path := filepath.Join(directory, "profile.json")
	allocatorRegistryTestWrite(b, path, data)
	for _, hot := range []bool{false, true} {
		b.Run(map[bool]string{false: "cold", true: "hot"}[hot], func(b *testing.B) {
			cache := &allocatorRegistryProfileCache{}
			if _, err := loadAllocatorRegistryProfileFile(context.Background(), path, profile.LibcBuildID, profile.LoaderBuildID, cache); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				if !hot {
					cache = &allocatorRegistryProfileCache{}
				}
				if _, err := loadAllocatorRegistryProfileFile(context.Background(), path, profile.LibcBuildID, profile.LoaderBuildID, cache); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
