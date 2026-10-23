package debugger

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"unicode/utf8"

	"fastdbg2/target"
	"golang.org/x/sys/unix"
)

const maxAllocatorProfileBytes = 128 << 10
const maxAllocatorProfileDepth = 16
const maxAllocatorProfileFields = 4096
const maxAllocatorProfileObjectFields = 256
const maxAllocatorProfileStringBytes = 4096
const maxAllocatorRegistryProfiles = 64

type allocatorRegistryKey struct {
	libcID   string
	loaderID string
	device   uint64
	inode    uint64
	size     int64
	modified unix.Timespec
	changed  unix.Timespec
}

type allocatorRegistryProfileCache struct {
	mu     sync.Mutex
	values map[allocatorRegistryKey]allocatorProfile
	slots  [maxAllocatorRegistryProfiles]allocatorRegistryKey
	next   int
}

var allocatorRegistryProfiles allocatorRegistryProfileCache

func (cache *allocatorRegistryProfileCache) get(key allocatorRegistryKey) (allocatorProfile, bool) {
	cache.mu.Lock()
	profile, ok := cache.values[key]
	cache.mu.Unlock()
	return profile, ok
}

func (cache *allocatorRegistryProfileCache) put(key allocatorRegistryKey, profile allocatorProfile) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.values == nil {
		cache.values = make(map[allocatorRegistryKey]allocatorProfile)
	}
	if _, exists := cache.values[key]; exists {
		return
	}
	if len(cache.values) == maxAllocatorRegistryProfiles {
		delete(cache.values, cache.slots[cache.next])
	}
	cache.slots[cache.next] = key
	cache.next = (cache.next + 1) % len(cache.slots)
	cache.values[key] = profile
}

func cloneAllocatorRegistryProfile(profile allocatorProfile) allocatorProfile {
	profile.Layout = cloneAllocatorLayout(profile.Layout)
	profile.MallocPar = cloneAllocatorRecord(profile.MallocPar)
	profile.HeapInfo = cloneAllocatorRecord(profile.HeapInfo)
	profile.Symbols = maps.Clone(profile.Symbols)
	return profile
}

func parseAllocatorProfile(data []byte) (allocatorProfile, error) {
	if len(data) == 0 {
		return allocatorProfile{}, fmt.Errorf("empty allocator profile: %w", target.ErrInvalidArgument)
	}
	if len(data) > maxAllocatorProfileBytes {
		return allocatorProfile{}, fmt.Errorf("allocator profile exceeds %d bytes: %w", maxAllocatorProfileBytes, target.ErrUnsupported)
	}
	if !utf8.Valid(data) {
		return allocatorProfile{}, fmt.Errorf("allocator profile is not UTF-8: %w", target.ErrInvalidArgument)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	remaining := maxAllocatorProfileFields
	if err := scanAllocatorProfileJSON(decoder, reflect.TypeOf(allocatorProfile{}), 0, &remaining); err != nil {
		return allocatorProfile{}, fmt.Errorf("allocator profile JSON: %w", errors.Join(target.ErrInvalidArgument, err))
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return allocatorProfile{}, fmt.Errorf("allocator profile has trailing data: %w", errors.Join(target.ErrInvalidArgument, err))
	}
	var profile allocatorProfile
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		return allocatorProfile{}, fmt.Errorf("allocator profile JSON: %w", errors.Join(target.ErrInvalidArgument, err))
	}
	if err := validateAllocatorProfile(profile); err != nil {
		return allocatorProfile{}, err
	}
	return profile, nil
}

func scanAllocatorProfileJSON(decoder *json.Decoder, valueType reflect.Type, depth int, remaining *int) error {
	if depth > maxAllocatorProfileDepth {
		return fmt.Errorf("allocator profile nesting exceeds %d levels: %w", maxAllocatorProfileDepth, target.ErrUnsupported)
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if valueType.Kind() == reflect.Pointer {
		if token == nil {
			return nil
		}
		valueType = valueType.Elem()
	}
	if token == nil {
		return fmt.Errorf("null allocator profile value for %s", valueType)
	}
	switch valueType.Kind() {
	case reflect.Struct, reflect.Map:
		if token != json.Delim('{') {
			return fmt.Errorf("allocator profile value for %s must be an object", valueType)
		}
		fields := make(map[string]reflect.Type)
		var fieldNames []string
		if valueType.Kind() == reflect.Struct {
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
				fields[name] = field.Type
				fieldNames = append(fieldNames, name)
			}
		} else if valueType.Key().Kind() != reflect.String {
			return fmt.Errorf("unsupported allocator profile map type %s", valueType)
		}
		seen := make(map[string]bool)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || len(key) > 256 {
				return fmt.Errorf("invalid allocator profile field name")
			}
			if seen[key] {
				return fmt.Errorf("duplicate allocator profile field %q", key)
			}
			if len(seen) == maxAllocatorProfileObjectFields || *remaining == 0 {
				return fmt.Errorf("allocator profile field budget exhausted: %w", target.ErrUnsupported)
			}
			seen[key] = true
			*remaining -= 1
			var fieldType reflect.Type
			if valueType.Kind() == reflect.Map {
				fieldType = valueType.Elem()
			} else {
				fieldType, ok = fields[key]
				if !ok {
					return fmt.Errorf("unknown allocator profile field %q in %s", key, valueType)
				}
			}
			if err := scanAllocatorProfileJSON(decoder, fieldType, depth+1, remaining); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.Join(err, fmt.Errorf("unterminated allocator profile object"))
		}
		for _, name := range fieldNames {
			if !seen[name] {
				return fmt.Errorf("missing allocator profile field %q in %s", name, valueType)
			}
		}
	case reflect.Array, reflect.Slice:
		if token != json.Delim('[') {
			return fmt.Errorf("allocator profile value for %s must be an array", valueType)
		}
		for decoder.More() {
			if *remaining == 0 {
				return fmt.Errorf("allocator profile array budget exhausted: %w", target.ErrUnsupported)
			}
			*remaining -= 1
			if err := scanAllocatorProfileJSON(decoder, valueType.Elem(), depth+1, remaining); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.Join(err, fmt.Errorf("unterminated allocator profile array"))
		}
	case reflect.String:
		value, ok := token.(string)
		if !ok {
			return fmt.Errorf("allocator profile value for %s must be a string", valueType)
		}
		if len(value) > maxAllocatorProfileStringBytes {
			return fmt.Errorf("allocator profile string exceeds %d bytes: %w", maxAllocatorProfileStringBytes, target.ErrUnsupported)
		}
	case reflect.Bool:
		if _, ok := token.(bool); !ok {
			return fmt.Errorf("allocator profile value for %s must be a boolean", valueType)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if _, ok := token.(json.Number); !ok {
			return fmt.Errorf("allocator profile value for %s must be an integer", valueType)
		}
	default:
		return fmt.Errorf("unsupported allocator profile value type %s", valueType)
	}
	return nil
}

func allocatorRegistryPath(libcID, loaderID string) (string, error) {
	for _, id := range []string{libcID, loaderID} {
		data, err := hex.DecodeString(id)
		if err != nil || len(data) < 16 || len(data) > 128 || hex.EncodeToString(data) != id {
			return "", fmt.Errorf("allocator registry requires complete lowercase hexadecimal build IDs: %w", target.ErrInvalidArgument)
		}
	}
	name := libcID + "." + loaderID + ".json"
	if len(name) > 255 {
		return "", fmt.Errorf("complete allocator build ID pair exceeds a filename component: %w", target.ErrUnsupported)
	}
	directory := os.Getenv("FASTDBG_ALLOCATOR_PROFILE_DIR")
	if directory == "" {
		directory = filepath.Join(".libc", "profiles")
	}
	if strings.ContainsRune(directory, 0) {
		return "", target.ErrInvalidArgument
	}
	directory, err := filepath.Abs(directory)
	if err != nil {
		return "", err
	}
	path := filepath.Join(directory, name)
	if len(path) >= 4096 {
		return "", fmt.Errorf("allocator registry path exceeds 4095 bytes: %w", target.ErrUnsupported)
	}
	return path, nil
}

func loadAllocatorRegistryProfile(ctx context.Context, libcID, loaderID string) (*allocatorProfile, error) {
	if err := contextReady(ctx); err != nil {
		return nil, err
	}
	path, err := allocatorRegistryPath(libcID, loaderID)
	if err != nil {
		return nil, err
	}
	return loadAllocatorRegistryProfileFile(ctx, path, libcID, loaderID, &allocatorRegistryProfiles)
}

func allocatorRegistrySourceKey(source *os.File, libcID, loaderID string) (allocatorRegistryKey, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(source.Fd()), &stat); err != nil {
		return allocatorRegistryKey{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return allocatorRegistryKey{}, fmt.Errorf("allocator registry source is not a regular file: %w", target.ErrUnsupported)
	}
	if stat.Size < 0 || stat.Size > maxAllocatorProfileBytes {
		return allocatorRegistryKey{}, fmt.Errorf("allocator registry source exceeds %d bytes: %w", maxAllocatorProfileBytes, target.ErrUnsupported)
	}
	return allocatorRegistryKey{
		libcID: libcID, loaderID: loaderID, device: stat.Dev, inode: stat.Ino,
		size: stat.Size, modified: stat.Mtim, changed: stat.Ctim,
	}, nil
}

func verifyAllocatorRegistrySource(ctx context.Context, source *os.File, before allocatorRegistryKey) error {
	after, err := allocatorRegistrySourceKey(source, before.libcID, before.loaderID)
	if err != nil {
		return err
	}
	if after != before {
		return fmt.Errorf("allocator registry source changed during lookup: %w", target.ErrStale)
	}
	return contextReady(ctx)
}

func loadAllocatorRegistryProfileFile(ctx context.Context, path, libcID, loaderID string, cache *allocatorRegistryProfileCache) (result *allocatorProfile, err error) {
	if cache == nil {
		return nil, target.ErrInvalidArgument
	}
	source, err := openRegularELFSource(ctx, path)
	if err != nil {
		if contextErr := contextReady(ctx); contextErr != nil {
			return nil, errors.Join(err, contextErr)
		}
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENOTDIR) {
			return nil, fmt.Errorf("no allocator registry profile for %s/%s: %w", libcID, loaderID, target.ErrNotFound)
		}
		return nil, err
	}
	defer func() {
		err = errors.Join(err, source.Close(), contextReady(ctx))
		if err != nil {
			result = nil
		}
	}()
	key, err := allocatorRegistrySourceKey(source, libcID, loaderID)
	if err != nil {
		return nil, err
	}
	if profile, ok := cache.get(key); ok {
		if err := verifyAllocatorRegistrySource(ctx, source, key); err != nil {
			return nil, err
		}
		clone := cloneAllocatorRegistryProfile(profile)
		return &clone, nil
	}
	data := make([]byte, int(key.size))
	if n, readErr := source.ReadAt(data, 0); readErr != nil || n != len(data) {
		return nil, errors.Join(readErr, io.ErrUnexpectedEOF, verifyAllocatorRegistrySource(ctx, source, key))
	}
	if err := verifyAllocatorRegistrySource(ctx, source, key); err != nil {
		return nil, err
	}
	profile, err := parseAllocatorProfile(data)
	if err != nil {
		return nil, errors.Join(err, verifyAllocatorRegistrySource(ctx, source, key))
	}
	if profile.LibcBuildID != libcID || profile.LoaderBuildID != loaderID {
		return nil, errors.Join(fmt.Errorf("allocator registry profile does not match the requested complete build ID pair: %w", target.ErrInvalidArgument), verifyAllocatorRegistrySource(ctx, source, key))
	}
	if err := verifyAllocatorRegistrySource(ctx, source, key); err != nil {
		return nil, err
	}
	cache.put(key, profile)
	clone := cloneAllocatorRegistryProfile(profile)
	return &clone, nil
}
