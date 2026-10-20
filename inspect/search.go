package inspect

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"runtime"
	"slices"
	"sync"

	"fastdbg2/target"
)

type MemoryReader interface {
	ReadMemory(addr target.Address, dst []byte) (int, error)
}

type SearchOptions struct {
	ChunkSize int
	Workers   int
}

type searchChunk struct {
	base target.Address
	data []byte
}

type searchMatches struct {
	base      target.Address
	addresses []target.Address
}

const searchCancellationStride = 4096

func Search(ctx context.Context, reader MemoryReader, start target.Address, size uint64, pattern []byte, options SearchOptions) ([]target.Address, error) {
	options, err := searchOptions(ctx, start, size, pattern, options)
	if err != nil {
		return nil, err
	}
	if reader == nil {
		return nil, fmt.Errorf("%w: memory reader is nil", target.ErrInvalidArgument)
	}
	if size < uint64(len(pattern)) {
		return nil, nil
	}
	pattern = bytes.Clone(pattern)
	return searchChunks(ctx, pattern, options.Workers, func(yield func(searchChunk) bool) error {
		var tail []byte
		for offset := uint64(0); offset < size; {
			if err := ctx.Err(); err != nil {
				return err
			}
			want := int(min(size-offset, uint64(options.ChunkSize)))
			data := make([]byte, len(tail)+want)
			copy(data, tail)
			address := start + target.Address(offset)
			n, readErr := reader.ReadMemory(address, data[len(tail):])
			if n < 0 || n > want {
				return fmt.Errorf("%w: memory reader returned %d bytes for a %d-byte request at %#x", target.ErrInvalidArgument, n, want, address)
			}
			if n < want && readErr == nil {
				readErr = io.ErrUnexpectedEOF
			}
			data = data[:len(tail)+n]
			if n > 0 && len(data) >= len(pattern) {
				if !yield(searchChunk{base: address - target.Address(len(tail)), data: data}) {
					return errors.Join(readErr, ctx.Err())
				}
			}
			if readErr != nil {
				return &target.PartialError{Op: fmt.Sprintf("search read at %#x", address), Completed: n, Total: want, Err: readErr}
			}
			offset += uint64(n)
			tail = data[len(data)-min(len(data), len(pattern)-1):]
		}
		return nil
	})
}

func SearchBytes(ctx context.Context, base target.Address, data, pattern []byte, workers int) ([]target.Address, error) {
	options, err := searchOptions(ctx, base, uint64(len(data)), pattern, SearchOptions{Workers: workers})
	if err != nil {
		return nil, err
	}
	if len(data) < len(pattern) {
		return nil, nil
	}
	pattern = bytes.Clone(pattern)
	return searchChunks(ctx, pattern, options.Workers, func(yield func(searchChunk) bool) error {
		for offset := 0; offset < len(data); {
			start := max(0, offset-len(pattern)+1)
			end := offset + min(options.ChunkSize, len(data)-offset)
			if !yield(searchChunk{base: base + target.Address(start), data: data[start:end]}) {
				return ctx.Err()
			}
			offset = end
		}
		return nil
	})
}

func searchOptions(ctx context.Context, start target.Address, size uint64, pattern []byte, options SearchOptions) (SearchOptions, error) {
	if ctx == nil || len(pattern) == 0 || options.ChunkSize < 0 || options.Workers < 0 {
		return options, fmt.Errorf("%w: context and nonempty pattern are required; chunk size and workers must not be negative", target.ErrInvalidArgument)
	}
	if size > 0 && size-1 > math.MaxUint64-uint64(start) {
		return options, fmt.Errorf("%w: search range", target.ErrOverflow)
	}
	if err := ctx.Err(); err != nil {
		return options, err
	}
	if options.ChunkSize == 0 {
		options.ChunkSize = max(64<<10, len(pattern))
	}
	if options.Workers == 0 {
		options.Workers = runtime.GOMAXPROCS(0)
	}
	if size > 0 {
		options.ChunkSize = int(min(uint64(options.ChunkSize), size))
		if options.ChunkSize > math.MaxInt-(len(pattern)-1) {
			return options, fmt.Errorf("%w: search chunk with overlap", target.ErrOverflow)
		}
		chunks := 1 + (size-1)/uint64(options.ChunkSize)
		options.Workers = int(min(uint64(options.Workers), chunks))
	}
	return options, nil
}

func searchChunks(ctx context.Context, pattern []byte, workers int, produce func(func(searchChunk) bool) error) ([]target.Address, error) {
	prefix, err := searchPrefix(ctx, pattern)
	if err != nil {
		return nil, err
	}
	jobs := make(chan searchChunk)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []searchMatches
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case chunk, ok := <-jobs:
					if !ok {
						return
					}
					var found []target.Address
					matched := 0
					for offset, value := range chunk.data {
						if offset%searchCancellationStride == 0 && ctx.Err() != nil {
							return
						}
						for matched > 0 && value != pattern[matched] {
							matched = prefix[matched-1]
						}
						if value == pattern[matched] {
							matched++
						}
						if matched == len(pattern) {
							found = append(found, chunk.base+target.Address(offset-len(pattern)+1))
							matched = prefix[matched-1]
						}
					}
					if len(found) > 0 {
						mu.Lock()
						results = append(results, searchMatches{base: chunk.base, addresses: found})
						mu.Unlock()
					}
				}
			}
		}()
	}
	err = produce(func(chunk searchChunk) bool {
		select {
		case jobs <- chunk:
			return true
		case <-ctx.Done():
			return false
		}
	})
	close(jobs)
	wg.Wait()
	if ctx.Err() != nil {
		return nil, errors.Join(err, ctx.Err())
	}
	slices.SortFunc(results, func(a, b searchMatches) int { return cmp.Compare(a.base, b.base) })
	total := 0
	for _, result := range results {
		total += len(result.addresses)
	}
	if total == 0 {
		return nil, err
	}
	matches := make([]target.Address, 0, total)
	for _, result := range results {
		matches = append(matches, result.addresses...)
	}
	return matches, err
}

func searchPrefix(ctx context.Context, pattern []byte) ([]int, error) {
	prefix := make([]int, len(pattern))
	for i, matched := 1, 0; i < len(pattern); i++ {
		if i%searchCancellationStride == 0 && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		for matched > 0 && pattern[i] != pattern[matched] {
			matched = prefix[matched-1]
		}
		if pattern[i] == pattern[matched] {
			matched++
		}
		prefix[i] = matched
	}
	return prefix, nil
}
