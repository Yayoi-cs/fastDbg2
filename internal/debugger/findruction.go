package debugger

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"

	"fastdbg2/display"
	"fastdbg2/inspect"
	"fastdbg2/target"
)

const findructionContextCount = 64

type findructionMatch struct {
	arch                         target.Architecture
	address, offset, readAddress target.Address
	code                         []byte
	instructions                 []inspect.Instruction
	readErr, decodeErr           error
}

type findructionGroup struct {
	arch       target.Architecture
	label      string
	start, end target.Address
	file       bool
	matches    []findructionMatch
}

func findructionMemoryGroups(maps []procMap, spans []searchSpan, addresses []target.Address) []findructionGroup {
	groups := make([]findructionGroup, len(spans))
	for i, span := range spans {
		index := sort.Search(len(maps), func(j int) bool { return maps[j].End > span.start })
		label := "[anonymous]"
		if index < len(maps) && maps[index].Path != "" {
			label = maps[index].Path
		}
		groups[i] = findructionGroup{label: label, start: span.start, end: span.end}
	}
	for _, address := range addresses {
		i := sort.Search(len(spans), func(i int) bool { return spans[i].end > address })
		if i < len(groups) && address >= spans[i].start {
			groups[i].matches = append(groups[i].matches, findructionMatch{address: address, readAddress: address})
		}
	}
	return groups
}

func findructionPreviews(ctx context.Context, reader inspect.MemoryReader, groups []findructionGroup, count int) error {
	if reader == nil || count < 1 || count > findructionContextCount {
		return target.ErrInvalidArgument
	}
	var jobs []*findructionMatch
	var failures error
	for gi := range groups {
		g := &groups[gi]
		limit := g.end
		for j := gi + 1; !g.file && j < len(groups) && groups[j].start == limit; j++ {
			limit = groups[j].end
		}
		for i := 0; i < len(g.matches); {
			if err := contextReady(ctx); err != nil {
				return err
			}
			first := &g.matches[i]
			if first.address < g.start || first.address >= g.end {
				return target.ErrInvalidArgument
			}
			start := first.address
			end := start + target.Address(min(uint64(limit-start), uint64(count*15)))
			next := i + 1
			for next < len(g.matches) && g.matches[next].address <= end {
				address := g.matches[next].address
				candidate := address + target.Address(min(uint64(limit-address), uint64(count*15)))
				if candidate-start > searchChunkBytes {
					break
				}
				end = max(end, candidate)
				next++
			}
			data := make([]byte, int(end-start))
			n, err := reader.ReadMemory(first.readAddress, data)
			data, err = inspectionConfirmedBytes(data, n, err)
			if uiDisplayFatal(err) {
				return err
			}
			if err != nil {
				failures = errors.Join(failures, fmt.Errorf("findruction context at %#x: %w", start, err))
			}
			for j := i; j < next; j++ {
				m := &g.matches[j]
				m.arch = abiFor(g.arch).arch
				offset := int(m.address - start)
				if offset < len(data) {
					m.code = data[offset:min(len(data), offset+count*15)]
				}
				m.readErr = err
				jobs = append(jobs, m)
			}
			i = next
		}
	}
	workers := min(len(jobs), runtime.GOMAXPROCS(0), 8)
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			for j := index; j < len(jobs); j += workers {
				if ctx.Err() != nil {
					return
				}
				m := jobs[j]
				m.instructions, m.decodeErr = inspect.Disassemble(m.arch, m.address, m.code, count)
			}
		}(worker)
	}
	wait.Wait()
	return errors.Join(failures, contextReady(ctx))
}

func findructionTotal(groups []findructionGroup) int {
	total := 0
	for _, g := range groups {
		total += len(g.matches)
	}
	return total
}

func findructionInsn(renderer display.Renderer, in inspect.Instruction, architectures ...target.Architecture) string {
	arch := target.AMD64
	if len(architectures) > 0 {
		arch = architectures[0]
	}
	mnemonic, operands, _ := strings.Cut(in.Text, " ")
	text := renderer.Text(display.StyleCyan, fmt.Sprintf("0x%0*x", abiFor(arch).word*2, in.Address)) + ": " + renderer.Text(display.StyleBlue, mnemonic)
	if operands != "" {
		text += " " + operands
	}
	return text
}

func findructionListing(renderer display.Renderer, groups []findructionGroup, pattern []byte, partial bool) string {
	var out strings.Builder
	status := ""
	if partial {
		status = " (partial)"
	}
	fmt.Fprintf(&out, "%s — %s match(es) across %d group(s); pattern = %x%s\n", renderer.Text(display.StyleGreen, "findruction"), renderer.Text(display.StyleCyan, fmt.Sprint(findructionTotal(groups))), len(groups), pattern, status)
	for gi, g := range groups {
		fmt.Fprintf(&out, "\n%s  %s\n", renderer.Text(display.StylePurple, fmt.Sprintf("[%d] %s [0x%x-0x%x)", gi, contextEscapedText(g.label), g.start, g.end)), renderer.Text(display.StyleCyan, fmt.Sprintf("(%d match(es))", len(g.matches))))
		for mi, m := range g.matches {
			field := "vaddr"
			if g.file {
				field = "elf-vaddr"
			}
			fmt.Fprintf(&out, "  %s  %s=%s", renderer.Text(display.StyleGreen, fmt.Sprintf("#%d/%d", mi+1, len(g.matches))), field, renderer.Text(display.StyleCyan, fmt.Sprintf("0x%0*x", abiFor(g.arch).word*2, m.address)))
			if g.file {
				fmt.Fprintf(&out, " file-offset=%s", renderer.Text(display.StyleBlue, fmt.Sprintf("0x%x", m.offset)))
			}
			out.WriteByte('\n')
			for _, in := range m.instructions[:min(7, len(m.instructions))] {
				fmt.Fprintf(&out, "    %s\n", findructionInsn(renderer, in, g.arch))
			}
			if len(m.instructions) == 0 {
				fmt.Fprintf(&out, "    %s\n", renderer.Text(display.StyleYellow, "<unable to disassemble>"))
			}
			if m.readErr != nil {
				fmt.Fprintf(&out, "    %s\n", renderer.Text(display.StyleError, "<context unreadable or partial>"))
			}
		}
	}
	return out.String()
}

func (c *Controller) publishFindruction(ctx context.Context, groups []findructionGroup, pattern []byte, options searchArguments, searchErr error) error {
	if uiDisplayFatal(searchErr) || contextReady(ctx) != nil {
		return errors.Join(searchErr, contextReady(ctx))
	}
	if c.pager != nil && !options.noTUI && !options.pager && findructionTotal(groups) > 0 {
		return errors.Join(searchErr, c.findructionTUI(ctx, groups, pattern, searchErr != nil))
	}
	text := findructionListing(c.renderer, groups, pattern, searchErr != nil)
	if err := contextReady(ctx); err != nil {
		return errors.Join(searchErr, err)
	}
	if options.pager {
		return errors.Join(searchErr, c.publishPaged(ctx, text))
	}
	return errors.Join(searchErr, c.writef("%s", text))
}

func (c *Controller) findructionPreviewCount(options searchArguments) int {
	if c.pager != nil && !options.noTUI && !options.pager {
		return findructionContextCount
	}
	return 7
}
