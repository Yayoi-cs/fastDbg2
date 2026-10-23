package debugger

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"fastdbg2/display"
	"fastdbg2/internal/cli"
	"fastdbg2/target"
)

var legacyUnsignedLiteral = regexp.MustCompile(`^(?:0[xX][0-9a-fA-F]+|0[0-7]*|[1-9][0-9]*)$`)

func legacyDumpArguments(rawArgs string) (string, error) {
	words := strings.Fields(rawArgs)
	if len(words) != 2 || !legacyUnsignedLiteral.MatchString(words[0]) || !legacyUnsignedLiteral.MatchString(words[1]) {
		return rawArgs, nil
	}
	count, err := strconv.ParseUint(words[1], 0, 64)
	if err != nil {
		return "", fmt.Errorf("invalid legacy dump count %q: %w", words[1], target.ErrInvalidArgument)
	}
	return fmt.Sprintf("--count %d %s", count, words[0]), nil
}

func (c *Controller) showLegacyDump(ctx context.Context, unit, rawArgs string) error {
	if unit != "word" {
		var err error
		rawArgs, err = legacyDumpArguments(rawArgs)
		if err != nil {
			return err
		}
	}
	return c.showHexdump(ctx, unit, rawArgs)
}

func legacyXXDArguments(rawArgs string) (string, string, error) {
	unit := "byte"
	first, rest := cli.SplitCommand(rawArgs)
	if first == "dword" || first == "qword" {
		unit, rawArgs = first, rest
	}
	first, _ = cli.SplitCommand(rawArgs)
	if first == "--count" {
		return unit, rawArgs, nil
	}
	arguments, err := cli.ParseArgs(rawArgs)
	if err != nil {
		return "", "", err
	}
	if len(arguments) < 1 || len(arguments) > 2 || strings.TrimSpace(arguments[0]) == "" {
		return "", "", fmt.Errorf("usage: xxd [dword|qword] EXPR [COUNT]; quote expressions containing spaces: %w", target.ErrInvalidArgument)
	}
	expression := arguments[0]
	if len(arguments) == 2 {
		if !legacyUnsignedLiteral.MatchString(arguments[1]) {
			return "", "", fmt.Errorf("xxd count must be an unsigned integer literal: %w", target.ErrInvalidArgument)
		}
		count, err := strconv.ParseUint(arguments[1], 0, 64)
		if err != nil {
			return "", "", fmt.Errorf("invalid xxd count %q: %w", arguments[1], target.ErrInvalidArgument)
		}
		expression = fmt.Sprintf("--count %d %s", count, expression)
	}
	return unit, expression, nil
}

func (c *Controller) showLegacyXXD(ctx context.Context, rawArgs string) error {
	unit, expression, err := legacyXXDArguments(rawArgs)
	if err != nil {
		return err
	}
	return c.showHexdump(ctx, unit, expression)
}

func (c *Controller) showColorLegend() error {
	width := display.OutputWidth(c.out)
	if err := c.writef("%s\n", c.renderer.Section("color", width)); err != nil {
		return err
	}
	for _, entry := range []struct {
		name                 string
		read, write, execute bool
	}{
		{"Code (r-x)", true, false, true},
		{"Writable (rw-)", true, true, false},
		{"ReadOnly (r--)", true, false, false},
		{"RWX (rwx)", true, true, true},
		{"WriteOnly (-w-)", false, true, false},
		{"No access (---)", false, false, false},
	} {
		address, err := c.renderer.AddressPermissions(target.AMD64, 0, entry.read, entry.write, entry.execute)
		if err != nil {
			return err
		}
		if err := c.writef("%-18s %s\n", entry.name, address); err != nil {
			return err
		}
	}
	if err := c.writef("%-18s %s\n", "Modified register", c.renderer.Text(display.StyleChanged, "$rax")); err != nil {
		return err
	}
	return c.writef("%s", display.Wrap("Permissions come from verified mappings, not inferred from address values. Unmapped values remain plain.\n", width, 4))
}

const metadataProofHelp = " Module headers identify scope, proof and metadata source. Main uses proc-exe+auxv; other file metadata prefers strict mapped-file identity. kernel-vma-build-id-metadata associates matching build-ID metadata with validated PT_LOAD geometry; it does not prove the same backing file or all contents. All-module views follow validated DT_DEBUG/link_map membership; explicitly selected custom mappings still require their own proof. The exact AT_SYSINFO_EHDR vDSO uses runtime metadata, never a guessed file. Unsupported kernel proof, missing IDs, mismatches or ambiguous associations retain unavailable/partial errors; stale/cancel discards results."

const ttyPagerHelp = " When stdin and stdout are real terminals and TERM is usable, sym and telescope display the confirmed text with less -SR and a short fastDbg2 status, using the terminal's alternate screen and keypad modes. Each logical row remains one line; left/right scroll horizontally and resize is handled by less. Pipes and nonterminal inputs print directly without a pager, preserving logical rows. NO_COLOR is still honored. Ctrl-C interrupts the current pager operation but stays in less; q returns to the console after screen and terminal restoration. External cancellation requests graceful pager termination; a forced cleanup reports that screen restoration is unconfirmed. If less is missing, a warning precedes direct output; a started pager that fails or is canceled is not redumped."

var legacyCommandDetails = map[string]string{
	"arena":         "Two explicit modes: arena --layout-file FILE [--all] EXPR; or arena --module EXACT [--debug-file FILE] --fast-link plain|safe-link-12 [--all] [EXPR]. Options precede the single address-expression argument; quote spaces, or use -- to end options. Layout JSON is bounded to 65536 bytes and must declare schema 1, glibc/amd64/little-endian/8-byte pointers, typed arena/chunk fields and fast_link; this user-supplied interpretation is not allocator-identity proof. JSON mode requires EXPR and cannot mix module/debug-file/fast-link options. Module mode requires exact DWARF types and explicit link encoding; omitted EXPR resolves only the exact main_arena object. An explicit debug file must have validated GNU build-ID or declared debuglink/CRC association; no filename/path search guesses. --all follows only the declared next field, with global limits of 256 arenas, 4096 nodes and 1 MiB of confirmed reads. Partial reads and inconsistent observed links preserve confirmed data and errors; stale/cancel or failed final process proof discards output. No automatic libc/arena/tcache discovery or allocation/thread-ownership inference.",
	"bins":          "Two explicit modes: bins --layout-file FILE EXPR; or bins --module EXACT [--debug-file FILE] --fast-link plain|safe-link-12 [EXPR]. Options precede one literal/quoted address expression; JSON mode cannot mix module/debug-file/fast-link options. Uses the same strict schema or exact DWARF/debug association as arena; module mode may resolve an exact main_arena object when EXPR is omitted. Traverses declared fastbinsY and normal-bin fields only; tcache is not inspected. The chosen plain or safe-link-12 encoding is explicit, never inferred from libc version or pointer plausibility. Normal-bin sentinel and predecessor relationships are checked, and inconsistencies are observed facts, not claims of corruption or free-state. Global limits are 4096 nodes and 1 MiB; --all is only supported by arena. Confirmed prefixes retain read errors, while stale/cancel or failed final process proof discards output. No heap/allocator discovery or allocation/thread-ownership inference.",
	"backtrace":     "COUNT is a positive decimal frame limit, default 32 and maximum 256. Optional --abi strict|sysv must precede COUNT. Native Linux AMD64 defaults to the SysV AMD64 ABI: RSP=CFA and RBX/RBP/R12-R15 same_value when CFI does not override them. These are ABI rules, not stack or instruction guesses. --abi strict disables all implicit register rules, including RSP=CFA; use it for a non-SysV calling convention. --abi sysv explicitly selects the native default. ABI-derived values are labeled SysV, distinct from explicit CFI rules. The profile never switches automatically between frames. Uses the selected thread's exact registers, current InstructionPC, memory token and supported AMD64 DWARF CFI. Raw RIP, frame PC and CFI lookup PC remain distinct. Runtime PT_GNU_EH_FRAME metadata is primary; only an absent runtime header permits proven-file .eh_frame/.debug_frame fallback. Malformed metadata does not trigger another guessed source. No RBP-chain or stack-scan fallback or nearest-symbol inference. Function names come from exact containing symbols across the verified loaded scope, including locally available debug files only after exact build-ID/debuglink association. Alias candidates are displayed together and never used to choose frame control. Symbol lookup uses the formal CFI lookup PC; displayed offsets retain the unmodified frame PC. Unsupported CFI, missing proof, memory failures and a reached frame limit preserve only confirmed frames and return an error. Stale/cancel or final process-proof failure discards the result. A zero return PC is not a confirmed bottom; only an explicit undefined return-address rule confirms completion.",
	"stackframe":    "INDEX is a nonnegative decimal frame index, default 0 and maximum 255, relative to the selected thread. Optional --abi strict|sysv must precede INDEX. Native Linux AMD64 defaults to SysV AMD64 ABI rules; --abi strict disables implicit register rules. One fixed profile applies to the whole trace, without guessing mixed calling conventions. ABI-derived defaults are labeled SysV and explicit CFI rules are labeled CFI. Unwinds with the same proven CFI contract as backtrace, then shows that frame's CFA, saved-register rules, confirmed save locations and recovered scalar register values. This replaces the legacy guessed RBP/return-slot annotations; INDEX is not a raw stack-word count. Only the engine's exact requested-depth limit is suppressed once the requested frame is proven; other missing/unsupported metadata or memory errors remain errors. No frame-pointer or stack-content inference.",
	"disassemble":   "Legacy literal ADDRESS COUNT is also accepted with unsigned hex/octal/decimal values; expressions with spaced operators remain expressions. f/func/F/FUNC [--module EXACT] [EXPR] uses an exact ELF STT_FUNC extent with known nonzero size, maximum 65536 bytes and 4096 forward instructions. Default scope is the independently proven main executable. Another DSO requires an exact module ID/path or unique basename; EXPR uses the verified loaded symbol scope; qualify names with MODULE!NAME when needed. The --module option independently limits the function-extent source. No automatic cross-module fallback is performed. It does not stop at an inferred first return instruction; missing, ambiguous or invalid bounds are errors." + metadataProofHelp,
	"db":            "Legacy ADDRESS COUNT is also accepted when both are integer literals (hex, octal or decimal). For register/symbol expressions or spaces, use --count N EXPR; expression operands are not guessed to be counts.",
	"dd":            "Legacy ADDRESS COUNT is also accepted when both are integer literals (hex, octal or decimal). COUNT counts dwords. Otherwise use --count N EXPR.",
	"dq":            "Legacy ADDRESS COUNT is also accepted when both are integer literals (hex, octal or decimal). COUNT counts qwords. Otherwise use --count N EXPR.",
	"xxd":           "xxd dumps bytes (default 64); xxd dword dumps 32-bit units (default 16); xxd qword dumps 64-bit units (default 8). EXPR is one literal argument; quote expressions containing spaces. Positional COUNT is an unsigned hex/octal/decimal literal. --count N EXPR also accepts a raw spaced expression. All modes are limited to 4096 bytes.",
	"set":           "The selected thread's exact general-register name (optional $) selects a register destination for set only. The kernel may normalize register writes; success reports accepted/requested values, and regs shows actual values. Symbol expressions use the same verified loaded scope as print. Memory writes use exact stopped tokens and checked unsigned widths. No automatic retry or rollback follows a partial write; state is refreshed and failures remain errors.",
	"set8":          "DEST is a memory-address expression, VALUE is an unsigned 8-bit expression. Supply exactly two literal arguments, quoting any expression containing spaces. Unlike set, $REG in DEST means its memory address, not a register assignment.",
	"set16":         "DEST is a memory-address expression, VALUE is an unsigned 16-bit expression; little-endian. Quote each expression containing spaces. Width overflow and partial writes are errors.",
	"set32":         "DEST is a memory-address expression, VALUE is an unsigned 32-bit expression; little-endian. Quote each expression containing spaces. Width overflow and partial writes are errors.",
	"xor":           "Reads exactly 8 confirmed raw bytes at DEST, computes the XOR with an unsigned 64-bit KEY, then writes with the same memory token. Quote each expression containing spaces. A failed or partial write is not retried or reported as success.",
	"wp":            "wp EXPR [--size 1|2|4|8] [--access write|read-write] sets a selected-thread hardware watchpoint; default 1-byte read-write matches legacy wp. wp list shows owned records. wp d SLOT clears an owned slot 0..3 for the selected thread using its exact generation. Slots are thread-local and shared with hardware execution breakpoints; newborn threads do not inherit debugger ownership.",
	"simd":          "Reads the selected thread's validated XSAVE or FXSAVE state. Shows MXCSR, XMM, available YMM and 80-bit x87 values. Inactive components are explicitly initial state, not unsupported or fabricated live values. Unknown/malformed layouts return errors.",
	"xmm":           "With no arguments, retains legacy behavior and shows full SIMD state, identical to simd. INDEX is an explicit decimal number 0..15 for a focused XMM view. Data comes from the selected thread's exact extended-register token.",
	"ymm":           "With no arguments, retains legacy behavior and shows full SIMD state, identical to simd. INDEX is an explicit decimal number 0..15 for a focused YMM view. Unsupported AVX is distinct from an initialized/inactive component; component offsets come from validated metadata.",
	"vmmap":         "Reads verified primary-process /proc mappings. Columns are start/end/size/file offset/permissions/device/inode/path. Optional FILTER only filters displayed path text; it is never used to guess module identity or load bias. Failed reads and malformed metadata are errors.",
	"proc-info":     "Shows authoritative process/thread/namespace/resource observations, with explicit unavailable fields and preserved errors. Thread identity comes from the debugger snapshot. Relative processes may be independently running; their metadata does not prove a stopped or owned state.",
	"fd":            "With no argument, lists descriptors; FD is an explicit nonnegative decimal descriptor (including 0). Values come from verified /proc fd/fdinfo data. Unknown flags or failed metadata are not silently read-only or absent. Target paths are escaped.",
	"sym":           "Lists ELF symbol facts with explicit module/source proofs, or a configured ELF before launch. FILTER is a display-only substring filter; expression lookup remains exact and ambiguous names remain errors. Undefined/TLS/IFUNC/unknown-load-bias symbols are not fabricated runtime addresses. The exact AT_SYSINFO_EHDR vDSO contributes validated runtime dynamic symbols; static symbol tables and DWARF are not inferred." + metadataProofHelp + ttyPagerHelp,
	"got":           "Default main executable; all selects verified mapped images, --module EXACT selects one exact module ID/path or unique basename. Reports ELF relocation offsets/symbol facts and confirmed runtime slot values. No index-times-16 PLT inference, lazy-binding guess or unreadable-as-zero output. The runtime vDSO supports a verified no-relocation result, not guessed GOT slots." + metadataProofHelp,
	"checksec":      "Default stopped main executable or configured file before launch. all selects mapped images; --module EXACT uses exact module selection; --file PATH reads an explicit ELF. Canary/fortify output is symbol evidence, not proof that every function is protected. ELF metadata does not prove runtime enforcement; unknowns remain explicit. The runtime vDSO reports supported program-header/dynamic/security facts; absent static-symbol-table or DWARF file metadata remains unknown." + metadataProofHelp,
	"stdio":         "Reads standard-stream STT_OBJECT symbols with exact nonzero ELF sizes from verified modules. --module EXACT limits the source. This is a raw symbol-object view, not a guessed glibc FILE/vtable/wide-data decoder; unreadable or ambiguous objects return errors." + metadataProofHelp,
	"fs_base":       "Shows the actual selected-thread fs_base register and 128 raw bytes. No automatic canary, pointer-guard, TCB or TLS-variable labels are inferred from fixed offsets.",
	"telescope":     "[--depth N] EXPR [COUNT]. EXPR is one literal argument; quote expressions containing spaces. COUNT defaults to 128 qwords and is bounded at 512. Default depth is 4. --depth N (1..16) bounds confirmed qword following through readable verified mappings; repeated addresses are marked as cycles and the depth limit as .... No instruction classification or inferred frames. Required reads stop on errors, preserving only confirmed bytes." + addressTextHelp + ttyPagerHelp,
	"search-string": "Options precede STRING: --max-bytes N (default 268435456, maximum 1073741824), --max-matches N (default 4096, maximum 65536); -- ends option parsing. STRING is literal, quote spaces. Bounds are single literal arguments, with quoted expressions allowed. Searches confirmed raw bytes in eligible readable maps; gaps are outside scope and incomplete reads/limits return explicit partial errors. START alone ends at its containing eligible mapping.",
	"search-value":  "Same range/resource options as search-string, plus --size N (1..8) and --endian little|big before VALUE. Default is the shortest occupied little-endian byte representation, minimum one byte, matching legacy behavior. Explicit widths never truncate overflow. Results are byte matches, not inferred typed objects.",
	"findruction":   "Quote the literal Intel assembly snippet; options/bounds match search-string. With a live target, searches executable mappings using confirmed logical code bytes; without a target and without bounds, searches the configured ELF executable PT_LOAD file bytes. File virtual addresses/offsets are not asserted runtime addresses. Byte matches do not prove instruction boundaries. Assembly with unresolved relocations is rejected; no pager or TUI is launched.",
	"cyclic":        "Uses lowercase a..z, subsequence length 4, maximum 456976 bytes. -d/-D reports the first exact match of the supplied byte sequence; patterns shorter than 4 bytes may be nonunique. Legacy 0x values use the shortest occupied little-endian representation (1..8 bytes); --size N and --endian little|big make encoding explicit. No truncation, target access, or guessed crash width.",
	"asm":           "Supply one literal Intel-syntax snippet (quote spaces and semicolons). Uses GNU as --64, never a shell, and validates the resulting AMD64 .text bytes. ASCII instruction syntax and local labels only: directives, assignments, comments, quoted operands, backslashes and CR are unsupported. Source is limited to 65536 bytes, assembled text to 1048576 bytes; warnings or unresolved .text relocations are errors. Temporary files stay under the workspace cache and cancellation cleans the owned assembler process and all its descendants.",
	"chunk":         "Requires --layout glibc-amd64 explicitly. Reads the chosen malloc_chunk header layout at EXPR; --words N (0..4) requests extra raw stored qwords. Stored flags are decoded without asserting that this is a valid/live/free allocation. No allocator, arena, or address discovery.",
	"visual-heap":   "Requires --layout glibc-amd64 and explicit START END (exclusive END), one literal or quoted expression per endpoint. Walks at most 1 MiB and 4096 headers, with 16-byte alignment/minimum size 32/exact range checks. Invalid headers remain raw evidence plus an error. No automatic heap/arena/tcache discovery or allocation ownership inference.",
	"color":         "Displays the verified-mapping permission palette and modified-register style using the current renderer policy, including NO_COLOR and terminal detection. It does not toggle the policy. Unknown mappings remain uncolored; address values do not establish permissions.",
	"!":             "Only an explicit leading ! enables /bin/sh syntax. Its entire remainder, including spaces, quotes, escapes and newlines, is preserved. Ordinary file/run/start arguments remain literal. Empty shell commands are rejected. Only TTY stdin is temporarily leased to the command's dedicated foreground process group; the foreground group and terminal settings are restored afterward. Non-TTY command-script stdin is not forwarded: the shell receives /dev/null; use explicit <FILE redirection for scripted shell input. No NO_NEW_PRIVS restriction is added, so ordinary privilege-changing execs remain allowed. Cancellation and root-shell completion clean the owned shell process group and descendants; background jobs intentionally do not outlive the command. If an owned child cannot be terminated or reaped, ownership is retained and the command waits for its exit; incomplete cleanup is not reported as success. This is not a persistent interactive shell.",
}
