package debugger

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"fastdbg2/display"
	"fastdbg2/internal/cli"
	"fastdbg2/target"
)

type commandSpec struct {
	name        string
	arguments   string
	description string
	aliases     []string
}

var commandSpecs = []commandSpec{
	{"file", "PATH [ARGS...]", "Configure an AMD64 executable and literal arguments.", nil},
	{"attach", "PID", "Attach to an existing native AMD64 process.", nil},
	{"start", "[ARGS...]", "Start or restart an owned process; stop immediately after exec.", []string{"s", "S", "START"}},
	{"run", "[ARGS...]", "Start or restart, install breakpoints, then continue.", []string{"r", "R", "RUN"}},
	{"continue", "[--deliver|--suppress]", "Resume according to scheduler-locking; explicitly decide pending signals.", []string{"c", "cont", "C", "CONTINUE", "CONT"}},
	{"step", "[--deliver|--suppress]", "Step one selected-thread instruction according to scheduler-locking.", []string{"si", "stepi", "STEP"}},
	{"interrupt", "", "Recover an unconfirmed active operation by interrupting and waiting.", nil},
	{"break", "EXPR | pie OFFSET | list", "Keep a breakpoint expression; resolve it at start or verified loader publication.", []string{"b", "B", "BREAK"}},
	{"delete", "ID... | all", "Remove logical breakpoints and their installed native breakpoints.", nil},
	{"enable", "ID...", "Enable logical breakpoints, installing them when a target is stopped.", nil},
	{"disable", "ID...", "Disable logical breakpoints without deleting their expressions.", nil},
	{"context", "[regs|stack|code|threads ...] | on|off", "Show selected context panes or enable/disable context display.", []string{"ctx", "CONTEXT"}},
	{"regs", "[-s|--simple] [REG...]", "Show selected-thread registers with verified address chains; -s shows raw values.", []string{"registers"}},
	{"print", "EXPR", "Evaluate an integer, register or exact verified-symbol expression.", []string{"p", "P", "PRINT"}},
	{"memory", "[--count N] EXPR", "Read raw memory; default 64 bytes, maximum 4096.", nil},
	{"x", "EXPR", "Examine an explicit address; use x/8xb, x/2i or x/s.", nil},
	{"disassemble", "[--count N] [EXPR]", "Disassemble confirmed code; default location is selected InstructionPC.", []string{"disass", "disasm"}},
	{"stack", "[COUNT]", "Show raw qwords at the selected thread's RSP; default 8.", []string{"stk", "STACK", "STK"}},
	{"backtrace", "[--abi strict|sysv] [COUNT]", "Unwind selected-thread frames using supported, proven AMD64 CFI metadata.", []string{"bt", "BT", "BACKTRACE"}},
	{"stackframe", "[--abi strict|sysv] [INDEX]", "Show the proven CFA and saved-register rules for a CFI frame.", []string{"stkf", "STACKFRAME", "STKF"}},
	{"hexdump", "UNIT [--count N] EXPR", "Dump byte, word, dword or qword units, with an ASCII column.", []string{"hd"}},
	{"db", "[--count N] EXPR", "Dump bytes; default 64 units.", nil},
	{"dw", "[--count N] EXPR", "Dump 16-bit words; default 32 units.", nil},
	{"dd", "[--count N] EXPR", "Dump 32-bit dwords; default 16 units.", nil},
	{"dq", "[--count N] EXPR", "Dump 64-bit qwords; default 8 units.", nil},
	{"xxd", "[dword|qword] EXPR [COUNT]", "Legacy raw hex/ASCII dump; COUNT counts selected units.", nil},
	{"set8", "DEST VALUE", "Write one byte to an explicit memory address.", nil},
	{"set16", "DEST VALUE", "Write a little-endian 16-bit word to memory.", nil},
	{"set32", "DEST VALUE", "Write a little-endian 32-bit dword to memory.", nil},
	{"xor", "DEST KEY", "XOR one confirmed raw qword and write its resulting value.", nil},
	{"wp", "EXPR [OPTIONS] | list | d SLOT", "Manage selected-thread hardware watchpoints and show owned records.", nil},
	{"simd", "", "Show actual extended-register state for the selected thread.", []string{"SIMD"}},
	{"xmm", "[INDEX]", "Show SIMD state, or an explicitly selected XMM register.", []string{"XMM"}},
	{"ymm", "[INDEX]", "Show SIMD state, or an explicitly selected YMM register.", []string{"YMM"}},
	{"vmmap", "[FILTER]", "Show exact process mappings, optionally filtered by path text.", []string{"VMMAP"}},
	{"proc-info", "", "Show observed process, thread, namespace and resource metadata.", []string{"procinfo", "proc.info", "PROC-INFO", "PROCINFO"}},
	{"fd", "[FD]", "Show file descriptors and their confirmed flags and targets.", []string{"fds", "FD", "FDS"}},
	{"sym", "[FILTER]", "List exact ELF symbol facts; use less on an interactive terminal when available.", []string{"symbol", "SYM", "SYMBOL"}},
	{"got", "[all|--module EXACT]", "Show confirmed relocation slots and their raw values.", []string{"GOT"}},
	{"checksec", "[all|--module EXACT|--file PATH]", "Show ELF mitigation-related evidence without inferring runtime protection.", []string{"CHECKSEC"}},
	{"stdio", "[--module EXACT]", "Dump exact standard-stream symbol objects without guessing FILE layouts.", []string{"stdio-dump", "STDIO", "STDIO-DUMP"}},
	{"fs_base", "", "Show selected-thread FS base and 128 raw bytes at that address.", []string{"fs"}},
	{"telescope", "[--depth N] EXPR [COUNT]", "Show verified address chains; use less on an interactive terminal when available.", []string{"tel"}},
	{"search-string", "[OPTIONS] STRING [START [END]]", "Search exact literal bytes in readable mappings.", nil},
	{"search-value", "[OPTIONS] VALUE [START [END]]", "Search the explicitly encoded integer bytes in readable mappings.", nil},
	{"findruction", "[OPTIONS] ASM [START [END]]", "Search assembled byte sequences; matches do not prove instruction boundaries.", nil},
	{"cyclic", "LENGTH | -d|-D [OPTIONS] VALUE", "Generate or locate bytes in the lowercase De Bruijn B(26,4) sequence.", nil},
	{"asm", "INTEL_ASM", "Assemble a literal AMD64 instruction snippet without unresolved relocations.", nil},
	{"chunk", "--layout glibc-amd64 [--words N] EXPR", "Interpret bytes using an explicitly requested chunk layout.", []string{"CHUNK"}},
	{"arena", "--layout-file FILE [--all] EXPR | --module EXACT [OPTIONS]", "Inspect arena fields and explicit links using validated layout metadata.", []string{"arenas", "ARENA", "ARENAS"}},
	{"bins", "--layout-file FILE EXPR | --module EXACT [OPTIONS]", "Inspect declared fastbin and normal-bin links without allocator guesses.", []string{"BINS"}},
	{"visual-heap", "--layout glibc-amd64 START END", "Walk an explicit chunk-layout range; no heap discovery or allocation inference.", []string{"vis", "VIS", "VISUAL-HEAP"}},
	{"color", "", "Show the verified-permission color and modified-register legend.", []string{"COLOR"}},
	{"!", "SHELL_COMMAND", "Run an explicit shell command; ordinary target arguments remain literal.", nil},
	{"threads", "", "List known threads and their process identities.", nil},
	{"thread", "[ID] | tid TID | apply ...", "Select by logical ID, explicitly select by TID, or inspect multiple threads.", []string{"t"}},
	{"info", "threads | registers [REG...] | breakpoints", "Show thread, register or breakpoint information.", []string{"i"}},
	{"set", "DEST [=] VALUE | scheduler-locking MODE", "Write a selected register or qword, or set the resume policy.", nil},
	{"show", "scheduler-locking", "Show the resume policy; recording and replay execution are unsupported.", nil},
	{"kill", "", "Kill the current target and release the debugger session.", nil},
	{"detach", "", "Restore breakpoints, deliver pending signals and detach.", nil},
	{"help", "[COMMAND]", "Show command help, aliases and supported arguments.", nil},
	{"quit", "", "Kill a launched target or detach an attached target, then exit.", []string{"exit", "q"}},
}

func CommandNames() []string {
	var names []string
	for _, command := range commandSpecs {
		names = append(names, command.name)
		names = append(names, command.aliases...)
	}
	for _, name := range []string{"print", "p"} {
		for _, format := range []string{"x", "d", "u", "o", "t"} {
			names = append(names, name+"/"+format)
		}
	}
	return names
}

func canonicalCommand(name string) (commandSpec, bool) {
	if base, suffix, found := strings.Cut(name, "/"); found {
		if base == "x" && suffix != "" {
			name = base
		} else if (base == "p" || base == "print") && len(suffix) == 1 && strings.Contains("xduot", suffix) {
			name = base
		} else {
			return commandSpec{}, false
		}
	}
	for _, command := range commandSpecs {
		if name == command.name || slices.Contains(command.aliases, name) {
			return command, true
		}
	}
	return commandSpec{}, false
}

func (c *Controller) Configure(path string, args []string) error {
	if c.active != nil {
		return fmt.Errorf("operation completion is unconfirmed; cleanup is required: %w", target.ErrBusy)
	}
	if c.session != nil && c.session.State() != target.StateExited {
		return fmt.Errorf("kill or detach the current target before configuring a file: %w", target.ErrInvalidState)
	}
	if path == "" || strings.IndexByte(path, 0) >= 0 {
		return fmt.Errorf("executable path is required: %w", target.ErrInvalidArgument)
	}
	for _, arg := range args {
		if strings.IndexByte(arg, 0) >= 0 {
			return fmt.Errorf("argument contains a NUL byte: %w", target.ErrInvalidArgument)
		}
	}
	resolved, err := exec.LookPath(path)
	if err != nil {
		return err
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return err
	}
	if err := preflightAMD64(resolved); err != nil {
		return err
	}
	c.path, c.args = resolved, slices.Clone(args)
	return nil
}

func (c *Controller) Execute(ctx context.Context, name, rawArgs string) (bool, error) {
	if ctx == nil {
		return false, target.ErrInvalidArgument
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if name == "" {
		return false, nil
	}
	command, ok := canonicalCommand(name)
	if !ok {
		return false, fmt.Errorf("unknown command: %q", name)
	}
	if command.arguments == "" && strings.TrimSpace(rawArgs) != "" {
		return false, fmt.Errorf("%s takes no arguments: %w", command.name, target.ErrInvalidArgument)
	}
	switch command.name {
	case "file":
		args, err := cli.ParseArgs(rawArgs)
		if err != nil {
			return false, err
		}
		if len(args) == 0 {
			return false, fmt.Errorf("usage: file PATH [ARGS...]: %w", target.ErrInvalidArgument)
		}
		if err := c.Configure(args[0], args[1:]); err != nil {
			return false, err
		}
		return false, c.writef("Configured native amd64 executable %q with arguments %q\n", c.path, c.args)
	case "attach":
		pid, err := positiveInt(rawArgs, "PID")
		if err != nil {
			return false, err
		}
		return false, c.attachProcess(ctx, pid)
	case "start", "run":
		return false, c.start(ctx, rawArgs, command.name == "run")
	case "continue", "step":
		return false, c.resume(ctx, rawArgs, command.name == "step")
	case "interrupt":
		return false, c.interruptActive(ctx)
	case "break":
		subcommand, expression := cli.SplitCommand(strings.TrimSpace(rawArgs))
		if (subcommand == "list" || subcommand == "l" || subcommand == "LIST" || subcommand == "L") && strings.TrimSpace(expression) == "" {
			return false, c.listBreakpoints()
		}
		if subcommand == "pie" || subcommand == "PIE" {
			return false, c.addPIEBreakpoint(ctx, expression)
		}
		return false, c.addBreakpoint(ctx, rawArgs)
	case "delete":
		return false, c.deleteBreakpoints(ctx, rawArgs)
	case "enable", "disable":
		return false, c.setBreakpointsEnabled(ctx, rawArgs, command.name == "enable")
	case "context":
		return false, c.showContext(ctx, rawArgs)
	case "regs":
		return false, c.showRegisters(ctx, rawArgs)
	case "print":
		_, format, _ := strings.Cut(name, "/")
		return false, c.showPrint(ctx, format, rawArgs)
	case "memory":
		return false, c.showMemory(ctx, rawArgs)
	case "x":
		_, spec, _ := strings.Cut(name, "/")
		return false, c.showExamine(ctx, spec, rawArgs)
	case "disassemble":
		return false, c.showDisassemble(ctx, rawArgs)
	case "stack":
		return false, c.showStack(ctx, rawArgs)
	case "backtrace":
		return false, c.showBacktrace(ctx, rawArgs)
	case "stackframe":
		return false, c.showStackFrame(ctx, rawArgs)
	case "hexdump":
		return false, c.showHexdump(ctx, "", rawArgs)
	case "db", "dw", "dd", "dq":
		unit := map[string]string{"db": "byte", "dw": "word", "dd": "dword", "dq": "qword"}[command.name]
		return false, c.showLegacyDump(ctx, unit, rawArgs)
	case "xxd":
		return false, c.showLegacyXXD(ctx, rawArgs)
	case "set8", "set16", "set32":
		bits := map[string]int{"set8": 8, "set16": 16, "set32": 32}[command.name]
		return false, c.commandSet(ctx, rawArgs, bits)
	case "xor":
		return false, c.commandXor(ctx, rawArgs)
	case "wp":
		return false, c.commandWatch(ctx, rawArgs)
	case "simd", "xmm", "ymm":
		return false, c.showSIMD(ctx, command.name, rawArgs)
	case "vmmap":
		return false, c.showVMMap(ctx, rawArgs)
	case "proc-info":
		return false, c.showProcInfo(ctx)
	case "fd":
		return false, c.showFDs(ctx, rawArgs)
	case "sym":
		return false, c.showSymbols(ctx, rawArgs)
	case "got":
		return false, c.showGOT(ctx, rawArgs)
	case "checksec":
		return false, c.showChecksec(ctx, rawArgs)
	case "stdio":
		return false, c.showStdio(ctx, rawArgs)
	case "fs_base":
		return false, c.showFSBase(ctx, rawArgs)
	case "telescope":
		return false, c.showTelescope(ctx, rawArgs)
	case "search-string", "search-value", "findruction":
		return false, c.commandSearch(ctx, command.name, rawArgs)
	case "cyclic":
		return false, c.showCyclic(ctx, rawArgs)
	case "asm":
		return false, c.showAssembly(ctx, rawArgs)
	case "chunk":
		return false, c.showHeapChunk(ctx, rawArgs)
	case "arena":
		return false, c.showArenas(ctx, rawArgs)
	case "bins":
		return false, c.showBins(ctx, rawArgs)
	case "visual-heap":
		return false, c.showVisualHeap(ctx, rawArgs)
	case "color":
		return false, c.showColorLegend()
	case "!":
		return false, c.commandShell(ctx, rawArgs)
	case "threads":
		return false, c.showThreads()
	case "thread":
		return false, c.commandThread(ctx, rawArgs)
	case "info":
		return false, c.showInfo(ctx, rawArgs)
	case "set", "show":
		setting, value := cli.SplitCommand(rawArgs)
		if setting != "scheduler-locking" {
			if command.name == "set" {
				return false, c.commandSet(ctx, rawArgs, 64)
			}
			return false, fmt.Errorf("usage: %s %s: %w", command.name, command.arguments, target.ErrInvalidArgument)
		}
		if command.name == "set" {
			return false, c.setSchedulerLocking(value)
		}
		if strings.TrimSpace(value) != "" {
			return false, fmt.Errorf("usage: show scheduler-locking: %w", target.ErrInvalidArgument)
		}
		return false, c.showSchedulerLocking()
	case "kill":
		return false, c.releaseTarget(true)
	case "detach":
		return false, c.releaseTarget(false)
	case "help":
		return false, c.showHelp(rawArgs)
	case "quit":
		if err := c.Close(); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, target.ErrUnsupported
}

func positiveInt(input, name string) (int, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return 0, fmt.Errorf("%s is required: %w", name, target.ErrInvalidArgument)
	}
	for _, b := range []byte(input) {
		if b < '0' || b > '9' {
			return 0, fmt.Errorf("%s must be a positive decimal integer: %w", name, target.ErrInvalidArgument)
		}
	}
	value, err := strconv.ParseUint(input, 10, strconv.IntSize-1)
	if err != nil || value == 0 {
		return 0, fmt.Errorf("invalid %s %q: %w", name, input, errors.Join(target.ErrInvalidArgument, err))
	}
	return int(value), nil
}

func (c *Controller) refresh() (target.Snapshot, error) {
	if c.session == nil {
		return target.Snapshot{}, fmt.Errorf("no target; use start or attach: %w", target.ErrInvalidState)
	}
	snapshot, err := c.session.Snapshot()
	if err != nil {
		return target.Snapshot{}, err
	}
	if snapshot.Architecture != target.AMD64 {
		return target.Snapshot{}, fmt.Errorf("command interface supports native amd64 only, got %q: %w", snapshot.Architecture, target.ErrUnsupported)
	}
	if c.snapshot.Memory.Space != (target.SpaceRef{}) && c.snapshot.Memory.Space != snapshot.Memory.Space {
		c.invalidateBreakpoints()
		c.image = imageState{}
	}
	if snapshot.State == target.StateExited {
		c.invalidateBreakpoints()
	}
	c.snapshot = snapshot
	return snapshot, nil
}

func (c *Controller) stopped() (target.Snapshot, target.ThreadInfo, error) {
	if c.active != nil {
		return target.Snapshot{}, target.ThreadInfo{}, fmt.Errorf("operation completion is unconfirmed; kill or detach for cleanup: %w", target.ErrBusy)
	}
	snapshot, err := c.refresh()
	if err != nil {
		return snapshot, target.ThreadInfo{}, err
	}
	if snapshot.State != target.StateStopped {
		return snapshot, target.ThreadInfo{}, fmt.Errorf("target is %s: %w", snapshot.State, target.ErrInvalidState)
	}
	for _, thread := range snapshot.Threads {
		if thread.Ref != c.selected {
			continue
		}
		if thread.Process != snapshot.Process {
			return snapshot, target.ThreadInfo{}, fmt.Errorf("selected thread is not in the primary process: %w", target.ErrUnsupported)
		}
		if thread.State != target.StateStopped || thread.Exiting || thread.Listening {
			return snapshot, target.ThreadInfo{}, fmt.Errorf("selected thread %d is not inspectable: %w", thread.TID, target.ErrInvalidState)
		}
		return snapshot, thread, nil
	}
	return snapshot, target.ThreadInfo{}, fmt.Errorf("select a stopped primary-process thread with thread ID or thread tid TID: %w", target.ErrNotFound)
}

func (c *Controller) showInfo(ctx context.Context, rawArgs string) error {
	name, args := cli.SplitCommand(rawArgs)
	switch name {
	case "registers":
		return c.showRegisters(ctx, args)
	case "threads", "breakpoints":
		if strings.TrimSpace(args) != "" {
			return fmt.Errorf("info %s takes no arguments: %w", name, target.ErrInvalidArgument)
		}
		if name == "threads" {
			return c.showThreads()
		}
		return c.listBreakpoints()
	default:
		return fmt.Errorf("usage: info threads | registers [REG...] | breakpoints: %w", target.ErrInvalidArgument)
	}
}

func (c *Controller) showHelp(arguments ...string) error {
	if len(arguments) > 1 {
		return target.ErrInvalidArgument
	}
	var requested string
	if len(arguments) == 1 {
		requested = strings.TrimSpace(arguments[0])
	}
	if requested != "" {
		name, subcommand := cli.SplitCommand(requested)
		command, ok := canonicalCommand(name)
		if !ok {
			return fmt.Errorf("unknown help command %q: %w", name, target.ErrInvalidArgument)
		}
		if subcommand != "" {
			switch command.name {
			case "info":
				if subcommand != "threads" && subcommand != "registers" && subcommand != "breakpoints" {
					return fmt.Errorf("unknown info command %q: %w", subcommand, target.ErrInvalidArgument)
				}
			case "set", "show":
				if subcommand != "scheduler-locking" {
					return fmt.Errorf("unknown setting %q: %w", subcommand, target.ErrInvalidArgument)
				}
			case "xxd":
				if subcommand != "dword" && subcommand != "qword" {
					return fmt.Errorf("unknown xxd unit %q: %w", subcommand, target.ErrInvalidArgument)
				}
			case "wp":
				if subcommand != "list" && subcommand != "d" {
					return fmt.Errorf("unknown wp command %q: %w", subcommand, target.ErrInvalidArgument)
				}
			case "break":
				if !slices.Contains([]string{"pie", "PIE", "list", "l", "L", "LIST"}, subcommand) {
					return fmt.Errorf("unknown break command %q: %w", subcommand, target.ErrInvalidArgument)
				}
			case "disassemble":
				if !slices.Contains([]string{"f", "func", "F", "FUNC"}, subcommand) {
					return fmt.Errorf("unknown disassembly mode %q: %w", subcommand, target.ErrInvalidArgument)
				}
			case "thread":
				if subcommand != "apply" && subcommand != "tid" {
					return fmt.Errorf("unknown thread command %q: %w", subcommand, target.ErrInvalidArgument)
				}
			default:
				return fmt.Errorf("usage: help COMMAND: %w", target.ErrInvalidArgument)
			}
		}
		return c.showCommandHelp(command)
	}
	if err := c.writef("%s\n", c.renderer.Text(display.StyleHeading, "Commands:")); err != nil {
		return err
	}
	for _, command := range commandSpecs {
		name := command.name
		if len(command.aliases) > 0 {
			name += " (" + strings.Join(command.aliases, ", ") + ")"
		}
		if err := c.writef("  %-24s %-39s %s\n", name, command.arguments, command.description); err != nil {
			return err
		}
	}
	return c.writef("\nNative amd64 only. start stops after exec, not at main; run restarts, continue does not.\nstep/si/stepi execute one instruction, not one source line. Legacy s/S mean start, not GDB source-line step. n/ni/next/finish are not aliases.\nScheduler-locking defaults to replay: normal execution is unlocked; recording/replay is unsupported.\nthread ID selects the logical thread ID; thread tid TID explicitly selects an OS thread ID.\nTarget arguments are literal: quotes and backslash escapes are accepted; no shell expansion is performed except by the explicit ! command.\nExpressions accept integers, $registers and exact symbols from the verified loaded scope.\nBacktick-quote MODULE!NAME or NAME@VERSION; different symbol addresses are ambiguous, never main-first guesses.\nSymbolic breakpoints are re-evaluated on restart and may wait for verified startup loader publication.\n--deliver forwards each resumed thread's pending signal; --suppress explicitly discards those signals.\nMemory commands require explicit addresses except stack and disassemble; x does not remember prior formats or addresses.\nContext is shown at stops by default; context off hides automatic and manual context until context on.\nFull context clears interactive screens; named panes and redirected output do not.\nAn empty interactive line repeats the previous raw command, including failed commands and !; whitespace-only lines are unknown commands. Script blank lines never repeat.\nThe interactive prompt shows the confirmed selected-thread instruction address, or [fastDbg2]$ when unavailable.\nsym and telescope use less on real terminals; pipes print directly. Missing less gives a warning and direct output.\nLaunch uses the debugger's OS stdin/stdout/stderr. Do not share command-script stdin with a target that reads stdin.\nA failed shutdown keeps the session available for cleanup; EOF and termination use the same ownership policy as quit.\nbacktrace/stackframe require supported, proven CFI metadata; no RBP-chain or stack-scan fallback is used.\narena/bins require an explicit validated layout-file and address, or exact module/DWARF metadata with an explicit fast-link policy; no automatic allocator or tcache discovery is performed.\nUse help COMMAND for command syntax, defaults and limits.\n")
}

func (c *Controller) showCommandHelp(command commandSpec) error {
	usage := strings.TrimSpace(command.name + " " + command.arguments)
	if command.name == "x" {
		usage = "x/[COUNT][FORMAT][UNIT] EXPR"
	}
	if err := c.writef("Usage: %s\n%s\n", usage, command.description); err != nil {
		return err
	}
	if len(command.aliases) > 0 {
		if err := c.writef("Aliases: %s\n", strings.Join(command.aliases, ", ")); err != nil {
			return err
		}
	}
	detail := commandDetails[command.name]
	if legacy := legacyCommandDetails[command.name]; legacy != "" {
		if detail != "" {
			detail += "\n"
		}
		detail += legacy
	}
	if detail != "" {
		return c.writef("%s\n", detail)
	}
	return nil
}

const symbolExpressionHelp = " Names are exact, case-sensitive definitions in the verified loaded scope, not substring or main-first choices. Backtick-quote `MODULE!NAME`, `NAME@VERSION` or `MODULE!NAME@VERSION` (module ID, exact path or unique basename; `@@` is unsupported). Same-address aliases collapse; different addresses are ambiguous. Library-local names need a module qualifier. TLS/IFUNC addresses are not guessed. Verified main symbols work at exec; library symbols may await loader publication."

const addressTextHelp = " Visible leaf text is a nonempty, NUL-terminated byte sequence at the exact source address of the displayed qword, or at a readable guard tail too short for a qword. It must terminate within 256 bytes and be valid UTF-8 with every rune satisfying unicode.IsPrint. This is a byte predicate, not a string-type guess or an immediate-register fallback. Quotes and backslashes are escaped; display is bounded to 64 columns including quotes and explicit ellipsis, after the entire bounded string is confirmed. Preview reads reuse confirmed bytes and are separately limited to 32 KiB and 2048 calls per view. Missing terminators, nonprintable bytes, unavailable previews and exhausted preview budgets omit the annotation; stale/cancel discards the view. Pointer chains, cycles, depth limits and required qword errors are unchanged."
const hexRowsHelp = " Rows contain up to 16 bytes and shrink by whole units to fit the terminal width; the requested count and total bytes are unchanged."

var commandDetails = map[string]string{
	"file":        "PATH and ARGS are literal, with quotes and backslash escapes but no shell expansion. Release a live target before changing files.",
	"attach":      "PID is a positive decimal OS process ID. Only native little-endian ELF64 AMD64 is supported. Attached targets are detached on quit or EOF.",
	"start":       "Stops immediately after exec, not at main. Legacy s/S aliases mean start, not GDB source-line step. Restarts only owned targets. With no arguments, reuses saved target arguments. Resolvable breakpoints are installed; symbolic breakpoints awaiting verified startup loader publication remain pending without advancing past exec.",
	"run":         "Starts or restarts an owned target, installs resolvable enabled breakpoints, then resumes according to scheduler-locking. Loader-pending symbols are retried at a verified rendezvous; other installation or loader errors prevent automatic resume.",
	"continue":    "Pending signals on resumed threads require --deliver or --suppress. off/replay/step resume the primary process, including newborn threads; on resumes only the selected thread. Pending symbolic breakpoints are retried at verified loader rendezvous; hard resolution errors return control to the user.",
	"step":        "One selected-thread machine instruction; this is not GDB source-line step. off/replay allow peer execution; on/step keep peers stopped. A different thread may stop first. Signals require an explicit decision for each resumed thread.",
	"interrupt":   "Retries interrupting an operation whose completion is unconfirmed, then waits for its result. It does not create a stop result or forget an unfinished operation. Ctrl-C interrupts an ordinary running command.",
	"break":       "break EXPR persists across restarts. Before start, unresolved expressions are pending. With a target, only a verified unpublished startup loader may defer resolution; run/continue retry at verified hooks. This pending form requires one bare or backtick-quoted symbol; unresolved compound/register-dependent expressions are unsupported. Resolution retries require a verified hook stop or completed instruction-step arrival, not loader-state polling; step stops remain visible. Ordinary constructors can be caught, but earlier IFUNC/audit calls are not guaranteed. Ambiguous/unsupported/corrupt scopes are errors. After consistent publication, a still-missing symbol is an error; the stop is retained and future dlopen is not silently awaited. Unload/rebinding tracking is not provided. User stops and signals remain visible. break list (l/L/LIST) or info breakpoints lists positive decimal IDs. break pie OFFSET adds the exact main load bias to an unsigned ELF virtual address; ET_EXEC has bias zero, not its first mapping start. Runtime symbols are not automatically unbased." + symbolExpressionHelp,
	"delete":      "Specify positive decimal breakpoint IDs or the single word all. No arguments is an error. All IDs are validated before changes; native failures retain remaining breakpoint state for cleanup.",
	"enable":      "Specify one or more positive decimal breakpoint IDs. Enabled expressions are installed in a stopped target or retained pending until a target starts.",
	"disable":     "Specify one or more positive decimal breakpoint IDs. Restores installed bytes and retains each expression and ID for later enable or restart.",
	"context":     "With no arguments, shows registers, raw stack values with bounded chains, current code and threads, in that order. Named panes may be regs/registers, stack, code or threads. context on/off enables or hides automatic and manual context (default on); standalone regs and other commands remain available. Full context clears an interactive terminal only after snapshot validation; named panes append without clearing. Default address chains follow at most 4 confirmed qwords in verified readable mappings; exact symbols and permissions are annotated without type/frame or per-thread stop-reason inference. Headers fit the terminal width, defaulting to 100 columns for redirected output." + addressTextHelp,
	"regs":        "REG names may have an optional $ prefix. -s/--simple shows raw values without mappings, symbols or address-chain reads. The default follows up to 4 confirmed qword links in verified readable mappings, annotates exact symbols and marks cycles. Overlapping true symbol labels are shown as a bounded candidate set, not silently chosen as unique. Register changes are highlighted only across stop/register revisions of the same thread and address space. Unknown or duplicate names are errors; requested order is preserved. Register RIP is raw, not the software-breakpoint instruction address." + addressTextHelp,
	"print":       "print/p EXPR displays HEX, DEC, OCT and BIN. print/x, /d, /u, /o, /t (also p/...) select hex, signed decimal, unsigned decimal, octal or binary. Constants work without a target; register/symbol expressions require a stopped selected thread. Expressions use checked unsigned 64-bit arithmetic, not GDB C-type width inference; negative literals are unsupported. /d reinterprets the result as int64. Put the format in the command token (p/x, not p /x). No value history is retained." + symbolExpressionHelp,
	"memory":      "Default 64 bytes; --count is a positive decimal count from 1 through 4096 and must precede EXPR. Displays raw target bytes, including installed software-breakpoint bytes." + symbolExpressionHelp,
	"x":           "Use x/8xb EXPR for eight hex bytes, x/2i EXPR for two instructions, or x/s EXPR for an explicit string read. Default x is one hexadecimal 32-bit word. COUNT is a positive decimal count; formats x/d/u/o/t/c/i/s and units b/h/w/g are supported. Numeric reads are limited to 4096 bytes; i to 256 instructions; s to 4096 bytes across all requested NUL-terminated strings. c and s support byte units only; i ignores an explicit unit. EXPR is always required; previous formats and addresses are not reused. Code uses logical breakpoint bytes, not inferred instructions.",
	"disassemble": "EXPR defaults to the selected thread's current InstructionPC. Default 8 instructions, maximum 256; --count N must precede EXPR. Reads confirmed logical code bytes and decodes forward only; raw RIP and InstructionPC remain distinct. No function-boundary or backward decoding inference.",
	"stack":       "COUNT is a positive decimal number of qwords (default 8, maximum 512). Uses the actual selected thread RSP and raw memory, with RSP/RBP address labels, byte offsets and default chains of at most 4 confirmed qwords through verified readable mappings. Use memory or x for raw-only memory rows. No type or frame inference is performed." + addressTextHelp,
	"hexdump":     "UNIT is byte, word, dword or qword (1, 2, 4 or 8 bytes). Default counts are 64, 32, 16 and 8 respectively. --count N counts units and must precede EXPR; at most 4096 bytes. Displays little-endian units and printable ASCII from confirmed raw bytes." + hexRowsHelp,
	"db":          "Equivalent to hexdump byte. Default 64 bytes; --count N precedes EXPR, with a 4096-byte maximum." + hexRowsHelp,
	"dw":          "Equivalent to hexdump word. Default 32 words; --count N precedes EXPR, with a 4096-byte maximum." + hexRowsHelp,
	"dd":          "Equivalent to hexdump dword. Default 16 dwords; --count N precedes EXPR, with a 4096-byte maximum." + hexRowsHelp,
	"dq":          "Equivalent to hexdump qword. Default 8 qwords; --count N precedes EXPR, with a 4096-byte maximum." + hexRowsHelp,
	"threads":     "Lists logical thread IDs, OS TIDs, process identities, state and each thread's own stop reason. The selected thread is marked with *. Exited and foreign-process threads are not implicitly selectable.",
	"thread":      "thread without arguments shows the selected thread. thread ID uses a positive decimal logical ThreadRef.ID, never a TID fallback. thread tid TID explicitly selects an OS TID. Only stopped inspectable primary-process threads can be selected. thread apply all|ID... [-c] COMMAND accepts read-only commands on inspectable primary-process threads; all visits descending IDs, all -ascending visits ascending IDs, and explicit IDs keep their order. -c continues after errors while retaining them. Selection is restored even on errors. threads/info threads still list all known processes and threads.",
	"info":        "info threads is threads; info registers [REG...] is regs; info breakpoints is break list. Only these explicit subcommands are supported.",
	"set":         "set scheduler-locking off|on|step|replay. off: all primary-process threads may run. on: selected thread only. step: selected only during instruction steps, all otherwise. replay is the default and is off during normal execution; recording/replay execution is unsupported.",
	"show":        "show scheduler-locking reports the current policy. Default replay means unlocked normal execution; recording/replay execution is unsupported.",
	"kill":        "Kills the target and releases its debugger session only after cleanup succeeds. Failures retain the session for retry.",
	"detach":      "Restores debugger breakpoints, delivers pending signals and detaches. Failures retain the session for retry.",
	"help":        "Use help COMMAND or help info threads/registers/breakpoints, help thread apply/tid, or help set/show scheduler-locking. Command names and aliases are explicit; only registered legacy uppercase spellings are accepted.",
	"quit":        "Kills a launched target or detaches an attached target. EOF and termination use the same ownership policy. Failed cleanup keeps the session available for retry.",
}
