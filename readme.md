# fastDbg2

## QEMU amd64 kernel debugging

Start an owned QEMU VM with its GDB stub enabled and the CPUs stopped:

```sh
qemu-system-x86_64 -accel tcg -cpu max -m 512M -smp 2 \
  -kernel bzImage -append 'nokaslr console=ttyS0' \
  -S -gdb tcp:127.0.0.1:12345 -nographic

./fastdbg2 --qemu 127.0.0.1:12345 --vmlinux ./vmlinux --kernel-slide 0
```

`-qemu -qemu-host HOST -qemu-port PORT` is also accepted; the default is
`localhost:12345`. Unix sockets use `--qemu unix:/path/to/gdb.sock`.
`-f vmlinux` can replace `--vmlinux` in QEMU mode.

```text
b start_kernel
c
context
regs -s rip rsp cr3 cr4 efer
pt $rip
vmmap
bt
stackframe
sym start_kernel
tel $rsp 16
thread 2
thread apply all regs -s rip
```

The original fastDbg QEMU command set is supported, including `pt`, `kbase`,
register/memory writes, searches, address walks, context and backtrace. Shared
commands also provide symbols, ELF inspection, assembly, findruction, SIMD,
watchpoints, vCPU selection, breakpoint management and terminal paging.

- Thread IDs are remote **vCPU IDs**, not guest task IDs or host PIDs. Memory
  inspection uses the selected vCPU's address space. Execution is all-stop;
  `set scheduler-locking on|off|step|replay` controls peer resume.
- Instruction decoding requires an active long-mode vCPU; firmware running
  before long mode is not decoded as amd64.
- `start` displays the stopped VM; `run` continues it. Neither resets QEMU.
- `vmmap` shows actual page-table mappings and physical starts, not guest VMAs
  or host mappings. `pt EXPR` supports 4-/5-level AMD64 paging and 4 KiB, 2 MiB
  and 1 GiB pages. Displayed permissions are page-table permissions; additional
  CPL, SMEP, SMAP and PKU restrictions are not represented as VMA permissions.
- Symbols require the matching, explicitly supplied `vmlinux` and an explicit
  relocation slide. `0` means linked addresses (`nokaslr`). For KASLR, supply
  the actual slide. `kbase` reports the lowest ELF load address plus that slide;
  it does not search for a plausible kernel base. Numeric debugging works
  without a local ELF. Per-CPU symbol offsets require explicit base arithmetic.
- Backtrace uses the ORC format identified by `.orc_header`
  `fe5d32bf581bd63b2ca9a5c65ba5a625eab3fe24`, including call and exception frames.
  Without ORC, it uses `.eh_frame` or `.debug_frame`. Unknown formats, unloaded
  module metadata and unavailable rules are errors, not stack-scan or inferred
  frame-pointer fallbacks. `--abi` affects DWARF implicit rules only.
- SIMD displays registers exposed by the remote target XML. Unexposed YMM
  upper lanes are unavailable, not zero. Remote watchpoints are VM-wide;
  slots 0–3 are debugger-owned handles, not allocations of guest DR registers.
  Accelerator support is checked through the remote protocol.
- `fd`, `stdio`, `arena`, `bins`, `vis`, native attach and native kill do not
  apply to a kernel target. They report that distinction instead of inspecting
  the host or interpreting kernel allocators as glibc.
- Ctrl-C interrupts execution. Tab completes commands, Enter repeats the last
  command, and long interactive views use `less`. `quit`, EOF and `detach`
  remove owned remote breakpoints/watchpoints and leave QEMU running.

## Tests

`go test ./...` includes a self-contained 64-bit multiboot fixture, 58
kernel-applicable command checks on QEMU/TCG, page-table tests, ORC decoding,
remote protocol error handling and native regressions. QEMU tests require
`qemu-system-x86_64`, GNU `as` and `ld`.

To test a real Linux ORC kernel as well:

```sh
FASTDBG2_TEST_KERNEL=/path/to/bzImage \
FASTDBG2_TEST_VMLINUX=/path/to/vmlinux \
go test ./internal/debugger -run 'TestQEMU' -v
```

Use `TMPDIR` and `GOTMPDIR` under the workspace when test artifacts must stay
inside it.

Protocol references: [QEMU GDB stub](https://www.qemu.org/docs/master/system/gdb.html),
[GDB remote packets](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Packets.html).
