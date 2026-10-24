.text
.global _start
.type _start,@function
_start:
 .cfi_startproc
 .cfi_undefined %rip
 movabs $0xffff800000700000,%rsp
 xor %ebp,%ebp
 call parent
 call parent
.global idle
idle:
 pause
 jmp idle
 .cfi_endproc
.size _start,.-_start
.global parent
.type parent,@function
parent:
 .cfi_startproc
 push %rbp
 .cfi_def_cfa_offset 16
 .cfi_offset %rbp,-16
 mov %rsp,%rbp
 .cfi_def_cfa_register %rbp
 call checkpoint
.global write_checkpoint
write_checkpoint:
 movq $0x42,scratch(%rip)
 pop %rbp
 .cfi_def_cfa %rsp,8
 ret
 .cfi_endproc
.size parent,.-parent
.global checkpoint
.type checkpoint,@function
checkpoint:
 .cfi_startproc
 nop
 ret
 .cfi_endproc
.size checkpoint,.-checkpoint
.data
.align 8
.global scratch, message, chain
.type scratch,@object
scratch:
 .quad 0x1122334455667788,0,0,0
.size scratch,.-scratch
.type message,@object
message:
 .asciz "QEMU-KERNEL-TEST"
.size message,.-message
.align 8
.type chain,@object
chain:
 .quad message
.size chain,.-chain
