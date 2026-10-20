.text
.global _start
_start:
    mov (%rsp), %rax
    lea 8(%rsp), %r12
    lea 16(%rsp,%rax,8), %r13
    sub $16, %rsp
    mov $72, %eax
    mov $5, %edi
    mov $2, %esi
    mov $1, %edx
    syscall
    test %rax, %rax
    js fail
    mov $72, %eax
    mov $3, %edi
    syscall
    test %rax, %rax
    js fail
    mov $3, %eax
    mov $6, %edi
    syscall
    test %rax, %rax
    js fail
    movl $0, (%rsp)
write_ready:
    mov $1, %eax
    mov $5, %edi
    mov %rsp, %rsi
    mov $4, %edx
    syscall
    cmp $-4, %rax
    je write_ready
    test %rax, %rax
    js fail
    cmp $4, %rax
    jne incomplete_ready
read_gate:
    xor %eax, %eax
    mov $4, %edi
    mov %rsp, %rsi
    mov $1, %edx
    syscall
    cmp $-4, %rax
    je read_gate
    test %rax, %rax
    js fail
    cmp $1, %rax
    jne cancelled
    cmpb $1, (%rsp)
    jne invalid_gate
    mov $3, %eax
    mov $4, %edi
    syscall
    test %rax, %rax
    js fail
    mov $322, %eax
    mov $3, %edi
    lea empty(%rip), %rsi
    mov %r12, %rdx
    mov %r13, %r10
    mov $4096, %r8d
    syscall
fail:
    neg %eax
    mov %eax, (%rsp)
write_error:
    mov $1, %eax
    mov $5, %edi
    mov %rsp, %rsi
    mov $4, %edx
    syscall
    cmp $-4, %rax
    je write_error
    mov $60, %eax
    mov $127, %edi
    syscall
    ud2
cancelled:
    mov $-125, %eax
    jmp fail
invalid_gate:
    mov $-71, %eax
    jmp fail
incomplete_ready:
    mov $-5, %eax
    jmp fail
empty:
    .byte 0
