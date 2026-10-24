.section .multiboot,"a"
.align 4
.long 0x1badb002,0,-0x1badb002
.text
.code32
.global _start
_start:
 cli
 mov $0x90000,%esp
 lgdt gdt_pointer
 mov $pml4,%eax
 mov %eax,%cr3
 mov %cr4,%eax
 or $0x20,%eax
 mov %eax,%cr4
 mov $0xc0000080,%ecx
 rdmsr
 or $0x900,%eax
 wrmsr
 mov %cr0,%eax
 or $0x80000000,%eax
 mov %eax,%cr0
 ljmp $8,$long_entry
.code64
long_entry:
 mov $16,%ax
 mov %ax,%ds
 mov %ax,%es
 mov %ax,%ss
 movabs $0xffff800000200000,%rax
 jmp *%rax
.align 8
gdt:
 .quad 0,0x00af9a000000ffff,0x00cf92000000ffff
gdt_pointer:
 .word 23
 .long gdt
.section .data
.align 4096
pml4:
 .long pdpt+3,0
 .zero 255*8
 .long pdpt+3,0
 .zero 255*8
pdpt:
 .long pd+3,0
 .quad 0x40000083
 .zero 510*8
pd:
 .long pt+3,0
 .quad 0x200083,0x400083,0x600083
 .zero 508*8
pt:
.set n,0
.rept 512
 .quad n*4096+3
 .set n,n+1
.endr
