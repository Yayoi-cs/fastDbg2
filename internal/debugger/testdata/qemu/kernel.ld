ENTRY(_start)
PHDRS { image PT_LOAD FLAGS(7); }
SECTIONS {
 . = 0xffff800000200000;
 .text : AT(0x200000) { *(.text) } :image
 .eh_frame : AT(ADDR(.eh_frame)-0xffff800000000000) { *(.eh_frame) } :image
 .data : AT(ADDR(.data)-0xffff800000000000) { *(.data) } :image
 .note.gnu.build-id : AT(ADDR(.note.gnu.build-id)-0xffff800000000000) { *(.note.gnu.build-id) } :image
}
