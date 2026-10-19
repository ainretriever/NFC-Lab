/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 NFClab contributors.
 */
ENTRY(Reset_Handler)
MEMORY { FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 512K
         RAM (rwx) : ORIGIN = 0x20000000, LENGTH = 128K }
_estack = ORIGIN(RAM) + LENGTH(RAM);
SECTIONS {
 .isr_vector : { KEEP(*(.isr_vector)) . = ALIGN(4); } > FLASH
 /* The trailing ALIGN(4) keeps LOADADDR(.data) word aligned: the startup code
    copies .data with LDRD, which takes an UNALIGNED UsageFault otherwise. */
 .text : { *(.text*) *(.rodata*) . = ALIGN(4); } > FLASH
 .data : { . = ALIGN(4); _sdata = .; *(.data*) . = ALIGN(4); _edata = .; } > RAM AT> FLASH
 _sidata = LOADADDR(.data);
 .bss (NOLOAD) : { . = ALIGN(4); _sbss = .; *(.bss*) *(COMMON) . = ALIGN(4); _ebss = .; } > RAM
 /DISCARD/ : { *(.comment*) *(.note*) }
}

ASSERT((_sidata % 4) == 0, "data load address must be word aligned")
ASSERT((_estack - _ebss) >= 8192, "reserve at least 8 KiB for stack")
