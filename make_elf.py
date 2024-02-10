#!/usr/bin/env python3

import os
from pathlib import Path
from makeelf.elf import ELF
from makeelf.elfstruct import (
    ELFCLASS,
    ELFDATA,
    ET as ELF_TYPE,
    EM as ELF_MACHINE,
    SHF as SHDR_FLAGS,
    SHT as SHDR_TYPE,
)
from makeelf.elfsect import STB as SYMTAB_BINDING

SCRIPT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
SOURCES_DIR = SCRIPT_DIR / 'sources'
ORIGINAL_BINARY = SOURCES_DIR / 'bootrom.bin'
BUILD_DIR = Path('out')
# I believe that the text section spans from the beginning of ORIGINAL_BINARY
# to address TEXT_SECTION_LENGTH (exclusive) and that the remainder of the file
# is data of some sort.
TEXT_SECTION_LENGTH = 0x31dc


def main():
    os.makedirs(BUILD_DIR, exist_ok=True)
    create_assemblable_source()


def create_assemblable_source():
    with open(ORIGINAL_BINARY, 'rb') as ob:
        contents = ob.read()
    text_section_contents = contents[:TEXT_SECTION_LENGTH]
    data_section_contents = contents[TEXT_SECTION_LENGTH:]

    assert len(text_section_contents) + \
        len(data_section_contents) == len(contents)

    elf = create_elf_from_original_binary(
        text_section_contents, data_section_contents)

    # Write `.elf` file version of original binary
    with open(BUILD_DIR / (ORIGINAL_BINARY.stem + '.elf'), 'wb') as f:
        f.write(bytes(elf))


def create_elf_from_original_binary(text_section_contents,
                                    data_section_contents):
    elf = ELF(
        e_class=ELFCLASS.ELFCLASS32,
        e_data=ELFDATA.ELFDATA2LSB,
        e_type=ELF_TYPE.ET_REL,
        e_machine=ELF_MACHINE.EM_RISCV,
    )

    text_sec_id = elf.append_section(".text", text_section_contents, 0)
    text_shdr = elf.Elf.Shdr_table[text_sec_id]
    text_shdr.sh_flags = int(SHDR_FLAGS.SHF_ALLOC | SHDR_FLAGS.SHF_EXECINSTR)
    text_shdr.sh_type = SHDR_TYPE.SHT_PROGBITS
    elf.append_symbol(
        sym_name="_binary_bootrom_bin_start",
        sym_section=text_sec_id,
        sym_offset=0,
        sym_size=0,
        sym_binding=SYMTAB_BINDING.STB_GLOBAL,
    )

    data_sec_id = elf.append_section(
        ".data", data_section_contents, 0x2000_0000)
    data_shdr = elf.Elf.Shdr_table[data_sec_id]
    data_shdr.sh_flags = int(SHDR_FLAGS.SHF_ALLOC | SHDR_FLAGS.SHF_WRITE)
    data_shdr.sh_type = SHDR_TYPE.SHT_PROGBITS

    return elf


if __name__ == '__main__':
    main()
