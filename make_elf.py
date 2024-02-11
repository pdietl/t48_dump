#!/usr/bin/env python3

import os
import subprocess
import itertools
import re
import sys
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
TEXT_START_SYMBOL_PREFIX = '_binary_bootrom_bin_start'


def main():
    with open(ORIGINAL_BINARY, 'rb') as ob:
        contents = ob.read()
    text_section_contents = contents[:TEXT_SECTION_LENGTH]
    data_section_contents = contents[TEXT_SECTION_LENGTH:]

    assert len(text_section_contents) + \
        len(data_section_contents) == len(contents)

    elf = create_elf_from_original_binary(
        text_section_contents, data_section_contents)

    # Write `.elf` file version of original binary
    os.makedirs(BUILD_DIR, exist_ok=True)
    binary_as_elf_file = BUILD_DIR / (ORIGINAL_BINARY.stem + '.elf')
    with open(binary_as_elf_file, 'wb') as f:
        f.write(bytes(elf))

    create_assemblable_source(binary_as_elf_file)


def create_assemblable_source(original_binary_as_elf_file: Path):
    ASM_LINE_ADDR_PAT = re.compile(r'^\s*([0-9a-f]+):')

    def get_asm_line_addr(asm_line: str) -> int:
        if m := ASM_LINE_ADDR_PAT.search(asm_line):
            return int(m.group(1), base=16)
        else:
            return 0

    ret = subprocess.run(['riscv-none-elf-objdump', '--section', '.text',
                          '--disassemble', original_binary_as_elf_file],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         timeout=5, check=True, text=True)
    asm = ret.stdout.splitlines()
    # Remove the .init and .vector sections
    asm = list(itertools.dropwhile(
        lambda line: get_asm_line_addr(line) < 0x200, asm))
    asm = massage_asm(asm)
    for line in asm:
        print(line)


def massage_asm(asm_lines: list[str]) -> list[str]:
    pat = re.compile(r'^.*[0-9a-f]+ <' +
                     TEXT_START_SYMBOL_PREFIX + r'\+0x([0-9a-f]+)>$')
    matches = {}
    for line_num, line in enumerate(asm_lines):
        if m := pat.search(line):
            matches.setdefault(m.group(1), []).append(line_num)

    # for k, v in matches.items():
    #    if len(v) > 1:
    #        print(f'Multiple statements targeting {k}:')
    #        for s in v:
    #            print(f'  {s.group(0)}')

    pat = re.compile(r'^(\s*)([0-9a-f]+):(.*)$')
    lui_pat = re.compile(r'^.*[0-9a-f]+:\t([0-9a-f]+)\s*lui\t')
    remove_raw_instr_pat = re.compile(
        r'^(\s*)([0-9a-f]+):\s*(?:[0-9a-f]+)\s*(.*)$')
    new_lines = []

    for line in asm_lines:
        is_compressed = True
        if m := lui_pat.search(line):
            # print(f'Found lui line:\n  "{line}"')
            is_compressed = (int(m.group(1), 16) & 3) != 3
            if not is_compressed:
                new_lines.append('.option norvc;')
            # print(f'Is compressed? {"yes" if is_compressed else "no"}')

            m = remove_raw_instr_pat.search(line)
            if m is None:
                print('Error!')
                sys.exit(1)

            # print(line)

        line = remove_raw_instr_pat.sub('\\1\\2:\t\\3', line)

        if (m := pat.search(line)) is not None and m.group(2) in matches:
            # print(f'Match on line {n:05}\n  "{line[:-1]}"\n')
            new_label = f'{TEXT_START_SYMBOL_PREFIX}__plus_{m.group(2)}'
            s = pat.sub(f'{new_label}:' + r'\3', line)
            # print(f'  "{s}"')
            new_lines.append(s)
        else:
            new_lines.append(line)

        if not is_compressed:
            new_lines.append('.option rvc;')

    pat2 = re.compile(
        r'^(.*?)([0-9a-f]+ <' + TEXT_START_SYMBOL_PREFIX +
        r'\+0x([0-9a-f]+)>)$')
    for k, v in matches.items():
        new_label = f'{TEXT_START_SYMBOL_PREFIX}__plus_{k}'
        for line_num in v:
            new_lines[line_num] = pat2.sub(
                r'\1' + new_label, new_lines[line_num])

    return new_lines


def create_elf_from_original_binary(text_section_contents: bytes,
                                    data_section_contents: bytes) -> ELF:
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
        sym_name=TEXT_START_SYMBOL_PREFIX,
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
