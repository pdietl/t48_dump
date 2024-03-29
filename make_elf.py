#!/usr/bin/env python3

import os
import subprocess
import itertools
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing_extensions import Self
from more_itertools import chunked

from result import Ok, Err, Result
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
ORIGINAL_BINARY = SOURCES_DIR / 'original_bootrom.bin'
BUILD_DIR = Path('out')
DATA_SECTION_BIN = BUILD_DIR / 'data_section.bin'
# I believe that the text section spans from the beginning of ORIGINAL_BINARY
# to address TEXT_SECTION_LENGTH (exclusive) and that the remainder of the file
# is data of some sort.
TEXT_SECTION_LENGTH = 0x31dc
TEXT_START_SYMBOL_PREFIX = '_binary_bootrom_bin_start'
DEFAULT_INTERRUPT_HANDLER_OFFSET_START_HEX = '293e'
DEFAULT_INTERRUPT_HANDLER_OFFSET_END_HEX = '29fc'
JAL_OP_CODE = 0x6f


# All lines of assembly should have the general form of:
# <ws><hex instr addr>:<ws><hex instr><ws><instr text><tab><instr ops><jmp annotation>?
#
# where
#   ws: whitespace
#   hex instr addr: hexadecimal address of the instruction
#   hex instr: hexadecimal of the instruction machine code (16 or 32 bits)
#   jmp annotations: A description of a jmp address
#
#   Examples:
#
#   |     200:       433d                    li      t1,15|
#   |     204:       02c37363                bgeu    t1,a2,22a <_binary_bootrom_bin_start+0x22a>|
#   |     228:       8082                    ret|
#   |     618:       33058593                add     a1,a1,816 # 330 <_binary_bootrom_bin_start+0x330>|
class AsmInstrLine:
    ASM_INSTR_LINE_PAT = re.compile(r"""
        \s+
        (?P<addr>
            [0-9a-fA-F]{,8}
        )
        :
        \s+
        (?P<encoded_instr>
            [0-9a-fA-F]{4}
            |
            [0-9a-fA-F]{8}
        )
        \s+
        (?P<instr_text>
            (?P<instr_mnemonic> \S+ )
            (?:                             # Maybe operands.
                \s+
                (?P<instr_operands> \S+ )   # If we have operands, the will be together with commands and no spaces
                (?:                         # Maybe jump label and offset
                    \s+
                    <
                    (?P<jmp_label>
                        [^-+]+
                    )
                    (?P<jmp_offset>
                        [+\-]
                         0x
                         [0-9a-fA-F]+
                    )
                    >
                )?
            )?
        )
        (?:                                 # Maybe a trailing comment
            \s*
            \#
            .*
        )?
        $
    """, re.VERBOSE)

    def __init__(self, address: int, encoded_instruction: int, instruction_text: str, instruction_mnemonic: str,
                 instruction_operands: list[str] | None, jump_target_label: str | None,
                 jump_target_offset: int | None) -> None:
        self.address = address
        self.encoded_instruction = encoded_instruction
        self.instruction_text = instruction_text
        self.instruction_mnemonic = instruction_mnemonic
        self.instruction_operands = instruction_operands
        self.jump_target_label = jump_target_label
        self.jump_target_offset = jump_target_offset

    @classmethod
    def from_str(cls, instr_line: str) -> Result[Self, None]:
        m = cls.ASM_INSTR_LINE_PAT.search(instr_line)
        if m:
            return Ok(cls(
                address=int(m.group('addr'), 16),
                encoded_instruction=int(m.group('encoded_instr'), 16),
                instruction_text=m.group('instr_text'),
                instruction_mnemonic=m.group('instr_mnemonic'),
                instruction_operands=ops.split(',') if (ops := m.group('instr_operands')) else None,
                jump_target_label=m.group('jmp_label'),
                jump_target_offset=int(m.group('jmp_offset'), 16) if m.group('jmp_offset') else None
            ))
        else:
            return Err(None)

    def is_compressed(self) -> bool:
        # The least significant 3 bits of all RISC-V instructions reveals whether it is
        # a compressed encoding.
        #
        # compressed: 0b00, 0b01, 0b10
        # not compressed: 0b11
        return (self.encoded_instruction & 0b11) != 0b11

    def __str__(self) -> str:
        return f'{self.address:8x}:{" " * 7}{self.encoded_instruction:<8x}{" " * 16}{self.instruction_text}'


def main():
    with open(ORIGINAL_BINARY, 'rb') as ob:
        contents = ob.read()

    # The lengths were determined empirically
    text_section_contents = contents[:TEXT_SECTION_LENGTH]
    data_section_contents = contents[TEXT_SECTION_LENGTH:]

    # Sanity check
    assert len(text_section_contents) + \
           len(data_section_contents) == len(contents)

    os.makedirs(BUILD_DIR, exist_ok=True)

    with open(DATA_SECTION_BIN, 'wb') as f:
        f.write(data_section_contents)

    init_and_vector_code: bytes = text_section_contents[:0x200]

    elf = create_elf_from_original_binary(
        text_section_contents, data_section_contents)

    # Write `.elf` file version of original binary
    binary_as_elf_file = BUILD_DIR / (ORIGINAL_BINARY.stem + '.elf')
    with open(binary_as_elf_file, 'wb') as f:
        f.write(bytes(elf))

    create_assemblable_source(binary_as_elf_file, init_and_vector_code)


@dataclass
class GlobalLabelAndAddr:
    label: str
    addr: int


def get_bits(n: int, start: int, end: int) -> int:
    return (n & (((1 << (end - start + 1)) - 1) << start)) >> start


def create_startup_asm_file(init_and_vector_code: bytes):
    assert len(init_and_vector_code) == 0x200

    global_labels_to_add: map[int, list[str]] = {}
    asm_lines: list[str] = []
    words: list[int] = []

    asm_lines.append('  .section .init, "ax", @progbits')
    asm_lines.append('  .global _start')
    asm_lines.append('  .align 1')
    asm_lines.append('')
    asm_lines.append('_start:')

    for word_bytes in chunked(init_and_vector_code, 4):
        words.append(int.from_bytes(word_bytes, 'little'))

    first_jmp = words[0]
    op = get_bits(first_jmp, start=0, end=6)
    assert op == JAL_OP_CODE
    offset = ((get_bits(first_jmp, start=31, end=31) << 20) |
              (get_bits(first_jmp, start=12, end=19) << 12) |
              (get_bits(first_jmp, start=20, end=20) << 11) |
              (get_bits(first_jmp, start=21, end=30) << 1))

    asm_lines.append('  j handle_reset')
    global_labels_to_add[offset] = ['handle_reset']

    for i in range(1, 13):
        assert words[i] == 0x13
        asm_lines.append('  .word 0x00000013')

    # ebreak instr
    assert words[13] == 0x100073
    asm_lines.append('  .word 0x00100073')

    asm_lines.append('  .section .vector, "ax", @progbits')
    asm_lines.append('  .align 1')
    asm_lines.append('_vector_base:')
    asm_lines.append('  .option norvc;')

    def add(label: str, word: int):
        asm_lines.append(f'  .word   {label}')
        global_labels_to_add.setdefault(word, []).append(label)

    asm_lines.append(f'  .word   _start')  # defined in this file
    assert words[15] == 0
    asm_lines.append('  .word   0')
    add('NMI_Handler', words[16])
    add('HardFault_Handler', words[17])
    assert words[18] == 0
    asm_lines.append('  .word   0')
    add('Ecall_M_Mode_Handler', words[19])
    assert words[20] == 0
    asm_lines.append('  .word   0')
    assert words[21] == 0
    asm_lines.append('  .word   0')
    add('Ecall_U_Mode_Handler', words[22])
    add('Break_Point_Handler', words[23])
    assert words[24] == 0
    asm_lines.append('  .word   0')
    assert words[25] == 0
    asm_lines.append('  .word   0')
    add('SysTick_Handler', words[26])
    assert words[27] == 0
    asm_lines.append('  .word   0')
    add('SW_Handler', words[28])
    assert words[29] == 0
    asm_lines.append('  .word   0')

    asm_lines.append('# External interrupts')

    ext_interrupts = ['WWDG_IRQHandler', 'PVD_IRQHandler', 'TAMPER_IRQHandler', 'RTC_IRQHandler', 'FLASH_IRQHandler',
                      'RCC_IRQHandler', 'EXTI0_IRQHandler', 'EXTI1_IRQHandler', 'EXTI2_IRQHandler', 'EXTI3_IRQHandler',
                      'EXTI4_IRQHandler', 'DMA1_Channel1_IRQHandler', 'DMA1_Channel2_IRQHandler',
                      'DMA1_Channel3_IRQHandler', 'DMA1_Channel4_IRQHandler', 'DMA1_Channel5_IRQHandler',
                      'DMA1_Channel6_IRQHandler', 'DMA1_Channel7_IRQHandler', 'ADC1_2_IRQHandler',
                      'USB_HP_CAN1_TX_IRQHandler', 'USB_LP_CAN1_RX0_IRQHandler', 'CAN1_RX1_IRQHandler',
                      'CAN1_SCE_IRQHandler', 'EXTI9_5_IRQHandler', 'TIM1_BRK_IRQHandler', 'TIM1_UP_IRQHandler',
                      'TIM1_TRG_COM_IRQHandler', 'TIM1_CC_IRQHandler', 'TIM2_IRQHandler', 'TIM3_IRQHandler',
                      'TIM4_IRQHandler', 'I2C1_EV_IRQHandler', 'I2C1_ER_IRQHandler', 'I2C2_EV_IRQHandler',
                      'I2C2_ER_IRQHandler', 'SPI1_IRQHandler', 'SPI2_IRQHandler', 'USART1_IRQHandler',
                      'USART2_IRQHandler', 'USART3_IRQHandler', 'EXTI15_10_IRQHandler', 'RTCAlarm_IRQHandler',
                      'USBWakeUp_IRQHandler', 'TIM8_BRK_IRQHandler', 'TIM8_UP_IRQHandler', 'TIM8_TRG_COM_IRQHandler',
                      'TIM8_CC_IRQHandler', 'RNG_IRQHandler', 'FSMC_IRQHandler', 'SDIO_IRQHandler', 'TIM5_IRQHandler',
                      'SPI3_IRQHandler', 'UART4_IRQHandler', 'UART5_IRQHandler', 'TIM6_IRQHandler', 'TIM7_IRQHandler',
                      'DMA2_Channel1_IRQHandler', 'DMA2_Channel2_IRQHandler', 'DMA2_Channel3_IRQHandler',
                      'DMA2_Channel4_IRQHandler', 'DMA2_Channel5_IRQHandler', 'ETH_IRQHandler', 'ETH_WKUP_IRQHandler',
                      'CAN2_TX_IRQHandler', 'CAN2_RX0_IRQHandler', 'CAN2_RX1_IRQHandler', 'CAN2_SCE_IRQHandler',
                      'OTG_FS_IRQHandler', 'USBHSWakeup_IRQHandler', 'USBHS_IRQHandler', 'DVP_IRQHandler',
                      'UART6_IRQHandler', 'UART7_IRQHandler', 'UART8_IRQHandler', 'TIM9_BRK_IRQHandler',
                      'TIM9_UP_IRQHandler', 'TIM9_TRG_COM_IRQHandler', 'TIM9_CC_IRQHandler', 'TIM10_BRK_IRQHandler',
                      'TIM10_UP_IRQHandler', 'TIM10_TRG_COM_IRQHandler', 'TIM10_CC_IRQHandler',
                      'DMA2_Channel6_IRQHandler', 'DMA2_Channel7_IRQHandler', 'DMA2_Channel8_IRQHandler',
                      'DMA2_Channel9_IRQHandler', 'DMA2_Channel10_IRQHandler', 'DMA2_Channel11_IRQHandler', ]

    for i in range(30, 30 + len(ext_interrupts)):
        add(ext_interrupts[i - 30], words[i])

    with open(BUILD_DIR / 'startup.s', 'w') as f:
        for line in asm_lines:
            f.write(line + '\n')

    return global_labels_to_add


def create_assemblable_source(original_binary_as_elf_file: Path, init_and_vector_code: bytes) -> None:
    asm_line_addr_pat = re.compile(r'^\s*([0-9a-f]+):')

    # See comment below about the expected format of assembly lines
    def get_asm_line_addr(asm_line: str) -> int:
        if m := asm_line_addr_pat.search(asm_line):
            return int(m.group(1), base=16)
        else:
            return 0

    # Create disassembly of the .text section of the original binary
    ret = subprocess.run(['riscv-none-elf-objdump', '--section', '.text',
                          '--disassemble', original_binary_as_elf_file],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         timeout=2.0,  # Seconds
                         check=True,
                         text=True)
    asm = ret.stdout.splitlines()
    # Remove:
    #   * Any leading information produced by objdump
    #   * init section
    #   * vector section
    #
    # All of this occurs on lines before the instruction address of 0x200
    # We will provide them in a separate assembly file
    asm = list(itertools.dropwhile(
        lambda asm_line: get_asm_line_addr(asm_line) < 0x200, asm))

    global_labels_to_add = create_startup_asm_file(init_and_vector_code)

    asm_lines_parsed: list[AsmInstrLine] = []
    target_branch_label = None

    for line in asm:
        match AsmInstrLine.from_str(line):
            case Ok(value):
                # We assume all branch labels have the same name
                if value.jump_target_label:
                    if target_branch_label:
                        assert value.jump_target_label == target_branch_label
                    else:
                        target_branch_label = value.jump_target_label
                asm_lines_parsed.append(value)
            case Err(e):
                print(f'Error making assembly line |{line}| into AsmInstrLine class instance!')
                sys.exit(1)

    output_asm_lines = massage_asm(asm_lines_parsed, target_branch_label, global_labels_to_add)
    with open(BUILD_DIR / 'main.s', 'w') as out:
        for line in output_asm_lines:
            out.write(line + '\n')


def massage_asm(asm_lines: list[AsmInstrLine], branch_label: str, global_labels_to_add: dict[int, list[str]]) -> list[
    str]:
    def lui_instr_can_be_compressed(instr: int) -> bool:
        imm = get_bits(instr, start=12, end=31)
        rd = get_bits(instr, start=7, end=11)
        if imm == 0 or rd == 0 or rd == 2:
            return False
        if (imm & ~((2 ** 7) - 1)) != 0:
            return False
        return True

    def mv_or_add_instr_can_be_compressed(instr: int) -> bool:
        rd = get_bits(instr, start=7, end=11)
        rs2 = get_bits(instr, start=2, end=6)
        return rd != 0 and rs2 != 0

    def sub_instr_can_be_compressed(instr: int) -> bool:
        return True

    def jal_instr_can_be_compressed(instr: int) -> bool:
        return True

    # Empirically discovered that these instruction are _sometimes_ not encoded as compressed
    # instructions even when they could be, and other times they are encoded in their compressed form.
    # I can only assume that the original assembler used had some holes in its logic for determining
    # whether to compress these instructions in some cases.
    #
    # So, each time we encounter these mnemonics, we check if the original uses its compressed encoding.
    # If the instruction _does not_ use its compressed encoding _and_ it meets its instruction-specific
    # criteria for compressed encoding eligibility, then we need to manually wrap the instruction
    # with the assembler directives `.option norvc;` and `.option rvc;` to make `as` not emit the
    # compressed encoding of the instruction. What a pain.
    instr_sometimes_not_compressed = {
        'mv': mv_or_add_instr_can_be_compressed,
        'add': mv_or_add_instr_can_be_compressed,
        'sub': sub_instr_can_be_compressed,
        'lui': lui_instr_can_be_compressed,
        'jal': jal_instr_can_be_compressed,
    }

    # The goal here is to find lines of the form:
    #
    #   |     204:       02c37363                bgeu    t1,a2,22a <_binary_bootrom_bin_start+0x22a>|
    #
    # and:
    #   1. Insert a label at address 0x22a
    #   2. Gather all branch instructions targeting 0x22a and substitute the '2aa' in their
    #      assembly line with a reference to the label created in 1.

    # Matches is a map
    #   from: an assembly instruction address that needs a new_label
    #   to:   a list of assembly instruction line numbers that target the `from` address
    branch_targets_map = {}
    for line in asm_lines:
        if line.jump_target_label:
            branch_targets_map.setdefault(line.jump_target_offset, []).append(line)

    output_asm_lines: list[str] = ['.text', '']

    for line in asm_lines:
        norvc_emitted = False

        if line.address in global_labels_to_add:
            for label in global_labels_to_add[line.address]:
                output_asm_lines.append(f'.global {label}')
                output_asm_lines.append(f'.type {label}, @function')
                output_asm_lines.append(f'{label}:')

        if line.address in branch_targets_map:
            output_asm_lines.append(f'{branch_label}_{line.address:x}:')

        if not line.is_compressed() and line.instruction_mnemonic in instr_sometimes_not_compressed:
            if instr_sometimes_not_compressed[line.instruction_mnemonic](line.encoded_instruction):
                output_asm_lines.append('.option norvc;')
                norvc_emitted = True

        new_line = ' ' * 4
        new_line += f'{line.instruction_mnemonic}'
        if line.instruction_operands:
            new_line += ' '
            if line.jump_target_label:
                if line.instruction_mnemonic == 'j' and line.jump_target_offset == line.address:
                    new_line += '.'
                else:
                    new_line += ','.join(line.instruction_operands[:-1])
                    if len(line.instruction_operands) > 1:
                        new_line += ','
                    new_line += f'{branch_label}_{line.jump_target_offset:x}'
            else:
                new_line += ','.join(line.instruction_operands)

        output_asm_lines.append(new_line)

        if norvc_emitted:
            output_asm_lines.append('.option rvc;')

    output_asm_lines.append('')
    output_asm_lines.append('.data')
    output_asm_lines.append(f'.incbin "{DATA_SECTION_BIN}"')

    return output_asm_lines


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
