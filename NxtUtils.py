"""
Copyright 2022 AridTag
This file is part of BinjaNxt.
BinjaNxt is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

BinjaNxt is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with BinjaNxt.
If not, see <https://www.gnu.org/licenses/>.
"""
from typing import Optional

from binaryninja import Function, Type, Undetermined, Variable, BinaryView, RegisterName
from binaryninja import LowLevelILInstruction, LowLevelILCall

RCX = RegisterName('rcx')
RDX = RegisterName('rdx')
RSI = RegisterName('rsi')
RBP = RegisterName('rbp')
R8 = RegisterName('r8')
R8D = RegisterName('r8d')


class AllocationDetails:
    size: int = 0
    alignment: int = 0

    def __init__(self, size, alignment):
        self.size = size
        self.alignment = alignment


def is_valid_function_call(bv: BinaryView, llil: LowLevelILInstruction) -> (bool, Optional[int]):
    if not isinstance(llil, LowLevelILCall) or len(llil.operands) != 1:
        return False, None

    call_insn: LowLevelILCall = llil
    call_dest = call_insn.dest.value
    if isinstance(call_dest, Undetermined):
        return False, None

    dest_func = bv.get_function_at(call_dest.value)
    if dest_func is None:
        return False, None

    return True, dest_func.start


def change_comment(bv: BinaryView, addr: int, desired_comment: str):
    comment = bv.get_comment_at(addr)
    if comment != desired_comment:
        bv.set_comment_at(addr, desired_comment)


def change_var(var: Variable, name: str, var_type: Type):
    set_name = var.name != name
    set_type = var.type != var_type
    if set_name and set_type:
        var.set_name_and_type_async(name, var_type)
    elif set_type:
        var.set_type_async(var_type)
    elif set_name:
        var.set_name_async(name)


def change_var_type(var: Variable, var_type: Type):
    if var.type != var_type:
        var.set_type_async(var_type)


def rename_func(func: Function, name: str):
    if func.name != name:
        func.name = name


def change_ret_type(func: Function, ret_type: Type):
    if func.return_type != ret_type:
        func.return_type = ret_type


def find_instruction_index(instructions: list[LowLevelILInstruction], insn: LowLevelILInstruction) -> int:
    """
    Finds the index of the given instruction in the list of instructions by its address.
    @param instructions:
    @param insn:
    @return: The index of the instruction or -1 if not found
    """
    return next((i for i, item in enumerate(instructions) if item.address == insn.address), -1)


def find_allocation_from_ctor_call(bv: BinaryView,
                                   calling_function_instructions: list[LowLevelILInstruction],
                                   calling_instruction: LowLevelILInstruction,
                                   alloc_addr: int) -> Optional[AllocationDetails]:
    """
    Determines the size and alignment of the allocation for the object being constructed.
    The value of num_bytes (rcx) must be able to be determined.
    If the value of alignment (rdx) cannot be determined then a default alignment of 16 will be assumed

    @param bv:
    @param calling_function_instructions:
    @param calling_instruction:
    @param alloc_addr: the address of the alloc function. It is assumed the alloc signature is as follows: void* alloc(int32_t num_bytes, int32_t alignment)
    @return: The AllocationDetails passed to the invokation of jag::HeapInterface::CheckedAlloc to allocate the object
    whose constructor is being called by calling_instruction or None
    """
    idx = find_instruction_index(calling_function_instructions, calling_instruction)
    while idx > 0:
        idx -= 1
        insn = calling_function_instructions[idx]

        (is_valid, dest_addr) = is_valid_function_call(bv, insn)
        if not is_valid:
            continue

        # If we hit another function call then we can't guarantee the registeres will have the correct values
        if dest_addr != alloc_addr:
            return None

        size = insn.get_reg_value(RCX)  # num_bytes
        alignment = insn.get_reg_value(RDX)  # alignment
        if isinstance(size, Undetermined):
            print('Unable to determine size of allocation')
            return None

        return AllocationDetails(size.value, alignment.value if not isinstance(alignment, Undetermined) else 16)

    return None
