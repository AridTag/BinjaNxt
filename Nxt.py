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

from binaryninja import *
import ctypes
import traceback

from BinjaNxt.NxtUtils import *
from BinjaNxt.PacketHandler import *

#from NxtUtils import *
#from PacketHandler import *

current_time_ms_addr: Optional[int] = None
checked_alloc_addr: Optional[int] = None
connection_manager_ctor_addr: Optional[int] = None


def run(bv: BinaryView) -> bool:
    define_types(bv)
    if not refactor_app_init(bv):
        print('Failed to refactor jag::App::MainInit')
        return False

    if not refactor_connection_manager(bv):
        print('Failed to refactor jag::ConnectionManager')
        return False

    if not refactor_packets(bv, connection_manager_ctor_addr):
        print('Failed to refactor packets')
        return False

    return True


def define_types(bv: BinaryView):
    t_isaac = Type.structure(members=[
        (Type.int(4, False), 'valuesRemaining'),
        (Type.array(Type.int(4, False), 256), 'rand_results'),
        (Type.array(Type.int(4, False), 256), 'mm'),
        (Type.int(4), 'aa'),
        (Type.int(4), 'bb'),
        (Type.int(4), 'cc')
    ], packed=True)
    bv.define_user_type('jag::Isaac', t_isaac)

    t_heap_interface = Type.structure(packed=True)
    bv.define_user_type('jag::HeapInterface', t_heap_interface)

    t_clientprot = Type.structure(members=[
        (Type.int(4, False), 'opcode'),
        (Type.int(4), 'size')
    ], packed=True)
    bv.define_user_type('jag::ClientProt', t_clientprot)

    t_packet = Type.structure(members=[
        (Type.int(8), 'unk1'),
        (Type.int(8), 'capacity'),
        (Type.pointer(bv.arch, Type.int(1, False)), 'buffer'),
        (Type.int(8), 'offset'),
        (Type.int(4), 'unk2'),
        (Type.int(8), 'unk3')
    ], packed=True)
    bv.define_user_type('jag::Packet', t_packet)


def refactor_app_init(bv: BinaryView) -> bool:
    main_init = find_main_init(bv)
    if main_init is None:
        return False

    rename_func(main_init, 'jag::App::MainInit')

    ref_threshold = 1500
    found_alloc = False
    client_struct_size = 0
    client_struct_alignment = 0
    for llil in main_init.llil.instructions:
        (is_valid, dest_addr) = is_valid_function_call(llil)
        if not is_valid or dest_addr is None:
            continue

        if not found_alloc:
            refs = list(bv.get_code_refs(dest_addr))
            if len(refs) < ref_threshold:
                continue

            client_struct_size = llil.get_reg_value(RegisterName('rcx')).value  # num_bytes
            client_struct_alignment = llil.get_reg_value(RegisterName('rdx')).value  # alignment
            client_threshold = 0x633e0
            if client_struct_size < client_threshold:
                print('Client structure size is smaller than expected got ' + hex(
                    client_struct_size) + ' expected at least ' + hex(client_threshold))
                break

            found_alloc = True
            checked_alloc = bv.get_function_at(dest_addr)
            rename_func(checked_alloc, 'jag::HeapInterface::CheckedAlloc')
            change_ret_type(checked_alloc, Type.pointer(bv.arch, Type.void()))
            change_var(checked_alloc.parameter_vars[0], 'num_bytes', Type.int(4))
            change_var(checked_alloc.parameter_vars[1], 'alignment', Type.int(4))

            global checked_alloc_addr
            checked_alloc_addr = checked_alloc.start
        else:
            with StructureBuilder.builder(bv, QualifiedName('jag::Client')) as client_builder:
                client_builder.packed = True
                client_builder.alignment = client_struct_alignment
                client_builder.width = client_struct_size

            client_ctor = bv.get_function_at(dest_addr)
            rename_func(client_ctor, 'jag::Client::ctor')
            change_var(client_ctor.parameter_vars[0], 'pClient', Type.pointer(bv.arch, bv.get_type_by_name('jag::Client')))
            break

    return True


def find_main_init(bv: BinaryView) -> Optional[Function]:
    """
    Looks for references to the SetErrorMode function in Kernel32.dll.
    There should only be one function that calls SetErrorMode and that is the main init.
    Returns the Function that calls SetErrorMode or None if there are no matches or too many matches
    """
    setErrorModes = bv.get_symbols_by_name('SetErrorMode')
    if len(setErrorModes) == 0:
        return None

    setErrorModeAddr = setErrorModes[-1].address
    references = list(bv.get_code_refs(setErrorModeAddr))
    if len(references) > 1:
        print('SetErrorMode is referenced multiple times!')
        for ref in references:
            print('    at ' + hex(ref.address))
        return None

    target_func = references[0].function
    print('found jag::App::MainInit at ' + hex(target_func.start))
    return target_func


def refactor_connection_manager(bv: BinaryView) -> bool:
    """
    Finds jag::ConnectionManager ctor by looking for instances of reg = reg + 20000.
    There are only a few functions that use this value
    """
    global current_time_ms_addr
    global connection_manager_ctor_addr

    print('Searching for jag::ConnectionManager::ctor this will take awhile...')
    candidates: Dict[LowLevelILInstruction, Function] = {}
    for func in bv.functions:
        candidate_ins: Optional[LowLevelILInstruction] = None
        is_candidate = False
        is_super_candidate = False
        for insn in func.llil.instructions:
            if not is_candidate:
                if insn.operation != LowLevelILOperation.LLIL_SET_REG:
                    continue

                set_reg: LowLevelILSetReg = insn
                value_expr = set_reg.operands[1]
                if value_expr.operation != LowLevelILOperation.LLIL_ADD:
                    continue

                for op in value_expr.operands:
                    if isinstance(op, LowLevelILConst):
                        const: LowLevelILConst = op
                        if const.constant == 20000:
                            candidate_ins = insn
                            is_candidate = True
                            # print(str(candidate_ins) + " @ " + hex(candidate_ins.address))
                            break
            else:
                distance = insn.address - candidate_ins.address
                if distance > 25:
                    # print('    discard at ' + str(distance))
                    break

                if insn.operation != LowLevelILOperation.LLIL_RET:
                    continue

                # print('    ' + str(distance))
                is_super_candidate = True
                break

        if is_super_candidate:
            candidates[candidate_ins] = func
            break

    if len(candidates) != 1:
        print('Failed to isolate jag::ConnectionManager::ctor.')
        print('    Remaining candidates: ' + str(candidates))
        return False

    insn_using_current_time: Optional[LowLevelILInstruction]
    ctor: Optional[Function] = None
    insn_using_current_time, ctor = list(candidates.items())[0]
    ctor_instructions = list(ctor.llil.instructions)

    current_time_addr = find_current_time_addr(insn_using_current_time, ctor_instructions)
    if current_time_addr is None:
        print('Failed to find address of s_CurrentTimeMs')
        return False

    current_time_ms_addr = current_time_addr
    bv.define_user_data_var(current_time_ms_addr, Type.int(8, False), 's_CurrentTimeMs')

    print('Determining size of jag::ConnectionManager')
    ctor_refs = list(bv.get_code_refs(ctor.start))
    if len(ctor_refs) != 1:
        print('Expected 1 xref to jag::ConnectionManager::ctor but got ' + str(len(ctor_refs)))
        return False

    allocation = find_allocation_from_ctor_call(list(ctor_refs[0].function.llil_instructions),
                                                ctor_refs[0].function.get_llil_at(ctor_refs[0].address),
                                                checked_alloc_addr)
    if allocation is None:
        print('Failed to determine size of jag::ConnectionManager')
        return False

    with StructureBuilder.builder(bv, QualifiedName('jag::ConnectionManager')) as builder:
        builder.packed = True
        builder.width = allocation.size
        builder.alignment = allocation.alignment

    connection_manager_ctor_addr = ctor.start
    print('Found jag::ConnectionManager::ctor at ' + hex(connection_manager_ctor_addr))

    rename_func(ctor, 'jag::ConnectionManager::ctor')
    change_var_type(ctor.parameter_vars[0], Type.pointer(bv.arch, bv.get_type_by_name('jag::ConnectionManager')))
    change_var_type(ctor.parameter_vars[1], Type.pointer(bv.arch, bv.get_type_by_name('jag::Client')))
    return True


def find_current_time_addr(insn_using_current_time: LowLevelILInstruction,
                           ctor_instructions: list[LowLevelILInstruction]) -> Optional[int]:
    """
    In order to get the data address for s_CurrentTimeMs we need to figure out the register that the current time
    value is stored in then we need to move backwards from insn_using_current_time to find the assignment to that
    register
    @param insn_using_current_time:
    @param ctor_instructions:
    @return: The address of s_CurrentTimeMs or None
    """
    reg_name: Optional[RegisterName] = None
    value_expr = insn_using_current_time.operands[1]
    for op in value_expr.operands:
        if isinstance(op, LowLevelILReg):
            reg: LowLevelILReg = op
            reg_name = reg.src.name

    if reg_name is None:
        print('s_CurrentTimeMs doesn\'t appear to be coming from a register. Script needs updating!')
        return None

    idx = find_instruction_index(ctor_instructions, insn_using_current_time)
    while idx > 0:
        idx -= 1  # decrementing at the start because we are starting at insn_using_current_time
        insn = ctor_instructions[idx]
        if insn.operation != LowLevelILOperation.LLIL_SET_REG:
            continue

        set_reg: LowLevelILSetReg = insn
        if set_reg.dest.name != reg_name:
            continue

        src = set_reg.src
        if isinstance(src, LowLevelILLoad):
            load: LowLevelILLoad = src
            if isinstance(load.operands[0], LowLevelILConstPtr):
                ptr: LowLevelILConstPtr = load.operands[0]
                return ptr.constant

        print('s_CurrentTimeMs doesn\'t appear to be coming from a static address. Script needs updating!')
        break

    return None
