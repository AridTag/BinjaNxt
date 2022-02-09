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
from binaryninja.log import log_error, log_warn, log_debug, log_info
from BinjaNxt.NxtUtils import *
from BinjaNxt.PacketHandler import PacketHandlers
from BinjaNxt.JagTypes import *
#from JagTypes import *
#from PacketHandler import PacketHandlers
#from NxtUtils import *


class Nxt:
    jag_types: JagTypes = JagTypes()
    packet_handlers: PacketHandlers = None
    current_time_ms_addr: Optional[int] = None
    checked_alloc_addr: Optional[int] = None
    connection_manager_ctor_addr: Optional[int] = None
    client_ctor_addr: Optional[int] = None
    static_client_ptrs: list[int] = []

    def __init__(self):
        self.packet_handlers = PacketHandlers(self.jag_types)

    def run(self, bv: BinaryView) -> bool:
        self.define_types(bv)
        if not self.refactor_app_init(bv):
            log_error('Failed to refactor jag::App::MainInit')
            return False

        if not self.refactor_connection_manager(bv):
            log_error('Failed to refactor jag::ConnectionManager')
            return False

        if not self.packet_handlers.run(bv, self.connection_manager_ctor_addr):
            log_error('Failed to refactor packets')
            return False

        return True

    def define_types(self, bv: BinaryView):
        t_isaac = Type.structure(members=[
            (Type.int(4, False), 'valuesRemaining'),
            (Type.array(Type.int(4, False), 256), 'rand_results'),
            (Type.array(Type.int(4, False), 256), 'mm'),
            (Type.int(4), 'aa'),
            (Type.int(4), 'bb'),
            (Type.int(4), 'cc')
        ], packed=True)
        bv.define_user_type(self.jag_types.isaac_name, t_isaac)
        self.jag_types.isaac = bv.get_type_by_name(self.jag_types.isaac_name)

        t_heap_interface = Type.structure(packed=True)
        bv.define_user_type(self.jag_types.heap_interface_name, t_heap_interface)
        self.jag_types.heap_interface = bv.get_type_by_name(self.jag_types.heap_interface_name)

        t_client_prot = Type.structure(members=[
            (Type.int(4, False), 'opcode'),
            (Type.int(4), 'size')
        ], packed=True)
        bv.define_user_type(self.jag_types.client_prot_name, t_client_prot)
        self.jag_types.client_prot = bv.get_type_by_name(self.jag_types.client_prot_name)

        t_packet = Type.structure(members=[
            (Type.int(8), 'unk1'),
            (Type.int(8), 'capacity'),
            (Type.pointer(bv.arch, Type.int(1, False)), 'buffer'),
            (Type.int(8), 'offset'),
            (Type.int(4), 'unk2'),
            (Type.int(8), 'unk3')
        ], packed=True)
        bv.define_user_type(self.jag_types.packet_name, t_packet)
        self.jag_types.packet = bv.get_type_by_name(self.jag_types.packet_name)

    def refactor_app_init(self, bv: BinaryView) -> bool:
        main_init = self.find_main_init(bv)
        if main_init is None:
            return False

        rename_func(main_init, 'jag::App::MainInit')

        if not self.find_alloc_and_client_ctor(bv, main_init):
            return False

        if self.refactor_static_client_ptr(bv):
            logmsg: str
            if len(self.static_client_ptrs) == 1:
                logmsg = 'Found jag::Client* jag::s_pClient @ {:#x}'.format(self.static_client_ptrs[0])
                bv.define_user_data_var(self.static_client_ptrs[0],
                                        Type.pointer(bv.arch, self.jag_types.client),
                                        'jag::s_pClient')
            else:
                logmsg = 'Found multiple jag::Client* jag::s_pClient'
                for idx, ptr in enumerate(self.static_client_ptrs):
                    logmsg += '\n    @ {:#x}'.format(ptr)
                    name = 'jag::s_pClient'
                    if idx > 0:
                        name += str(idx)

                    bv.define_user_data_var(self.static_client_ptrs[0],
                                            Type.pointer(bv.arch, self.jag_types.client),
                                            name)

            log_info(logmsg)

        return True

    def find_main_init(self, bv: BinaryView) -> Optional[Function]:
        """
        Looks for references to the SetErrorMode function in Kernel32.dll.
        There should only be one function that calls SetErrorMode and that is the main init.
        Returns the Function that calls SetErrorMode or None if there are no matches or too many matches
        """
        set_error_modes = bv.get_symbols_by_name('SetErrorMode')
        if len(set_error_modes) == 0:
            return None

        set_error_mode_addr = set_error_modes[-1].address
        references = list(bv.get_code_refs(set_error_mode_addr))
        if len(references) > 1:
            log_error('SetErrorMode is referenced multiple times!')
            for ref in references:
                log_error('    at {:#x}'.format(ref.address))
            return None

        target_func = references[0].function
        log_info('found jag::App::MainInit at {:#x}'.format(target_func.start))
        return target_func

    def find_alloc_and_client_ctor(self, bv: BinaryView, main_init: Function) -> bool:
        ref_threshold = 1500
        found_alloc = False
        client_struct_size = 0
        client_struct_alignment = 0
        for llil in main_init.llil.instructions:
            (is_valid, dest_addr) = is_valid_function_call(bv, llil)
            if not is_valid or dest_addr is None:
                continue

            if not found_alloc:
                refs = list(bv.get_code_refs(dest_addr))
                if len(refs) < ref_threshold:
                    continue

                client_struct_size = llil.get_reg_value(RCX).value  # num_bytes
                client_struct_alignment = llil.get_reg_value(RDX).value  # alignment
                # 0x633d0 <-- size in version 921-4
                client_expected_size = 0x633e0  # size as of jag::Client version 922-4
                if client_struct_size != client_expected_size:
                    size_diff = abs(client_struct_size - client_expected_size)
                    if size_diff < 0x10:
                        log_warn((
                                     'Client structure size deviates more than 16 bytes from expected.'
                                     'got {:#x} but expected within 16 bytes of {:#x}'
                                 ).format(client_struct_size, client_expected_size))

                found_alloc = True
                checked_alloc = bv.get_function_at(dest_addr)
                self.checked_alloc_addr = checked_alloc.start
                rename_func(checked_alloc, '{}::CheckedAlloc'.format(self.jag_types.heap_interface_name))
                change_ret_type(checked_alloc, Type.pointer(bv.arch, Type.void()))
                change_var(checked_alloc.parameter_vars[0], 'num_bytes', Type.int(4))
                change_var(checked_alloc.parameter_vars[1], 'alignment', Type.int(4))

            else:
                with StructureBuilder.builder(bv, QualifiedName(self.jag_types.client_name)) as client_builder:
                    client_builder.packed = True
                    client_builder.alignment = client_struct_alignment
                    client_builder.width = client_struct_size

                self.jag_types.client = bv.get_type_by_name(self.jag_types.client_name)

                client_ctor = bv.get_function_at(dest_addr)
                self.client_ctor_addr = client_ctor.start
                rename_func(client_ctor, '{}::ctor'.format(self.jag_types.client_name))
                change_var(client_ctor.parameter_vars[0], 'pClient',
                           Type.pointer(bv.arch, self.jag_types.client))
                break
        return True

    def refactor_static_client_ptr(self, bv: BinaryView) -> bool:
        """
        Searches jag::App::MainInit for where the jag::Client address is stored and sets the type
        and label of the data location appropriately
        @param bv: @return: True if found; False otherwise
        """
        ctor_refs = list(bv.get_code_refs(self.client_ctor_addr))
        if len(ctor_refs) != 1:
            log_error('Expected 1 ref to jag::Client::ctor but found {}'.format(len(ctor_refs)))
            return False

        call_site_addr = ctor_refs[0].address
        containing_funcs = bv.get_functions_containing(call_site_addr)
        if len(containing_funcs) != 1:
            log_error('Expected 1 func containing call to jag::Client::ctor but found {}'.format(len(containing_funcs)))
            return False

        func = containing_funcs[0]
        call_insn = func.get_llil_at(call_site_addr)
        fun_insns = list(func.llil.instructions)
        start_idx = find_instruction_index(fun_insns, call_insn) + 1
        if start_idx <= 0:
            # shouldn't actually happen, but you never know
            log_error('Couldn\'t find call instruction in function it\'s supposed to be in')
            return False

        # the return value of jag::Client::ctor is the client address.
        # we need to track where the address stored in RAX goes
        # we expect to see the address get stored in 1 or more data locations within the next few instructions
        # we are going to track where the value of rax goes through the rest of the function. If we encountere an
        # instruction that we can't guarantee hasn't clobbered the register values, we clear the list of registers the
        # address is known to exist in.
        # While going through the instructions we will specifically look for stores with a destination of ConstPtr
        # by the time we reach the end of the function there should only be 1 data location that stil
        # contains the address of the client
        current_addr_reg_locations: list[RegisterName] = ['rax']
        current_data_locations: list[int] = []
        for i in range(start_idx, len(fun_insns)):
            insn = fun_insns[i]
            if insn.operation == LowLevelILOperation.LLIL_CALL:
                # if we encounter a call then we can't guarantee the registers are preserved
                # without doing more introspection
                # TODO: Theoretically a call could change one of the known data locations
                #       I don't think there's a need to get that sophisticated yet
                current_addr_reg_locations.clear()
            elif insn.operation == LowLevelILOperation.LLIL_STORE:
                # Encountered a store. Look for a destination of ConstPtr and src of a known client addr register
                store_insn: LowLevelILStore = insn
                dest_insn: LowLevelILInstruction = store_insn.dest
                if isinstance(dest_insn, LowLevelILConstPtr):
                    dest_insn: LowLevelILConstPtr = dest_insn
                    dest_addr = dest_insn.constant
                    src_insn = store_insn.src
                    if isinstance(src_insn, LowLevelILReg):
                        reg_insn: LowLevelILReg = src_insn
                        if reg_insn.src.name in current_addr_reg_locations:
                            if dest_addr not in current_data_locations:
                                current_data_locations.append(dest_addr)
                        elif dest_addr in current_data_locations:
                            current_data_locations.remove(dest_addr)

            elif insn.operation == LowLevelILOperation.LLIL_SET_REG:
                set_insn: LowLevelILSetReg = insn

                dest_to_add = None
                src_reg = None
                src_insn = set_insn.src
                if isinstance(src_insn, LowLevelILReg):
                    reg_insn: LowLevelILReg = src_insn
                    src_reg = reg_insn.src.name
                    if str(src_reg) in current_addr_reg_locations:
                        dest_to_add = set_insn.dest.name

                if dest_to_add is not None:
                    # prevent something like mov rcx, rcx from messing with us
                    if src_reg != dest_to_add:
                        # check if the value of a known location is changing
                        if dest_to_add in current_addr_reg_locations:
                            current_addr_reg_locations.remove(dest_to_add)
                        else:
                            current_addr_reg_locations.append(dest_to_add)

        num_ptrs = len(current_data_locations)
        if num_ptrs == 0:
            log_error("Unable to locate jag::Client* s_pClient")
            return False
        elif num_ptrs > 1:
            # as of 922-4 there should only be 1 left over data location. warn if there are more
            log_warn('Found multiple static data locations for jag::Client* s_pClient. Is this correct?')

        self.static_client_ptrs = current_data_locations
        return True

    def refactor_connection_manager(self, bv: BinaryView) -> bool:
        """
        Finds jag::ConnectionManager ctor by looking for instances of reg = reg + 20000.
        There are only a few functions that use this value
        """

        log_info('Searching for jag::ConnectionManager::ctor this will take awhile...')
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
            log_error(
                'Failed to isolate jag::ConnectionManager::ctor.\n    Remaining candidates: {}'.format(candidates))
            return False

        insn_using_current_time: Optional[LowLevelILInstruction]
        ctor: Optional[Function]
        insn_using_current_time, ctor = list(candidates.items())[0]
        ctor_instructions = list(ctor.llil.instructions)

        current_time_addr = self.find_current_time_addr(insn_using_current_time, ctor_instructions)
        if current_time_addr is None:
            log_error('Failed to find address of s_CurrentTimeMs')
            return False

        self.current_time_ms_addr = current_time_addr
        bv.define_user_data_var(self.current_time_ms_addr, Type.int(8, False), 's_CurrentTimeMs')

        log_info('Determining size of jag::ConnectionManager')
        ctor_refs = list(bv.get_code_refs(ctor.start))
        if len(ctor_refs) != 1:
            log_error('Expected 1 xref to jag::ConnectionManager::ctor but got {}'.format(len(ctor_refs)))
            return False

        allocation = find_allocation_from_ctor_call(bv,
                                                    list(ctor_refs[0].function.llil_instructions),
                                                    ctor_refs[0].function.get_llil_at(ctor_refs[0].address),
                                                    self.checked_alloc_addr)
        if allocation is None:
            log_error('Failed to determine size of jag::ConnectionManager')
            return False

        with StructureBuilder.builder(bv, QualifiedName(self.jag_types.conn_mgr_name)) as builder:
            builder.packed = True
            builder.width = allocation.size
            builder.alignment = allocation.alignment

        self.jag_types.conn_mgr = bv.get_type_by_name(self.jag_types.conn_mgr_name)

        self.connection_manager_ctor_addr = ctor.start
        log_info('Found jag::ConnectionManager::ctor at {:#x}'.format(self.connection_manager_ctor_addr))

        rename_func(ctor, '{}::ctor'.format(self.jag_types.conn_mgr_name))
        change_var_type(ctor.parameter_vars[0], Type.pointer(bv.arch, self.jag_types.conn_mgr))
        change_var_type(ctor.parameter_vars[1], Type.pointer(bv.arch, self.jag_types.client))
        return True

    def find_current_time_addr(self,
                               insn_using_current_time: LowLevelILInstruction,
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
            log_error('s_CurrentTimeMs doesn\'t appear to be coming from a register. Script needs updating!')
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
                operand = load.operands[0]
                if isinstance(operand, LowLevelILConstPtr):
                    ptr: LowLevelILConstPtr = operand
                    return ptr.constant

            log_error('s_CurrentTimeMs doesn\'t appear to be coming from a static address. Script needs updating!')
            break

        return None
