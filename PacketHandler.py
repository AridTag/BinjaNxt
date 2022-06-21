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

from BinjaNxt.NxtUtils import *
from BinjaNxt.PacketHandlerInfo import *
from BinjaNxt.JagTypes import *
from BinjaNxt.NxtAnalysisData import NxtAnalysisData


#from NxtAnalysisData import NxtAnalysisData
#from JagTypes import *
#from NxtUtils import *
#from PacketHandlerInfo import *


class PacketHandlers:
    found_data: NxtAnalysisData

    __EXPECTED_NUM_SERVER_HANDLERS: int = 195

    __server_packet_name_offs = 0

    def __init__(self, found_data: NxtAnalysisData):
        self.found_data = found_data
        self.found_data.packet_handlers = [None] * self.__EXPECTED_NUM_SERVER_HANDLERS

    def run(self, bv: BinaryView, connection_manager_ctor_addr: int) -> bool:
        packet_handler_ctor = self.find_packet_handler_ctor_and_register(bv, connection_manager_ctor_addr)
        if packet_handler_ctor is None:
            return False

        log_info('Found RegisterPacketHandler @ ' + hex(self.found_data.register_packet_handler_addr))
        log_info('Found jag::PacketHandler::ctor @ ' + packet_handler_ctor.name)

        if not self.__initialize_server_packet_infos(bv, packet_handler_ctor):
            log_error('Failed to initialize PacketHandler info')
            return False

        if not self.__initialize_server_packet_handler_names(bv, connection_manager_ctor_addr):
            log_error('Failed to initialize PacketHandler names')
            return False

        for handler in self.found_data.packet_handlers:
            if handler.name == "":
                continue

            qualified_handler_name, clean_name = self.get_qualified_handler_name(handler.name)
            handler_ctor = bv.get_function_at(handler.ctor)
            rename_func(handler_ctor, '{}::ctor'.format(qualified_handler_name))

            if handler.vtable is not None:
                change_comment(bv, handler.vtable, 'start vtable {}'.format(qualified_handler_name))

                handle_packet_vtable_addr = handler.vtable + (bv.arch.address_size * 2)
                handle_packet_addr: Optional[int]
                try:
                    handle_packet_addr = bv.read_int(handle_packet_vtable_addr, bv.arch.address_size, False)
                except ValueError:
                    # TODO: As of version 922-4 there is one unhandled case with IfSetPlayerHeadIgnoreWorn
                    # See: corresponding todo in __find_packet_handler_vtable
                    log_error('vtable issue with ' + handler.name + ' - ' + str(handler.opcode) + ', ' + hex(handler.vtable))
                    handler.vtable = None
                    handle_packet_addr = None

                if handle_packet_addr is not None:
                    handle_packet_func = bv.get_function_at(handle_packet_addr)
                    if handle_packet_func is None:
                        # TODO: Can I create a function? what is a "user" function?
                        print('no func?')
                    else:
                        rename_func(handle_packet_func, '{}::HandlePacket'.format(qualified_handler_name))

                        if len(handle_packet_func.parameter_vars) >= 2:
                            change_var(handle_packet_func.parameter_vars[1], 'pPacket', Type.pointer(bv.arch, self.found_data.types.packet))

        print('Handlers: [')
        print(*self.found_data.packet_handlers, sep=',\n    ')
        print(']')

        return True

    def get_qualified_handler_name(self, handler_name: str) -> (str, str):
        """

        @param handler_name:
        @return: The fully qualified name as the first value and the "clean" handler name as the second
        """
        clean_name = ""
        for s in handler_name.split('_'):
            if len(s) < 2:
                continue
            clean_name = clean_name + s.title()

        fqn = "jag::PacketHandlers::{}".format(clean_name)
        return fqn, clean_name

    def __initialize_server_packet_infos(self, bv: BinaryView, packet_handler_ctor: Function) -> bool:
        ctor_refs = list(bv.get_code_refs(packet_handler_ctor.start))
        for idx, ref in enumerate(ctor_refs):
            if not ref.function.is_call_instruction(ref.address):
                ctor_refs.remove(ref)

        num_valid = 0
        for ref in ctor_refs:
            call_insn = ref.function.get_llil_at(ref.address)
            rcx = call_insn.get_reg_value(RCX)
            rdx = call_insn.get_reg_value(RDX)
            r8d = call_insn.get_reg_value(R8D)
            if isinstance(rdx, Undetermined):
                continue
            if isinstance(r8d, Undetermined):
                continue
            if isinstance(rcx, Undetermined):
                continue

            opcode = ctypes.c_int(rdx.value).value
            size = ctypes.c_int(r8d.value).value
            addr = rcx.value + 0x8
            ctor = ref.function

            # If jagex decides to add more than the currently known amount of packets (195)
            if opcode > len(self.found_data.packet_handlers) - 1:
                for i in range(0, (opcode - len(self.found_data.packet_handlers))):
                    self.found_data.packet_handlers.append(None)

            self.found_data.packet_handlers[opcode] = PacketHandlerInfo(opcode, size, addr, ctor.start)
            num_valid += 1

        log_info('Found {} valid packet handlers of {} possible'.format(num_valid, len(ctor_refs)))
        if num_valid != len(ctor_refs):
            return False

        return True

    def __initialize_server_packet_handler_names(self, bv: BinaryView,
                                                 connection_manager_ctor_addr: Optional[int]) -> bool:
        if connection_manager_ctor_addr is None:
            print('Address of jag::ConnectionManager::ctor is required to name packet handlers')
            return False

        connection_manager_ctor = bv.get_function_at(connection_manager_ctor_addr)
        visited_func_addrs: list[int] = []
        call_num: int = 0
        try:
            # We are going to loop through the ConnectionManager::ctor and recursive follow any function calls
            # looking for calls to RegisterPacketHandler. The order of those calls will dictate the name
            # of the handler (I guess?)
            for insn in connection_manager_ctor.llil.instructions:
                (valid_call, dest_addr) = is_valid_function_call(bv, insn)
                if not valid_call:
                    continue

                call_num += 1
                if call_num <= 2:
                    continue

                # start at the 3rd call instruction for whatever reason
                self.__find_packet_handler_registrations_recurse(bv, connection_manager_ctor, insn,
                                                                 bv.get_function_at(dest_addr), visited_func_addrs)

        except Exception as e:
            print("Fatal error")
            traceback.print_exception(e)
            return False

        return True

    def __find_packet_handler_registrations_recurse(self,
                                                    bv: BinaryView,
                                                    containing_func: Function,
                                                    call_insn: LowLevelILInstruction,
                                                    called_func: Function,
                                                    visited_func_addrs: list[int],
                                                    parent_call_ins: Optional[LowLevelILInstruction] = None):
        if called_func.start == self.found_data.register_packet_handler_addr:
            rcx = call_insn.get_reg_value(RCX)
            rdx = call_insn.get_reg_value(RDX)
            if isinstance(rcx, Undetermined):
                print('Undetermined PacketHandler::HandlePacket addr???')
                return
            if isinstance(rdx, Undetermined):
                print('Undetermined PacketHandler addr???')
                return

            addr = rdx.value
            addr_original = addr
            handler = self.packet_handler_from_addr(addr)
            if handler is None:
                # a few can be grabbed from rcx at the parent call site
                if parent_call_ins is not None:
                    parent_rcx = parent_call_ins.get_reg_value(RCX)
                    if not isinstance(parent_rcx, Undetermined):
                        addr = parent_rcx.value
                        handler = self.packet_handler_from_addr(addr)

                    # can also be found in rdx of the parent...
                    if handler is None:
                        parent_rdx = parent_call_ins.get_reg_value(RDX)
                        if not isinstance(parent_rdx, Undetermined):
                            addr = parent_rdx.value
                            handler = self.packet_handler_from_addr(addr)

                if handler is None:
                    print('Unknown PacketHandler addr=' + hex(addr) + ' addr_original=' + hex(
                        addr_original) + ' - insn = '
                          + str(call_insn) + ' @ ' + hex(call_insn.address))
                    return

            if handler.done:
                return

            # TODO: opcode 126 IF_SETPLAYERHEAD_IGNOREWORN isn't even making it here
            packet_handler_vtable = self.__find_packet_handler_vtable(call_insn, containing_func, rcx)

            handler.done = True
            handler.name = server_packet_names[self.__server_packet_name_offs]
            handler.vtable = packet_handler_vtable
            self.__server_packet_name_offs += 1
            return

        # loop through all the instructions of called_func looking for nested register calls
        for insn in called_func.llil.instructions:
            (valid_call, dest_addr) = is_valid_function_call(bv, insn)
            if not valid_call:
                continue

            isregister = True if self.found_data.register_packet_handler_addr is not None \
                and dest_addr == self.found_data.register_packet_handler_addr else False

            if dest_addr not in visited_func_addrs or isregister:
                if not isregister:
                    visited_func_addrs.append(dest_addr)

                fun = bv.get_function_at(dest_addr)
                if fun is None:
                    continue

                self.__find_packet_handler_registrations_recurse(bv, called_func, insn, fun, visited_func_addrs, call_insn)

        return

    def __find_packet_handler_vtable(self, call_insn, containing_func, rcx) -> Optional[int]:
        vtable_addr: Optional[int] = None
        if isinstance(rcx, StackFrameOffsetRegisterValue):
            # TODO: This feels not great. I'm not sure if there is a better way to do this..
            # Looking for an instruction similar to "[rbp - 0x29 {var_88}].q = rax"
            # In this example case the value stored in the stack from rax is the address of the vtable
            # We want to pull that address so we need to find where it comes from and get the
            # value at that instruction
            # we start at call_insn and walk backwards through the func instructions looking for
            # the value of rcx at the call site
            fun_instructions = list(containing_func.llil.instructions)
            fun_instructions.reverse()
            start_idx = find_instruction_index(fun_instructions, call_insn)

            set_rcx_insn: Optional[LowLevelILSetReg] = None
            # start by looking for the instruction that sets rcx
            for i in range(start_idx + 1, len(fun_instructions)):
                fun_insn = fun_instructions[i]
                if isinstance(fun_insn, LowLevelILSetReg):
                    set_reg: LowLevelILSetReg = fun_insn
                    if set_reg.dest.name == RCX:
                        set_rcx_insn = fun_insn
                        break

            if set_rcx_insn is None:
                # couldn't find what sets rcx
                return None

            rbp_at_set_rcx = set_rcx_insn.get_reg_value(RBP)

            for i in range(start_idx + 1, len(fun_instructions)):
                fun_insn = fun_instructions[i]
                rbp_current = fun_insn.get_reg_value(RBP)
                if isinstance(fun_insn, LowLevelILStore):
                    store_insn: LowLevelILStore = fun_insn
                    dest_insn = store_insn.dest
                    if isinstance(dest_insn, LowLevelILAdd):
                        add_insn: LowLevelILAdd = dest_insn
                        left_insn = add_insn.left
                        right_insn = add_insn.right
                        # TODO: It could be possible for left and right to be swapped i guess...i don't see why not
                        if isinstance(left_insn, LowLevelILReg) and isinstance(right_insn, LowLevelILConst):
                            op_reg: LowLevelILReg = left_insn
                            op_const: LowLevelILConst = right_insn
                            if op_reg.src.name.lower() == 'rbp':
                                if (rbp_current == rbp_at_set_rcx and op_const.constant == rcx.offset) \
                                        or op_const.constant < 0:
                                    # TODO: Looking for _any_ negative offset on rbp is probably _not_ the play
                                    #       but it seems to work for now.
                                    src_insn = store_insn.src
                                    if isinstance(src_insn, LowLevelILReg):
                                        src_reg: LowLevelILReg = src_insn
                                        vtable_addr = src_reg.value.value
                                        if isinstance(vtable_addr, Undetermined):
                                            print('! {}'.format(store_insn))
                                    elif isinstance(src_insn, LowLevelILConst):
                                        src_const: LowLevelILConst = src_insn
                                        vtable_addr = src_const.constant
                                        if isinstance(vtable_addr, Undetermined):
                                            print('!! {}'.format(store_insn))
                                    else:
                                        print('Unknown src for PacketHandler vtable')
                                        print("[{}] - [{} ({})] - [{} ({})] src {} ({}) {}"
                                              .format(fun_insn,
                                                      add_insn.left,
                                                      type(add_insn.left),
                                                      add_insn.right,
                                                      type(add_insn.right),
                                                      store_insn.src,
                                                      type(store_insn.src),
                                                      store_insn.src.value.value))
                                    break

        else:
            vtable_addr = rcx.value

        return vtable_addr

    def packet_handler_from_addr(self, addr: int) -> Optional[PacketHandlerInfo]:
        for handler in self.found_data.packet_handlers:
            if handler is not None and handler.addr == addr:
                return handler

        return None

    def find_packet_handler_ctor_and_register(self,
                                              bv: BinaryView,
                                              connection_manager_ctor_addr: int) -> Optional[Function]:
        print('Searching for jag::PacketHandler::ctor')
        connection_manager_ctor = bv.get_function_at(connection_manager_ctor_addr)

        visited_func_addrs: list[int] = []
        call_num: int = 0
        try:
            for insn in connection_manager_ctor.llil.instructions:
                (valid_call, dest_addr) = is_valid_function_call(bv, insn)
                if not valid_call:
                    continue

                call_num += 1
                if call_num <= 2:
                    continue

                # start at the 3rd call instruction for whatever reason
                # print(insn)
                ctor = self.__find_packet_handler_base_ctor_recurse(bv,
                                                                    insn,
                                                                    bv.get_function_at(dest_addr),
                                                                    visited_func_addrs)
                if ctor is not None:
                    return ctor
        except Exception as e:
            print("Fatal error\n" + str(e))
            return None

        print('Failed to find jag::PacketHandler::ctor')
        return None

    def __find_packet_handler_base_ctor_recurse(self,
                                                bv: BinaryView,
                                                call_insn: LowLevelILInstruction,
                                                called_func: Function,
                                                visited_func_addrs: list[int]) -> Optional[Function]:
        if self.found_data.register_packet_handler_addr is None and len(called_func.callers) > 200:
            self.found_data.register_packet_handler_addr = called_func.start
            visited_func_addrs.remove(self.found_data.register_packet_handler_addr)

            rdx = call_insn.get_reg_value(RDX)
            if isinstance(rdx, Undetermined):
                raise Exception(
                    "Unable to determine address of PacketHandler for initial call to RegisterPacketHandler")

            addr = rdx.value
            vtable_addr = addr - 8
            vtable_refs = list(bv.get_code_refs(vtable_addr))
            if len(vtable_refs) <= 1:
                raise Exception("Expected more than 1 initial vtable reference but got " + str(len(vtable_refs)))

            # we want to filter the vtable refs down to just the call
            # to the base ctor that takes the vtable as a parameter
            for idx, r in enumerate(vtable_refs):
                if not r.function.is_call_instruction(r.address):
                    vtable_refs.remove(r)

            if len(vtable_refs) != 1:
                raise Exception("Expected 1 reference to vtable of PacketHandler but got " + str(len(vtable_refs)))

            the_insn = vtable_refs[0].function.get_llil_at(vtable_refs[0].address)
            if not isinstance(the_insn, LowLevelILCall):
                raise Exception("Unexpected instruction type! {} - {}".format(the_insn, type(the_insn)))

            base_ctor_call_insn: LowLevelILCall = the_insn
            if isinstance(base_ctor_call_insn.dest.value, Undetermined):
                raise Exception(
                    "Unable to determine dest address of call to jag::PacketHandler::ctor. Script might need updating")

            return bv.get_function_at(base_ctor_call_insn.dest.value.value)

        # loop through all the instructions of the called function looking for nested register calls
        for insn in called_func.llil.instructions:
            (valid_call, dest_addr) = is_valid_function_call(bv, insn)
            if not valid_call:
                continue

            isregister = True if self.found_data.register_packet_handler_addr is not None \
                and dest_addr == self.found_data.register_packet_handler_addr else False

            if dest_addr not in visited_func_addrs or isregister:
                if not isregister:
                    visited_func_addrs.append(dest_addr)

                res = self.__find_packet_handler_base_ctor_recurse(bv,
                                                                   insn,
                                                                   bv.get_function_at(dest_addr),
                                                                   visited_func_addrs)
                if res is not None:
                    return res

        return None
