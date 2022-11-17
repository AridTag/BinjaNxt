"""
Copyright 2022 AridTag and Contributors
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

from BinjaNxt.NxtAnalysisData import NxtAnalysisData
from BinjaNxt.NxtUtils import  *
from BinjaNxt.ClientProtInfo import ClientProtInfo

#from NxtAnalysisData import NxtAnalysisData
#from NxtUtils import *
#from ClientProtInfo import ClientProtInfo


class ClientTcpMessage:
    found_data: NxtAnalysisData

    _addr_some_clientprot: Optional[int] = None

    # in 918 there are 124
    MIN_CLIENT_PROTS = 120
    MAX_CLIENT_PROTS = 135


    def __init__(self, found_data: NxtAnalysisData):
        self.found_data = found_data


    def run(self, bv: BinaryView) -> bool:
        if self.found_data.current_time_ms_addr is None:
            log_error('Address of jag::FrameTime::m_CurrentTimeMS is required for MakeClientMessage, ClientProt, RegisterClientProt')
            return False

        if not self._refactor_makeclientmessage(bv):
            return False

        self._refactor_registerclientprot(bv)
        self._refactor_clientprots(bv)

        return True


    def _refactor_makeclientmessage(self, bv: BinaryView) -> bool:
        fn_make_client_message: Optional[Function] = None
        func_calling_make_client_message: Optional[Function] = None
        insn_call_make_client_message: Optional[LowLevelILCall] = None

        visited_funcs: list[int] = []
        current_time_refs = bv.get_code_refs(self.found_data.current_time_ms_addr)
        for ref in current_time_refs:
            func = ref.function
            if func.start in visited_funcs:
                continue

            visited_funcs.append(func.start)

            if not ensure_func_analyzed(func):
                continue

            for insn in func.llil.instructions:
                if not isinstance(insn, LowLevelILSetReg):
                    continue

                set_reg: LowLevelILSetReg = insn
                value_expr = set_reg.operands[1]
                if not isinstance(value_expr, LowLevelILConst):
                    continue

                value: LowLevelILConst = value_expr
                if value.constant != 0x6666666666666667:
                    continue

                found_func, func_calling, call_insn = self._find_make_client_message(bv, func)
                if found_func is not None:
                    if found_func == fn_make_client_message:
                        continue

                    if fn_make_client_message is not None:
                        self._log_too_many_candidates_makeclientmessage()
                        return False

                    fn_make_client_message = found_func
                    func_calling_make_client_message = func_calling
                    insn_call_make_client_message = call_insn
                    break

        if fn_make_client_message is None:
            log_error("Failed to locate jag::game::ServerConnection::MakeClientMessage<jag::ClientProt>")
            return False

        log_info('Found jag::game::ServerConnection::MakeClientMessage<jag::ClientProt> @ {:#x}'
                 .format(fn_make_client_message.start))

        self.found_data.make_client_message_addr = fn_make_client_message.start
        change_func_name(fn_make_client_message, "jag::game::ServerConnection::MakeClientMessage<jag::ClientProt>")

        self._addr_some_clientprot = self._find_clientprot_addr(func_calling_make_client_message,
                                                          insn_call_make_client_message)
        return True


    def _refactor_registerclientprot(self, bv: BinaryView) -> bool:
        if self._addr_some_clientprot is None:
            return False

        refs = bv.get_code_refs(self._addr_some_clientprot - 4)
        for ref in refs:
            instructions = list(ref.function.llil.instructions)
            insn_index = find_instruction_index(instructions, ref.function.get_llil_at(ref.address, ref.arch))
            for i in range(max(0, insn_index - 4), len(instructions)):
                insn = instructions[i]
                if not isinstance(insn, LowLevelILTailcall):
                    continue

                tail_call: LowLevelILTailcall = insn
                dest = tail_call.dest
                if not isinstance(dest, LowLevelILConstPtr):
                    continue

                ptr: LowLevelILConstPtr = dest
                num_register_refs = len(list(bv.get_code_refs(ptr.constant)))
                if self.MIN_CLIENT_PROTS < num_register_refs < self.MAX_CLIENT_PROTS:
                    func = bv.get_function_at(ptr.constant)
                    change_func_name(func, 'jag::RegisterClientProt')
                    if len(func.parameter_vars) == 3:
                        change_var(func.parameter_vars[0], 'pClientProt', Type.pointer(bv.arch, self.found_data.types.client_prot))
                        change_var(func.parameter_vars[1], 'opCode', Type.int(4, False))
                        change_var(func.parameter_vars[2], 'size', Type.int(4))
                    self.found_data.register_clientprot_addr = func.start
                    return True

        log_error("Failed to locate jag::RegisterClientProt")
        return False


    def _refactor_clientprots(self, bv: BinaryView):
        references = list(bv.get_code_refs(self.found_data.register_clientprot_addr))
        log_info("Found {} references to jag::RegisterClientProt".format(len(references)))
        for ref in references:

            prot_addr: Optional[int] = None
            opcode: Optional[int] = None
            size: Optional[int] = None

            skip_reference = False
            for insn in ref.function.mlil.instructions:
                if insn.address != ref.address:
                    continue

                if not isinstance(insn, MediumLevelILCallBase):
                    skip_reference = True
                    break

                if isinstance(insn, MediumLevelILTailcall):
                    tail_call: MediumLevelILTailcall = insn
                    if not isinstance(tail_call.dest, MediumLevelILConstPtr) or tail_call.dest.constant != self.found_data.register_clientprot_addr:
                        log_warn('Instruction referencing jag::RegisterClientProt is not calling jag::RegisterClientProt @ {}'
                                 .format(hex(ref.address)))
                        skip_reference = True
                    else:
                        if len(tail_call.params) != 3:
                            log_warn('Invalid number of args to jag::RegisterClientProt @ {}'
                                     .format(hex(ref.address)))
                            skip_reference = True

                        ptr: MediumLevelILConstPtr = tail_call.params[0]
                        op: MediumLevelILConst = tail_call.params[1]
                        size_insn: MediumLevelILConst = tail_call.params[2]
                        prot_addr = ptr.constant
                        opcode = op.constant
                        size = size_insn.constant
                elif isinstance(insn, MediumLevelILCall):
                    call: MediumLevelILCall = insn
                    if not isinstance(call.dest, MediumLevelILConstPtr) or call.dest.constant != self.found_data.register_clientprot_addr:
                        log_warn('Instruction referencing jag::RegisterClientProt is not calling jag::RegisterClientProt @ {}'
                                 .format(hex(ref.address)))
                        skip_reference = True
                    else:
                        if len(call.params) != 3:
                            log_warn('Invalid number of args to jag::RegisterClientProt @ {}'
                                     .format(hex(ref.address)))
                            skip_reference = True

                        ptr: MediumLevelILConstPtr = call.params[0]
                        op: MediumLevelILConst = call.params[1]
                        size_insn: MediumLevelILConst = call.params[2]
                        prot_addr = ptr.constant
                        opcode = op.constant
                        size = size_insn.constant
                else:
                    log_warn("Reference to jag::RegisterClientProt is not a Call @ {}".format(hex(ref.address)))
                    skip_reference = True

                break

            if skip_reference:
                continue

            prot: ClientProtInfo = ClientProtInfo(opcode, int32(size), prot_addr, ref.function.start)
            self.found_data.clientprots.append(prot)

            bv.define_data_var(prot.addr,
                               self.found_data.types.client_prot,
                               'jag::ClientProt::ClientProtOP_{}'.format(prot.opcode))


    def _find_clientprot_addr(self, func_calling_make_client_message: Function, insn_call_make_client_message: LowLevelILCall) -> Optional[int]:
        load_prot_addr_insn = insn_call_make_client_message
        instructions = list(func_calling_make_client_message.llil.instructions)
        index_of_call = find_instruction_index(instructions, insn_call_make_client_message)
        for i in range(index_of_call, max(0, index_of_call - 10), -1):
            insn = instructions[i]
            if isinstance(insn, LowLevelILSetReg):
                set_reg: LowLevelILSetReg = insn
                dest = set_reg.operands[0]
                src = set_reg.operands[1]
                if isinstance(dest, ILRegister):
                    reg: ILRegister = dest
                    if reg.name.casefold() == R8.casefold():
                        if isinstance(src, LowLevelILConstPtr):
                            ptr: LowLevelILConstPtr = src
                            return ptr.constant

        return None


    def _log_too_many_candidates_makeclientmessage(self):
        log_error(
            "Found more than one candidate for jag::game::ServerConnection::MakeClientMessage_ClientProt\nClientProt, RegisterClientProt and MakeClientMessage will not be located")


    def _find_make_client_message(self, bv: BinaryView, func: Function) -> (Optional[Function], Optional[Function], Optional[LowLevelILCall]):
        found_func: Optional[Function] = None
        func_calling: Optional[Function] = None
        call_func_insn: Optional[LowLevelILCall] = None

        for insn in func.llil.instructions:
            if not isinstance(insn, LowLevelILCall):
                continue

            call_insn: LowLevelILCall = insn
            called = get_called_func(bv, call_insn)
            if called is None:
                continue

            if not ensure_func_analyzed(called):
                continue

            for insn2 in called.llil.instructions:
                if not isinstance(insn2, LowLevelILCall):
                    continue

                called2 = get_called_func(bv, insn2)
                if called2 is None:
                    continue

                func_type, demangled_name = demangle_ms(called2.arch, called2.name)
                if func_type is None:
                    continue

                if get_qualified_name(demangled_name).casefold() == "std::_Throw_C_error".casefold():
                    if found_func is not None:
                        self._log_too_many_candidates_makeclientmessage()
                        return None

                    found_func = called
                    func_calling = func
                    call_func_insn = insn
                    break

        return found_func, func_calling, call_func_insn
