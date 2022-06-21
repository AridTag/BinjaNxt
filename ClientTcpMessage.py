from binaryninja import *

from NxtAnalysisData import NxtAnalysisData


class ClientTcpMessage:
    found_data: NxtAnalysisData

    def __init__(self, found_data: NxtAnalysisData):
        self.found_data = found_data

    def run(self, bv: BinaryView) -> bool:
        visited_funcs_outer: list[int] = []
        refs = bv.get_code_refs(0x140999868)
        for r in refs:
            func = r.function
            if func.start in visited_funcs_outer:
                continue

            visited_funcs_outer.append(func.start)
            for insn in func.llil.instructions:
                pass


        if self.found_data.current_time_ms_addr is None:
            log_error('Address of jag::FrameTime::m_CurrentTimeMS is required ClientProt, RegisterClientProt, MakeClientMessage for client tcp messages')
        return True

    
