from typing import Optional, TypedDict
from BinjaNxt.JagTypes import JagTypes
from BinjaNxt.PacketHandlerInfo import PacketHandlerInfo

#from JagTypes import JagTypes
#from PacketHandlerInfo import PacketHandlerInfo


class NxtAnalysisData:
    types: JagTypes = JagTypes()
    static_client_ptrs: list[int] = []
    current_time_ms_addr: Optional[int] = None
    checked_alloc_addr: Optional[int] = None
    connection_manager_ctor_addr: Optional[int] = None
    client_ctor_addr: Optional[int] = None
    register_packet_handler_addr: Optional[int] = None
    packet_handlers: list[PacketHandlerInfo] = []

