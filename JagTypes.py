from typing import Optional
from binaryninja import Type


class JagTypes:
    current_time_ms_name = 'jag::FrameTime::m_CurrentMS'

    client_name = 'jag::Client'
    client: Optional[Type] = None

    isaac_name = 'jag::Isaac'
    isaac: Optional[Type] = None

    heap_interface_name = 'jag::HeapInterface'
    heap_interface: Optional[Type] = None

    conn_mgr_name = 'jag::ConnectionManager'
    conn_mgr: Optional[Type] = None

    client_prot_name = 'jag::ClientProt'
    client_prot: Optional[Type] = None

    server_prot_name = 'jag::ServerProt'
    server_prot: Optional[Type] = None

    packet_handler_name = 'jag::PacketHandler'
    packet_handler: Optional[Type] = None

    packet_name = 'jag::Packet'
    packet: Optional[Type] = None
