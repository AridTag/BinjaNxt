from typing import Optional
from binaryninja import Type


class JagTypes:
    namespace_sep = "_"

    client_name = 'jag{}Client'.format(namespace_sep)
    client: Optional[Type] = None

    isaac_name = 'jag{}Isaac'.format(namespace_sep)
    isaac: Optional[Type] = None

    heap_interface_name = 'jag{}HeapInterface'.format(namespace_sep)
    heap_interface: Optional[Type] = None

    conn_mgr_name = 'jag{}ConnectionManager'.format(namespace_sep)
    conn_mgr: Optional[Type] = None

    client_prot_name = 'jag{}ClientProt'.format(namespace_sep)
    client_prot: Optional[Type] = None

    packet_name = 'jag{}Packet'.format(namespace_sep)
    packet: Optional[Type] = None
