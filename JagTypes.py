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
from typing import Optional

from binaryninja import Type, BinaryView


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

    def create_types(self, bv: BinaryView):
        t_isaac = Type.structure(members=[
            (Type.int(4, False), 'valuesRemaining'),  # This may actually be value used, investigate.
            (Type.array(Type.int(4, False), 256), 'results'),
            (Type.array(Type.int(4, False), 256), 'mm'),
            # One of these is the counter, another is the accumulator
            (Type.int(4), 'aa'),
            (Type.int(4), 'bb'),
            (Type.int(4), 'cc')
        ], packed=True)
        bv.define_user_type(self.isaac_name, t_isaac)
        self.isaac = bv.get_type_by_name(self.isaac_name)

        t_heap_interface = Type.structure(packed=True)
        bv.define_user_type(self.heap_interface_name, t_heap_interface)
        self.heap_interface = bv.get_type_by_name(self.heap_interface_name)

        t_client_prot = Type.structure(members=[
            (Type.int(4, False), 'opcode'),
            (Type.int(4), 'size')
        ], packed=True)
        bv.define_user_type(self.client_prot_name, t_client_prot)
        self.client_prot = bv.get_type_by_name(self.client_prot_name)

        t_server_prot = Type.structure(members=[
            (Type.int(4, False), 'opcode'),
            (Type.int(4), 'size')
        ], packed=True)
        bv.define_user_type(self.server_prot_name, t_server_prot)
        self.server_prot = bv.get_type_by_name(self.server_prot_name)

        t_packethandler_builder = Type.structure(members=[
            (Type.pointer(bv.arch, Type.void()), 'vtable')
        ], packed=True).mutable_copy()
        t_packethandler_builder.width = 0x48
        bv.define_user_type(self.packet_handler_name, t_packethandler_builder.immutable_copy())
        self.packet_handler = bv.get_type_by_name(self.packet_handler_name)

        t_packet = Type.structure(members=[
            (Type.int(8), 'unk1'),
            (Type.int(8), 'capacity'),
            (Type.pointer(bv.arch, Type.int(1, False)), 'buffer'),
            (Type.int(8), 'offset'),
            (Type.int(4), 'unk2'),
            (Type.int(8), 'unk3')
        ], packed=True)
        bv.define_user_type(self.packet_name, t_packet)
        self.packet = bv.get_type_by_name(self.packet_name)
