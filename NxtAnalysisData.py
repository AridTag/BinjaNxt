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
from typing import Optional, TypedDict
from BinjaNxt.JagTypes import JagTypes
from BinjaNxt.PacketHandlerInfo import PacketHandlerInfo
from BinjaNxt.ClientProtInfo import ClientProtInfo

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
    make_client_message_addr: Optional[int] = None
    register_clientprot_addr: Optional[int] = None
    isaac_init_addr: Optional[int] = None
    isaac_generate_addr: Optional[int] = None
    clientprots: list[ClientProtInfo] = []

    def print_info(self):
        self.packet_handlers.sort(key=lambda x: x.opcode)
        print('Handlers: [')
        print(*self.packet_handlers, sep=',\n    ')
        print(']')

        self.clientprots.sort(key=lambda x: x.opcode)
        print('ClientProts: [')
        print(*self.clientprots, sep=',\n')
        print(']')

        self.print_cpp()

    def print_cpp(self):
        print('ServerProtNames')
        for handler in self.packet_handlers:
            print('{' + '{}, L"{}"'.format(handler.opcode, handler.name) + '},\n')

        print('\n\n')

        print('ServerProtSizes')
        for handler in self.packet_handlers:
            print('{' + '{}, {}'.format(handler.opcode, handler.size) + '},\n')

        print('ClientProtSizes')
        for prot in self.clientprots:
            print('{' + '{}, {}'.format(prot.opcode, prot.size) + '},\n')

