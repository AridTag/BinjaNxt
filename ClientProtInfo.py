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


class ClientProtInfo:
    name: str = ""
    opcode: int
    size: Optional[int]
    addr: int
    init_addr: int

    def __init__(self, opcode: int, size: Optional[int], addr: int, init_addr: int):
        self.opcode = opcode
        self.size = size
        self.addr = addr
        self.init_addr = init_addr

    def __str__(self):
        return '[opcode={}, size={}, addr={}, init_addr={}]'\
            .format(str(self.opcode),
                    str(self.size),
                    hex(self.addr),
                    hex(self.init_addr))
