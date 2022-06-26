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