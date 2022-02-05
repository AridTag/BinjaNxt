# BinjaNxt
Author: **AridTag**

Binary Ninja plugin for automated refactoring of the RuneScape Nxt client

## Description:
Plugin for Binary Ninja originally based on the Ghidra script created by [Techdaan](https://github.com/Techdaan/) : [rs3nxt-ghidra-scripts](https://github.com/Techdaan/rs3nxt-ghidra-scripts)

Can be run via the plugin menu or via the python console by entering the following commands
```python
import BinjaNxt.NxtUtils
import BinjaNxt.PacketHandlerInfo
import BinjaNxt.PacketHandler
import BinjaNxt.Nxt
import BinjaNxt
import importlib

importlib.reload(BinjaNxt.NxtUtils);importlib.reload(BinjaNxt.PacketHandlerInfo);importlib.reload(BinjaNxt.PacketHandler);importlib.reload(BinjaNxt.Nxt);importlib.reload(BinjaNxt);BinjaNxt.refactor_nxt(bv, 0)
```

## License
This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 
