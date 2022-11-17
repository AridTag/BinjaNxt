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

from BinjaNxt.Nxt import Nxt
#from Nxt import Nxt

plugin_name = 'BinjaNxt'


def run(bv: BinaryView):
    nxt = Nxt()
    if not nxt.run(bv):
        show_message_box(plugin_name, 'Refactoring failed! Check the log for more information',
                         MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)
        return

    show_message_box(plugin_name, 'Done!', MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.InformationIcon)


def __run(bv: BinaryView, addr):
    run(bv)


PluginCommand.register_for_address("BinjaNxt Refactor", "Refactors the Runescape Nxt client", __run)
