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

class PacketHandlerInfo:
    done: bool = False
    name: str = ""
    opcode: int
    size: int
    addr: int
    vtable: Optional[int]
    ctor: int

    def __init__(self, opcode: int, size: int, addr: int, ctor: int):
        self.opcode = opcode
        self.size = size
        self.addr = addr
        self.ctor = ctor
        self.vtable = None

    def __str__(self):
        return 'PacketHandler[name={}, opcode={}, size={}, addr={}, ctor={}, vtable={}]'\
            .format(self.name,
                    str(self.opcode),
                    str(self.size),
                    hex(self.addr),
                    hex(self.ctor),
                    hex(self.vtable) if self.vtable is not None else "Unknown")


server_packet_names: list[str] = [
    # /* Animations */
    "LOC_ANIM_SPECIFIC",
    "PROJANIM_SPECIFIC",
    "SPOTANIM_SPECIFIC",
    "NPC_ANIM_SPECIFIC",
    "RESET_ANIMS",
    "SERVER_TICK_END",

    # /* Audio */
    "SYNTH_SOUND",
    "VORBIS_SOUND",
    "VORBIS_SPEECH_SOUND",
    "VORBIS_SPEECH_STOP",
    "VORBIS_PRELOAD_SOUNDS",
    "VORBIS_SOUND_GROUP",
    "VORBIS_SOUND_GROUP_START",
    "VORBIS_SOUND_GROUP_STOP",
    "VORBIS_PRELOAD_SOUND_GROUP",
    "SOUND_MIXBUSS_ADD",
    "SOUND_MIXBUSS_SETLEVEL",
    "MIDI_SONG",
    "MIDI_SONG_STOP",
    "MIDI_SONG_LOCATION",
    "MIDI_JINGLE",
    "SONG_PRELOAD",

    # /* Camera */
    "CAMERA_UPDATE",
    "CAM2_ENABLE",
    "CAM_RESET",
    "CAM_FORCEANGLE",
    "CAM_MOVETO",
    "CAM_LOOKAT",
    "CAM_SMOOTHRESET",
    "CAM_SHAKE",
    "CAM_REMOVEROOF",
    "CUTSCENE",

    # /* Chat */
    "MESSAGE_PUBLIC",
    "MESSAGE_GAME",
    "CHAT_FILTER_SETTINGS",
    "MESSAGE_PRIVATE",
    "MESSAGE_PRIVATE_ECHO",
    "MESSAGE_FRIENDCHANNEL",
    "MESSAGE_CLANCHANNEL",
    "MESSAGE_CLANCHANNEL_SYSTEM",
    "MESSAGE_QUICKCHAT_PRIVATE_ECHO",
    "MESSAGE_QUICKCHAT_PRIVATE",
    "MESSAGE_QUICKCHAT_FRIENDCHAT",
    "MESSAGE_QUICKCHAT_CLANCHANNEL",
    "MESSAGE_PLAYER_GROUP",
    "MESSAGE_QUICKCHAT_PLAYER_GROUP",

    # /* Clans */
    "CLANSETTINGS_FULL",
    "CLANSETTINGS_DELTA",
    "CLANCHANNEL_FULL",
    "CLANCHANNEL_DELTA",

    # /* ClientState */
    "LOGOUT",
    "LOGOUT_FULL",
    "LOGOUT_TRANSFER",
    "REBUILD_REGION",
    "REBUILD_NORMAL",
    "SET_MOVEACTION",
    "SET_MAP_FLAG",
    "RUNCLIENTSCRIPT",
    "UPDATE_REBOOT_TIMER",
    "JCOINS_UPDATE",
    "LOYALTY_UPDATE",

    # /* Debug */
    "DEBUG_SERVER_TRIGGERS",
    "CONSOLE_FEEDBACK",

    # /* Environment */
    "ENVIRONMENT_OVERRIDE",
    "POINTLIGHT_COLOUR",
    "_UNKNOWN1_",

    # /* Friend Chat */
    "UPDATE_FRIENDCHAT_CHANNEL_FULL",
    "UPDATE_FRIENDCHAT_CHANNEL_SINGLEUSER",

    # /* Friends */
    "UPDATE_FRIENDLIST",
    "FRIENDLIST_LOADED",
    "CHAT_FILTER_SETTINGS_PRIVATECHAT",

    # /* Hint */
    "HINT_ARROW",
    "HINT_TRAIL",

    # /* Ignores */
    "UPDATE_IGNORELIST",

    # /* Interfaces */
    "IF_SETPOSITION",
    "IF_SETSCROLLPOS",
    "IF_OPENTOP",
    "IF_OPENSUB",
    "IF_OPENSUB_ACTIVE_PLAYER",
    "IF_OPENSUB_ACTIVE_NPC",
    "IF_OPENSUB_ACTIVE_LOC",
    "IF_OPENSUB_ACTIVE_OBJ",
    "IF_CLOSESUB",
    "IF_MOVESUB",
    "IF_SETEVENTS",
    "IF_SETTARGETPARAM",
    "IF_SETTEXT",
    "IF_SETHIDE",
    "IF_SETGRAPHIC",
    "IF_SET_HTTP_IMAGE",
    "IF_SETPLAYERMODEL_OTHER",
    "IF_SETPLAYERMODEL_SELF",
    "IF_SETPLAYERMODEL_SNAPSHOT",
    "IF_SETMODEL",
    "IF_SETANIM",
    "IF_SETNPCHEAD",
    "IF_SETPLAYERHEAD",
    "IF_SETPLAYERHEAD_OTHER",
    "IF_SETPLAYERHEAD_IGNOREWORN",
    "IF_SETOBJECT",
    "IF_SETTEXTFONT",
    "IF_SETCOLOUR",
    "IF_SETRECOL",
    "IF_SETRETEX",
    "IF_SETCLICKMASK",
    "IF_SETTEXTANTIMACRO",
    "TRIGGER_ONDIALOGABORT",
    "IF_SETANGLE",

    # /* Inventories */
    "UPDATE_INV_PARTIAL",
    "UPDATE_INV_FULL",
    "UPDATE_INV_STOP_TRANSMIT",
    "UPDATE_STOCKMARKET_SLOT",

    # /* Lobby */
    "NO_TIMEOUT",
    "CREATE_CHECK_EMAIL_REPLY",
    "CREATE_ACCOUNT_REPLY",
    "CREATE_CHECK_NAME_REPLY",
    "CREATE_SUGGEST_NAME_ERROR",
    "CREATE_SUGGEST_NAME_REPLY",
    "LOBBY_APPEARANCE",
    "CHANGE_LOBBY",

    # /* Misc */
    "SEND_PING",
    "MINIMAP_TOGGLE",
    "SHOW_FACE_HERE",
    "EXECUTE_CLIENT_CHEAT",
    "DO_CHEAT",
    "SETDRAWORDER",
    "JS5_RELOAD",
    "WORLDLIST_FETCH_REPLY",

    # /* NPC Info */
    "NPC_INFO",
    "NPC_HEADICON_SPECIFIC",

    # /* Player Groups */
    "PLAYER_GROUP_FULL",
    "PLAYER_GROUP_DELTA",
    "PLAYER_GROUP_VARPS",

    # /* Player Info */
    "LAST_LOGIN_INFO",
    "PLAYER_INFO",
    "SET_PLAYER_OP",
    "UPDATE_RUNENERGY",
    "UPDATE_RUNWEIGHT",
    "UPDATE_UID192",
    "SET_TARGET",
    "REDUCE_PLAYER_ATTACK_PRIORITY",
    "REDUCE_NPC_ATTACK_PRIORITY",
    "PLAYER_SNAPSHOT",
    "CLEAR_PLAYER_SNAPSHOT",
    "UPDATE_DOB",

    # /* Server Reply */
    "SERVER_REPLY",

    # /* Telemetry */
    "TELEMETRY_GRID_FULL",
    "TELEMETRY_GRID_VALUES_DELTA",
    "TELEMETRY_GRID_ADD_GROUP",
    "TELEMETRY_GRID_REMOVE_GROUP",
    "TELEMETRY_GRID_ADD_ROW",
    "TELEMETRY_GRID_REMOVE_ROW",
    "TELEMETRY_GRID_SET_ROW_PINNED",
    "TELEMETRY_GRID_MOVE_ROW",
    "TELEMETRY_GRID_ADD_COLUMN",
    "TELEMETRY_GRID_REMOVE_COLUMN",
    "TELEMETRY_GRID_MOVE_COLUMN",
    "TELEMETRY_CLEAR_GRID_VALUE",

    # /* Variables */
    "RESET_CLIENT_VARCACHE",
    "VARP_SMALL",
    "VARP_LARGE",
    "VARBIT_SMALL",
    "VARBIT_LARGE",
    "CLIENT_SETVARC_SMALL",
    "CLIENT_SETVARC_LARGE",
    "CLIENT_SETVARCBIT_SMALL",
    "CLIENT_SETVARCBIT_LARGE",
    "CLIENT_SETVARCSTR_SMALL",
    "CLIENT_SETVARCSTR_LARGE",
    "STORE_SERVERPERM_VARCS_ACK",
    "VARCLAN_DISABLE",
    "VARCLAN_ENABLE",
    "VARCLAN",
    "UPDATE_STAT",

    # /* Web Page */
    "UPDATE_SITESETTINGS",
    "URL_OPEN",
    "SOCIAL_NETWORK_LOGOUT",

    # /* Zone Updates */
    "UPDATE_ZONE_PARTIAL_FOLLOWS",
    "UPDATE_ZONE_FULL_FOLLOWS",
    "UPDATE_ZONE_PARTIAL_ENCLOSED",
    "LOC_ADD_CHANGE",
    "LOC_CUSTOMISE",
    "LOC_DEL",
    "LOC_ANIM",
    "MAP_PROJANIM",
    "MAP_PROJANIM_HALFSQ",
    "MAP_ANIM",
    "OBJ_ADD",
    "OBJ_DEL",
    "OBJ_REVEAL",
    "OBJ_COUNT",
    "SOUND_AREA",
    "____WAT____",
    "LOC_PREFETCH",
    "TEXT_COORD"
]