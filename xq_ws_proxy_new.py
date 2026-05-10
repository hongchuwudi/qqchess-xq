"""
QQ象棋 WebSocket 拦截脚本 (mitmproxy addon) — 完整版 v2
=====================================================
JCE 解析 → 密钥派生 → TEA-CBC 解密 → 走子提取

启动: mitmdump --listen-port 8888 -s xq_ws_proxy.py
"""

import sys
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

import json
import struct
import re
import os
import base64
from datetime import datetime

from mitmproxy import ctx

# Generated imports — functions moved to xq_modules/
from xq_modules.tea_crypto import tea_zjb_decrypt, derive_session_key
from xq_modules.jce_parser import JceIn
from xq_modules.protocol import parse_pkg, parse_login, parse_game_event, parse_request_play, parse_game_context
from xq_modules.move_utils import unwrap_ws, _raw_move, extract_fen, find_moves_in_vec
from xq_modules.coord_conv import game_to_fen, detect_format
