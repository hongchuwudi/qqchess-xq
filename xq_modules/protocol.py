"""QQ Chess protocol message parsers."""

import struct
import re
from .jce_parser import JceIn

# ============================================================
# 协议结构
# ============================================================

def parse_pkg(data):
    """
    TPackage:
      iClientVer(0), iOpenPlatType(1), iOSType(2), uUin(3),
      sOpenID(4), iZoneID(5), iGameID(6), iSequence(7),
      iFlag(8), stMsg(9), iRoomID(10), sSig(11),
      sChannelID(12), sClientVersion(13), iClientType(14)
    """
    j = JceIn(data)
    pkg = {
        'iClientVer': j.read_int32(0),
        'iOpenPlatType': j.read_int32(1),
        'iOSType': j.read_int32(2),
        'uUin': j.read_uint32(3),
        'sOpenID': j.read_string(4),
        'iZoneID': j.read_int32(5),
        'iGameID': j.read_int32(6),
        'iSequence': j.read_int32(7),
        'iFlag': j.read_int32(8),
    }
    # stMsg (tag 9)
    if j.read_struct_begin(9):
        pkg['stMsg'] = _parse_tmsg(j)
        j.read_struct_end()
    else:
        pkg['stMsg'] = None
    pkg['iRoomID'] = j.read_int32(10)
    pkg['sSig'] = j.read_string(11)
    pkg['sChannelID'] = j.read_string(12)
    pkg['sClientVersion'] = j.read_string(13)
    pkg['iClientType'] = j.read_int32(14)
    return pkg


def _parse_tmsg(j):
    """TMsg: stMsgHead(0), vecMsgBody(1)"""
    head = None
    body = b''
    if j.read_struct_begin(0):
        head = {
            'iMsgType': j.read_int32(0),
            'iMsgID': j.read_int32(1),
            'iResult': j.read_int32(2),
            'ts': j.read_int64(3),
        }
        j.read_struct_end()
    body = j.read_bytes(1)
    return {'head': head, 'body': body}


def _scan_ssec_in_body(body, target_fields=(10, 11)):
    """Brute-force scan for sSecKey at target fields. Returns hex string or ''."""
    best = ''
    for i in range(len(body) - 2):
        b = body[i]
        field_id = b >> 4
        jce_type = b & 0xf
        if field_id == 15:
            if i + 1 >= len(body):
                continue
            field_id = body[i + 1]
        if field_id not in target_fields or jce_type not in (6, 7):
            continue
        try:
            offset = i + 1 + (1 if (b >> 4) == 15 else 0)
            if jce_type == 6:
                slen = body[offset]
                if offset + 1 + slen > len(body): continue
                val = body[offset + 1:offset + 1 + slen]
            else:
                slen = struct.unpack('>I', body[offset:offset + 4])[0]
                if slen < 16 or slen > 1000 or offset + 4 + slen > len(body): continue
                val = body[offset + 4:offset + 4 + slen]
            if slen >= 16:
                try:
                    text = val.decode('ascii')
                    if all(c in '0123456789abcdefABCDEF' for c in text):
                        best = text
                    else:
                        best = val.hex()
                except Exception:
                    best = val.hex()
        except Exception:
            continue
    return best


def parse_login(body):
    """
    TResponseLogin — supports both QQ and WeChat variants.

    QQ variant:       sSecKey at field 10, uUin at field 1
    WeChat variant:   sSecKey at field 11, sWXGameSessionKey at field 15

    Uses raw-body scan first (avoids JCE reader position corruption
    when a field has unexpected type), then JCE reader for uUin only.
    """
    # Raw scan first — safe, doesn't corrupt reader state
    ssec = _scan_ssec_in_body(body, (10, 11))
    wx_key = _scan_ssec_in_body(body, (15,))

    # JCE reader for structured fields (only after scan)
    j = JceIn(body)
    uin = j.read_uint32(1)

    return {
        'iResultID': j.read_int32(0),
        'uUin': uin,
        'sSecKey': ssec,
        'sWXGameSessionKey': wx_key,
    }


def parse_game_event(body):
    """
    TGameEvent (QQChessPlayProto):
      nEventID(0), nRoomID(1), nTableID(2), nSeatID(3), vecMsgBody(4)
    """
    j = JceIn(body)
    return {
        'nEventID': j.read_int16(0),
        'nRoomID': j.read_int16(1),
        'nTableID': j.read_int16(2),
        'nSeatID': j.read_int16(3, 0),
        'vecMsgBody': j.read_bytes(4),
    }


def parse_request_play(body):
    """
    TRequestPlay (QQChessPlayProto):
      nCmdID(0), nRoomID(1), nTableID(2), nSeatID(3), vecMsgBody(4)
    """
    j = JceIn(body)
    return {
        'nCmdID': j.read_int16(0),
        'nRoomID': j.read_int16(1),
        'nTableID': j.read_int16(2),
        'nSeatID': j.read_int16(3, 0),
        'vecMsgBody': j.read_bytes(4),
    }


def parse_game_context(body):
    """
    Qca / TGameInfo (QQChessPlayProto) — 86001 game context:
      qm(0), hxb(1), iFirstSide(2), tF(3), VX(4), UX(5),
      Am(6), WB(7), eA(8), Pwb(9), Qwb(10), iwb(11),
      jwb(12), ewb(13), fwb(14), XXa(15), wba(16), vba(17),
      vFc(18), qYa(19), qBc(20), pBc(21), bFinishCompeteRed(22), b1c(23)

    iFirstSide = seat ID of red side (first mover).
    Client JS confirms: this.I$ = xa.iFirstSide;
                        this.zl = this.I$ === this.mySeat;  // true=player is red
    """
    j = JceIn(body)
    result = {
        'iFirstSide': j.read_int32(2, -1),
        'qm': j.read_int32(0, -1),
        'hxb': j.read_int32(1, -1),
    }
    # Also try to extract board pos from Am (tag 6): struct CY
    # CY: Gbb(0), R3(1), S3(2), T3(3), W3(4), $5b(5), a6b(6), qm(7),
    #     swb(8), wxb(9), iFlag(10)
    if j.read_struct_begin(6):
        # Just extract key position fields
        result['board_R3'] = j.read_int32(1, -1)
        result['board_S3'] = j.read_int32(2, -1)
        result['board_T3'] = j.read_int32(3, -1)
        result['board_W3'] = j.read_int32(4, -1)
        j.read_struct_end()
    return result


# ============================================================
# WS 帧解析
# ============================================================

SEND_PREFIX = b'\x01\x10\xcf'   # 3 fixed bytes, then 2 session bytes
RECV_PREFIX = b'\x0c'          # 1 fixed byte,  then 2 session bytes


def unwrap_ws(raw):
    """剥离 WebSocket 帧外层, 返回 (direction, jce_bytes)

    帧格式: [2B big-endian length][magic][route+JCE body]
    SEND magic = 01 10 cf XX YY (5B, XX YY = session-specific)
    RECV magic = 0c XX YY        (3B, XX YY = session-specific)
    QQ和微信登录的 session bytes 不同, 不能硬编码。
    """
    if len(raw) < 7:
        return None, b''
    if raw[2:5] == SEND_PREFIX:
        return 'SEND', raw[7:]
    if raw[2] == 0x0c:
        return 'RECV', raw[5:]
    return None, b''
