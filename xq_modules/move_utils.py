"""Move extraction from binary vecMsgBody + WS frame unwrap."""

import re

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
    # SEND: 01 10 cf + 2 session bytes → skip 2+5=7 bytes
    if raw[2:5] == SEND_PREFIX:
        return 'SEND', raw[7:]
    # RECV: 0c + 2 session bytes → skip 2+3=5 bytes
    if raw[2] == 0x0c:
        return 'RECV', raw[5:]
    return None, b''


# ============================================================
# 走子检测
# ============================================================

def _raw_move(body, offset):
    """Read 4 bytes at offset as 1-indexed coords → UCI, or None."""
    if offset + 4 > len(body):
        return None
    fc, fr, tc, tr = body[offset], body[offset + 1], body[offset + 2], body[offset + 3]
    if not (1 <= fc <= 9 and 1 <= fr <= 10 and 1 <= tc <= 9 and 1 <= tr <= 10):
        return None
    if fc == tc and fr == tr:
        return None
    cols = 'abcdefghi'
    uci = f"{cols[fc - 1]}{fr - 1}{cols[tc - 1]}{tr - 1}"
    return {'offset': offset, 'from': [fc - 1, fr - 1], 'to': [tc - 1, tr - 1], 'uci': uci}


def extract_fen(data):
    """Try to extract a Chinese chess FEN string from binary data.

    FEN pattern: 10 rows of [rnbakcpRNBAKCP1-9] separated by /, plus side [wb].
    """
    pattern = (
        rb'([rnbakcpRNBAKCP1-9]{1,20}/'
        rb'[rnbakcpRNBAKCP1-9]{1,20}/'
        rb'[rnbakcpRNBAKCP1-9]{1,20}/'
        rb'[rnbakcpRNBAKCP1-9]{1,20}/'
        rb'[rnbakcpRNBAKCP1-9]{1,20}/'
        rb'[rnbakcpRNBAKCP1-9]{1,20}/'
        rb'[rnbakcpRNBAKCP1-9]{1,20}/'
        rb'[rnbakcpRNBAKCP1-9]{1,20}/'
        rb'[rnbakcpRNBAKCP1-9]{1,20}/'
        rb'[rnbakcpRNBAKCP1-9]{1,20}\s+[wb])'
    )
    m = re.search(pattern, data)
    if m:
        return m.group(1).decode('ascii')
    return None


def find_moves_in_vec(body):
    """Extract move coords from vecMsgBody.

    SEND (86004 cmdID=17, 16B): coords at [12] (marker at [11] varies:
      0xff = non-capture, other = capture/check).
    RECV (86005 eventID=49, 292B): marker 0x5f at [8], coords at [10].
    """
    if len(body) < 13:
        return []

    # SEND: offset 12 — try regardless of marker; _raw_move validates coords strictly
    if len(body) >= 16:
        m = _raw_move(body, 12)
        if m:
            m['ctx_before'] = body[8:12].hex()
            m['ctx_after'] = body[16:20].hex() if len(body) >= 20 else ''
            m['tag_score'] = 100
            return [m]

    # RECV: offset 10, marker 0x5f at 8 (both echo 0x00 and real 0x08)
    if len(body) >= 14 and body[8] == 0x5f:
        m = _raw_move(body, 10)
        if m:
            m['ctx_before'] = body[6:10].hex()
            m['ctx_after'] = body[14:18].hex() if len(body) >= 18 else ''
            m['tag_score'] = 50
            return [m]

    return []

