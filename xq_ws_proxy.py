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

# ============================================================
# TEA 算法 — 严格对应 JS 模块 294 TEAUtils
# 字节序: 大端 (i4a/yJb)
# 轮函数: 标准 TEA (非 XXTEA)
# CBC: zJb/Aad 带 Wjb/dkb 填充
# ============================================================

DELTA = 0x9E3779B9
ROUNDS = 16       # cdd
WJB = 2           # 头部随机填充字节数
DKB = 7           # 尾部零填充字节数
QDE = 4           # shift amount for initial sum in decrypt


def _read_u32_be(data, offset):
    """i4a: 大端读 uint32"""
    return (data[offset] << 24 | data[offset + 1] << 16 |
            data[offset + 2] << 8 | data[offset + 3])


def _write_u32_be(data, offset, value):
    """yJb: 大端写 uint32"""
    value &= 0xFFFFFFFF
    data[offset] = value >> 24
    data[offset + 1] = (value >> 16) & 0xFF
    data[offset + 2] = (value >> 8) & 0xFF
    data[offset + 3] = value & 0xFF


def _key_to_u32s(key_bytes):
    """读取 16 字节密钥为 4 个 uint32 (大端, 对应 JS oa[0..3])"""
    return [_read_u32_be(key_bytes, i * 4) for i in range(4)]


def tea_encrypt_block(v0, v1, k):
    """Iec: 标准 TEA 加密一个 8 字节块 (大端)"""
    total = 0
    for _ in range(ROUNDS):
        total = (total + DELTA) & 0xFFFFFFFF
        # v0 += ((v1<<4)+k0 ^ v1+total ^ (v1>>5)+k1)
        v0 = (v0 + (((((v1 << 4) & 0xFFFFFFFF) + k[0]) & 0xFFFFFFFF ^
                      (v1 + total) & 0xFFFFFFFF ^
                      (((v1 >> 5) & 0xFFFFFFFF) + k[1]) & 0xFFFFFFFF))) & 0xFFFFFFFF
        # v1 += ((v0<<4)+k2 ^ v0+total ^ (v0>>5)+k3)
        v1 = (v1 + (((((v0 << 4) & 0xFFFFFFFF) + k[2]) & 0xFFFFFFFF ^
                      (v0 + total) & 0xFFFFFFFF ^
                      (((v0 >> 5) & 0xFFFFFFFF) + k[3]) & 0xFFFFFFFF))) & 0xFFFFFFFF
    return v0, v1


def tea_decrypt_block(v0, v1, k):
    """qKb: 标准 TEA 解密一个 8 字节块 (大端)"""
    total = (DELTA << QDE) & 0xFFFFFFFF  # delta * 16
    for _ in range(ROUNDS):
        # v1 -= ((v0<<4)+k2 ^ v0+total ^ (v0>>5)+k3)
        v1 = (v1 - (((((v0 << 4) & 0xFFFFFFFF) + k[2]) & 0xFFFFFFFF ^
                      (v0 + total) & 0xFFFFFFFF ^
                      (((v0 >> 5) & 0xFFFFFFFF) + k[3]) & 0xFFFFFFFF))) & 0xFFFFFFFF
        # v0 -= ((v1<<4)+k0 ^ v1+total ^ (v1>>5)+k1)
        v0 = (v0 - (((((v1 << 4) & 0xFFFFFFFF) + k[0]) & 0xFFFFFFFF ^
                      (v1 + total) & 0xFFFFFFFF ^
                      (((v1 >> 5) & 0xFFFFFFFF) + k[1]) & 0xFFFFFFFF))) & 0xFFFFFFFF
        total = (total - DELTA) & 0xFFFFFFFF
    return v0, v1


def _decrypt_block_bytes(block, key_u32s):
    """解密一个 8 字节块, 返回 8 字节 (大端)"""
    v0 = _read_u32_be(block, 0)
    v1 = _read_u32_be(block, 4)
    d0, d1 = tea_decrypt_block(v0, v1, key_u32s)
    out = bytearray(8)
    _write_u32_be(out, 0, d0)
    _write_u32_be(out, 4, d1)
    return bytes(out)


def _encrypt_block_bytes(block, key_u32s):
    """加密一个 8 字节块, 返回 8 字节 (大端)"""
    v0 = _read_u32_be(block, 0)
    v1 = _read_u32_be(block, 4)
    e0, e1 = tea_encrypt_block(v0, v1, key_u32s)
    out = bytearray(8)
    _write_u32_be(out, 0, e0)
    _write_u32_be(out, 4, e1)
    return bytes(out)


def tea_zjb_decrypt(ciphertext, key):
    """zJb: TEA-CBC 解密, 带 Wjb/dkb 填充处理

    对应 JS TEAUtils.zJb().
    解密公式: P[i] = D(C[i] ⊕ P[i-1], key) ⊕ C[i-1], C[-1]=P[-1]=0

    ciphertext 结构:
      [block_0 (8B): 解密后首字节低3位=随机头长度ra]
      [Wjb=2 字节头部随机填充]
      [payload]
      [dkb=7 字节尾部零填充]
      总开销 = 1 + ra + 2 + 7 = 10+ra 字节, 再补齐到 8 字节边界
    """
    data = ciphertext
    ct_len = len(data)
    if ct_len % 8 != 0 or ct_len < 16:
        return None

    k = _key_to_u32s(key)

    # 解密第一个块获取头部信息
    block0 = _decrypt_block_bytes(data[0:8], k)
    pad_len = block0[0] & 7
    payload_len = ct_len - 1 - pad_len - WJB - DKB
    if payload_len < 0:
        return None

    out = bytearray()

    # la: 当前解密块寄存器 (对应 JS la)
    cur_dec = bytearray(block0)
    # ia: 前一个密文块 (CBC feedback), IV=0
    prev_ct = bytearray(8)

    ct_pos = 8           # 密文读取位置 (已消费第一个块)
    blk_pos = 1 + pad_len  # 当前块内字节位置 (跳过头部)

    def _load_next():
        nonlocal ct_pos, blk_pos, prev_ct
        # 保存当前密文块作为 "前一个密文" 用于输出 XOR
        prev_ct = data[ct_pos - 8:ct_pos]
        # XOR la 与新密文块, 然后解密
        for i in range(8):
            if ct_pos + i >= ct_len:
                return False
            cur_dec[i] ^= data[ct_pos + i]
        dec = _decrypt_block_bytes(bytes(cur_dec), k)
        cur_dec[:] = dec
        ct_pos += 8
        blk_pos = 0
        return True

    # --- 跳过 WJB 字节头部填充 ---
    skip_cnt = 0
    while skip_cnt < WJB:
        if blk_pos < 8:
            blk_pos += 1
            skip_cnt += 1
        if blk_pos == 8 and skip_cnt < WJB:
            if not _load_next():
                return None

    # --- 解密 payload ---
    out_cnt = 0
    while out_cnt < payload_len:
        if blk_pos < 8:
            out.append(cur_dec[blk_pos] ^ prev_ct[blk_pos])
            blk_pos += 1
            out_cnt += 1
        if blk_pos == 8 and out_cnt < payload_len:
            if not _load_next():
                return None

    # --- 跳过 DKB 字节尾部填充 (验证为零) ---
    dkb_cnt = 0
    while dkb_cnt < DKB:
        if blk_pos < 8:
            if cur_dec[blk_pos] ^ prev_ct[blk_pos]:
                return None  # 尾部填充必须为零
            blk_pos += 1
            dkb_cnt += 1
        if blk_pos == 8 and dkb_cnt < DKB:
            if not _load_next():
                return None

    return bytes(out)


def tea_aad_encrypt(plaintext, key):
    """Aad: TEA-CBC 加密, 带 Wjb/dkb 填充

    对应 JS TEAUtils.Aad().
    加密公式: C[i] = E(P[i] ⊕ C[i-1], key) ⊕ P[i-1], C[-1]=P[-1]=0
    """
    import random as _random
    k = _key_to_u32s(key)
    pt_len = len(plaintext)

    pad = (8 - (pt_len + 1 + WJB + DKB) % 8) % 8
    total = pt_len + 1 + WJB + DKB + pad

    out = bytearray(total)
    out_pos = 0

    cur = bytearray(8)       # current plaintext block (sa in JS)
    cur_pos = 0
    prev_pt = bytearray(8)   # previous plaintext (ra in JS), IV=0
    prev_ct_ref = prev_pt    # reference for CBC XOR (ua in JS), initially prev_pt
    prev_ct_off = 0          # ja in JS

    def _flush():
        nonlocal out_pos, cur_pos, prev_ct_ref, prev_ct_off
        # XOR plaintext with previous ciphertext feedback
        for i in range(8):
            cur[i] ^= prev_ct_ref[prev_ct_off + i]
        # Encrypt to output
        enc = _encrypt_block_bytes(bytes(cur), k)
        # XOR output with previous plaintext
        for i in range(8):
            out[out_pos + i] = enc[i] ^ prev_pt[i]
        # Save this plaintext as "previous" for next round
        prev_pt[:] = cur
        prev_ct_off = out_pos
        prev_ct_ref = out
        out_pos += 8
        cur_pos = 0

    # First byte: random high 5 bits | pad length in low 3 bits
    cur[0] = (_random.randint(0, 255) & 0xF8) | (pad & 0xFF)
    cur_pos = 1
    for _ in range(pad):
        cur[cur_pos] = _random.randint(0, 255) & 0xFF
        cur_pos += 1

    # Wjb header bytes (random)
    wjb_cnt = 0
    while wjb_cnt < WJB:
        if cur_pos < 8:
            cur[cur_pos] = _random.randint(0, 255) & 0xFF
            cur_pos += 1
            wjb_cnt += 1
        if cur_pos == 8:
            _flush()

    # Payload
    pt_pos = 0
    while pt_pos < pt_len:
        if cur_pos < 8:
            cur[cur_pos] = plaintext[pt_pos]
            cur_pos += 1
            pt_pos += 1
        if cur_pos == 8:
            _flush()

    # Dkb tail bytes (zero)
    dkb_cnt = 0
    while dkb_cnt < DKB:
        if cur_pos < 8:
            cur[cur_pos] = 0
            cur_pos += 1
            dkb_cnt += 1
        if cur_pos == 8:
            _flush()

    return bytes(out)


def derive_session_key(ssec_hex, uin):
    """派生会话密钥 — 对应 JS 85001 handler:
    key = pad16(str(uin)), sSecKey_bytes = K4a(sSecKey) → zJb 解密
    """
    tk = str(uin).encode('latin-1').ljust(16, b'\x00')
    ssec_bytes = bytes.fromhex(ssec_hex)
    sk = tea_zjb_decrypt(ssec_bytes, tk)
    if sk:
        return sk[:16]
    return None


# ============================================================
# JCE 解析器 (精简, 仅处理本协议需要的类型)
# ============================================================

class JceIn:
    """JCE 输入流 — 按 tag 升序读取字段"""

    def __init__(self, data, pos=0):
        self.d = data
        self.p = pos

    # ---- 底层 ----

    def _peek(self):
        """peek 下一字段的(tag, type), 不移动指针"""
        if self.p >= len(self.d):
            return None, None
        b = self.d[self.p]
        tag, typ = b >> 4, b & 0xf
        if tag == 15:
            if self.p + 1 >= len(self.d):
                return None, None
            tag = self.d[self.p + 1]
            return tag, typ
        return tag, typ

    def _read_head(self):
        """读取字段头 (tag, type), 移动指针"""
        tag, typ = self._peek()
        self.p += 1
        if tag is not None and (self.d[self.p - 1] >> 4) == 15:
            self.p += 1  # skip extended tag byte
        return tag, typ

    def _skip_val(self, typ):
        if typ == 0:   self.p += 1       # INT8
        elif typ == 1: self.p += 2       # INT16
        elif typ == 2: self.p += 4       # INT32
        elif typ == 3: self.p += 8       # INT64
        elif typ == 4: self.p += 4       # FLOAT
        elif typ == 5: self.p += 8       # DOUBLE
        elif typ == 6:                   # STR1
            self.p += 1 + self.d[self.p]
        elif typ == 7:                   # STR4
            n = struct.unpack('>I', self.d[self.p:self.p + 4])[0]
            self.p += 4 + n
        elif typ == 8:                   # MAP
            self.p += 1  # count=0 (we only handle empty maps)
        elif typ == 9:                   # LIST
            self.p += 1  # count=0
        elif typ == 10:                  # STRUCT_BEGIN → skip nested
            self._skip_struct()
        elif typ == 12: pass             # ZERO
        elif typ == 13:                  # BYTES
            self._read_head()            # inner tag=0 type=INT8
            n = self._read_int_len()     # variable-length int
            self.p += n
        # typ 11 (STRUCT_END) handled by caller

    def _skip_struct(self):
        """跳过整个结构体直到 STRUCT_END (嵌套安全)"""
        depth = 1
        while self.p < len(self.d) and depth > 0:
            tag, typ = self._read_head()
            if typ == 10:
                depth += 1
            elif typ == 11:
                depth -= 1
            else:
                self._skip_val(typ)

    def _skip_to(self, want_tag):
        """跳过 tag < want_tag 的字段, 返回是否找到 want_tag"""
        while self.p < len(self.d):
            tag, typ = self._peek()
            if typ == 11:        # STRUCT_END
                return False
            if tag >= want_tag:
                return tag == want_tag
            self._read_head()
            self._skip_val(typ)
        return False

    # ---- 读取变长整数 (用于 BYTES 内部长度) ----
    def _read_int_len(self):
        """读取 JCE 变长整数 (0/1/2/3 类型)"""
        tag, typ = self._read_head()
        if typ == 12: return 0        # ZERO
        if typ == 0:                  # INT8
            v = self.d[self.p]
            self.p += 1
            return v
        if typ == 1:                  # INT16
            v = struct.unpack('>h', self.d[self.p:self.p + 2])[0]
            self.p += 2
            return v
        if typ == 2:                  # INT32
            v = struct.unpack('>i', self.d[self.p:self.p + 4])[0]
            self.p += 4
            return v
        return 0

    # ---- 公开读取 API ----

    def read_int32(self, tag, default=0):
        if not self._skip_to(tag):
            return default
        _, typ = self._read_head()
        if typ == 12: return 0
        if typ == 0:
            v = struct.unpack('b', self.d[self.p:self.p + 1])[0]
            self.p += 1
            return v
        if typ == 1:
            v = struct.unpack('>h', self.d[self.p:self.p + 2])[0]
            self.p += 2
            return v
        if typ == 2:
            v = struct.unpack('>i', self.d[self.p:self.p + 4])[0]
            self.p += 4
            return v
        return default

    def read_uint32(self, tag, default=0):
        """UInt32 — 注意大值会用 INT64 编码"""
        if not self._skip_to(tag):
            return default
        _, typ = self._read_head()
        if typ == 12: return 0
        if typ == 0:
            v = self.d[self.p]; self.p += 1; return v
        if typ == 1:
            v = struct.unpack('>H', self.d[self.p:self.p + 2])[0]
            self.p += 2; return v
        if typ == 2:
            v = struct.unpack('>I', self.d[self.p:self.p + 4])[0]
            self.p += 4; return v
        if typ == 3:  # INT64 for large uUin
            lo = struct.unpack('>I', self.d[self.p + 4:self.p + 8])[0]
            self.p += 8; return lo
        return default

    def read_int64(self, tag, default=0):
        if not self._skip_to(tag):
            return default
        _, typ = self._read_head()
        if typ == 12: return 0
        if typ in (0, 1, 2):
            return self.read_int32(tag, default)  # reuse already consumed head? no.
        if typ == 3:
            hi = struct.unpack('>I', self.d[self.p:self.p + 4])[0]
            lo = struct.unpack('>I', self.d[self.p + 4:self.p + 8])[0]
            self.p += 8
            return (hi << 32) | lo
        return default

    def read_int16(self, tag, default=0):
        if not self._skip_to(tag):
            return default
        _, typ = self._read_head()
        if typ == 12: return 0
        if typ == 0:
            v = struct.unpack('b', self.d[self.p:self.p + 1])[0]
            self.p += 1; return v
        if typ == 1:
            v = struct.unpack('>h', self.d[self.p:self.p + 2])[0]
            self.p += 2; return v
        return default

    def read_string(self, tag, default=''):
        if not self._skip_to(tag):
            return default
        _, typ = self._read_head()
        if typ == 6:
            n = self.d[self.p]; self.p += 1
            v = self.d[self.p:self.p + n].decode('utf-8', errors='replace')
            self.p += n; return v
        if typ == 7:
            n = struct.unpack('>I', self.d[self.p:self.p + 4])[0]
            self.p += 4
            if n > 100000: return default
            v = self.d[self.p:self.p + n].decode('utf-8', errors='replace')
            self.p += n; return v
        return default

    def read_bytes(self, tag, default=b''):
        if not self._skip_to(tag):
            return default
        self._read_head()           # outer: tag, type=13
        self._read_head()           # inner: tag=0, type=INT8
        n = self._read_int_len()    # variable-length int
        if n < 0 or n > 10 * 1024 * 1024:
            return default
        v = self.d[self.p:self.p + n]
        self.p += n
        return v

    def read_struct_begin(self, tag):
        """读取 STRUCT_BEGIN, 返回 True 如果找到"""
        if not self._skip_to(tag):
            return False
        tag2, typ = self._read_head()
        return typ == 10

    def read_struct_end(self):
        """跳过剩余字段直到 STRUCT_END (嵌套安全版本)"""
        depth = 1
        while self.p < len(self.d) and depth > 0:
            tag, typ = self._read_head()
            if typ == 10:   # STRUCT_BEGIN
                depth += 1
            elif typ == 11: # STRUCT_END
                depth -= 1
            else:
                self._skip_val(typ)


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


def parse_login(body):
    """
    TResponseLogin (QQChessZoneProto):
      0: iResultID, 1: uUin, ..., 4: tPlayerInfo, ...
      10: sSecKey, 11: banEndTime, 12: bShowButton, ...
    """
    j = JceIn(body)
    uin = j.read_uint32(1)
    ssec = j.read_string(10)
    if ssec:
        try:
            raw_val = ssec.encode('latin-1')
        except Exception:
            raw_val = b''
        if len(raw_val) >= 16:
            ssec = raw_val.hex()
        else:
            ssec = ''
    # Fallback: scan for field=10 STR1/STR4 after skipping tPlayerInfo
    # The struct at field 4 may contain its own field 10, so we take
    # the LAST occurrence (which is the top-level TResponseLogin field 10)
    if not ssec:
        last_val = None
        for i in range(len(body) - 2):
            b = body[i]
            field_id = b >> 4
            jce_type = b & 0xf
            if field_id == 15:
                if i + 1 >= len(body):
                    continue
                field_id = body[i + 1]
            if field_id != 10 or jce_type not in (6, 7):
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
                            last_val = text
                        else:
                            last_val = val.hex()
                    except Exception:
                        last_val = val.hex()
            except Exception:
                continue
        if last_val:
            ssec = last_val
    return {'iResultID': j.read_int32(0), 'uUin': uin, 'sSecKey': ssec}


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

SEND_MAGIC = b'\x01\x10\xcf\x10\x01'
RECV_MAGIC = b'\x0c\x10\x01'


def unwrap_ws(raw):
    """剥离 WebSocket 帧外层, 返回 (direction, jce_bytes)"""
    if len(raw) < 7:
        return None, b''
    if raw[2:7] == SEND_MAGIC:
        return 'SEND', raw[7:]
    if raw[2:5] == RECV_MAGIC:
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


# ============================================================
# mitmproxy 插件
# ============================================================

class QQChessWSProxy:

    def __init__(self):
        self.st = datetime.now()
        self.total = 0
        self.sends = 0
        self.recvs = 0
        self.raw = []
        self.decoded = []
        self.moves = []
        self.move_n = 0
        self.session_key = None
        self.uin = None
        self.my_seat = None       # nSeatID from our SEND 86004
        self.i_first_side = None  # which seat is red (from RECV 86001 context)
        self.my_camp = None       # 'red' or 'black'
        self.game_count = 0       # number of completed games
        self._game_active = False # whether a game is currently in progress
        self._game_start_seq = 0  # seq when current game started
        self._consecutive_86006 = 0  # count consecutive 86006 RECV for end detection

    def websocket_start(self, flow):
        if 'qqchess' not in flow.request.url:
            return
        flow.metadata['ok'] = True
        flow.metadata['ts'] = datetime.now().isoformat()
        ctx.log.info(f"[QQ象棋] 已连接 {flow.request.url}")

    def websocket_message(self, flow):
        if not flow.metadata.get('ok'):
            return
        if not flow.websocket.messages:
            return
        m = flow.websocket.messages[-1]
        self.total += 1
        direction = 'SEND' if m.from_client else 'RECV'
        if m.from_client:
            self.sends += 1
        else:
            self.recvs += 1
        raw = m.content if not m.is_text else m.text.encode()
        ts = datetime.now().isoformat()

        # 保存原始消息
        self.raw.append({
            'seq': self.total, 'time': ts, 'direction': direction,
            'size': len(raw), 'base64': base64.b64encode(raw).decode(),
        })

        # 剥离 WS 帧
        d, jce_data = unwrap_ws(raw)
        if not d:
            return

        # 解析 TPackage
        try:
            pkg = parse_pkg(jce_data)
        except Exception as e:
            ctx.log.warn(f"[JCE] TPackage 解析失败 seq={self.total}: {e}")
            return

        st = pkg.get('stMsg')
        head = st.get('head') if st else None
        body = st.get('body') if st else b''
        msg_id = head['iMsgID'] if head else 0
        i_flag = pkg.get('iFlag', 0)
        encrypted = bool(i_flag & 1)

        dir_sym = "↑" if direction == 'SEND' else "↓"
        enc_sym = "[E]" if encrypted else "[ ]"
        ctx.log.info(
            f"[{dir_sym}] #{self.total:04d} {len(raw):5d}B  "
            f"msgID={msg_id:5d} {enc_sym}  iFlag={i_flag}"
        )

        # ---- 登录响应 (85001) ----
        if msg_id == 85001 and not m.from_client:
            try:
                login = parse_login(body)
                ctx.log.info(
                    f"  [LOGIN] uUin={login['uUin']}  "
                    f"sSecKey={login['sSecKey'][:32] if login['sSecKey'] else '(none)'}..."
                )
                if login['sSecKey'] and login['uUin']:
                    self.session_key = derive_session_key(login['sSecKey'], login['uUin'])
                    self.uin = login['uUin']
                    ctx.log.info(f"  [KEY] session_key={self.session_key.hex()}")
            except Exception as e:
                ctx.log.error(f"  [LOGIN] 解析失败: {e}")

        # ---- 解密 ----
        plain = None
        if encrypted and self.session_key and body:
            try:
                plain = tea_zjb_decrypt(body, self.session_key)
            except Exception as e:
                ctx.log.error(f"  [DEC] 失败: {e}")

        # ---- 游戏上下文 (86001) — 仅日志参考 (body是TResponseSitDown, field2是tableID) ----
        check_body_ctx = plain if encrypted else body
        if msg_id == 86001 and not m.from_client and check_body_ctx:
            try:
                ctx2 = parse_game_context(check_body_ctx)
                ctx.log.info(
                    f"  [86001] tableID={ctx2.get('iFirstSide')}  "
                    f"qm={ctx2.get('qm')}  hxb={ctx2.get('hxb')}"
                )
                if not self._game_active:
                    self._on_game_begin(self.total)
            except Exception as e:
                ctx.log.warn(f"  [CTX] 解析失败: {e}")

        # ---- 游戏事件 (86004 走子, 86005/86011 服务器事件) ----
        check_body = plain if encrypted else body
        if msg_id in (86004, 86005, 86011) and check_body:
            try:
                if msg_id == 86004:
                    ev = parse_request_play(check_body)
                    # Game is active if we're sending moves
                    if not self._game_active:
                        self._on_game_begin(self.total)
                    # Track player's own seat from SEND messages
                    seat_id = ev.get('nSeatID', -1)
                    if seat_id >= 0 and self.my_seat is None:
                        self.my_seat = seat_id
                        ctx.log.info(f"  [SEAT] my_seat={self.my_seat}")
                    ctx.log.info(
                        f"  [SEND] cmdID={ev['nCmdID']}  "
                        f"room={ev['nRoomID']}  table={ev['nTableID']}  "
                        f"seat={seat_id}  "
                        f"vec={len(ev['vecMsgBody'])}B"
                    )
                    move_label = "MOVE SENT"
                else:
                    ev = parse_game_event(check_body)
                    ctx.log.info(
                        f"  [GAME] eventID={ev['nEventID']}  "
                        f"room={ev['nRoomID']}  table={ev['nTableID']}  "
                        f"seat={ev.get('nSeatID', '?')}  "
                        f"vec={len(ev['vecMsgBody'])}B"
                    )
                    move_label = "MOVE"
                    # eventID=63: full state sync (mid-game join) — extract FEN
                    if ev['nEventID'] == 63 and ev['vecMsgBody']:
                        fen = extract_fen(ev['vecMsgBody'])
                        if fen:
                            ctx.log.info(f"  [MIDGAME] fen={fen}")
                inner = ev['vecMsgBody']
                if inner:
                    candidates = find_moves_in_vec(inner)
                    scored = sorted(candidates, key=lambda x: -x['tag_score'])
                    for mv in scored[:5]:
                        ctx.log.info(
                            f"  [MOVE?] {mv['uci']}  {mv['from']}→{mv['to']}  "
                            f"off={mv['offset']}  score={mv['tag_score']}  "
                            f"ctx={mv['ctx_before']}|{mv['ctx_after']}"
                        )
                    if scored:
                        best = scored[0]
                        self.move_n += 1
                        event_id = ev.get('nEventID', ev.get('nCmdID', 0))
                        move_seat = ev.get('nSeatID', -1)
                        # Determine camp: Red always moves first in Chinese chess
                        if self.my_camp is None and self.move_n == 1:
                            self.my_camp = 'red' if direction == 'SEND' else 'black'
                            ctx.log.info(f"  [CAMP] first move is {direction} → {self.my_camp}")
                        if self.my_camp:
                            opp_camp = 'red' if self.my_camp == 'black' else 'black'
                            mover_camp = self.my_camp if direction == 'SEND' else opp_camp
                            is_own = (direction == 'SEND')
                        else:
                            mover_camp = None
                            is_own = None
                        rec = {
                            'num': self.move_n, 'seq': self.total,
                            'time': ts, 'direction': direction,
                            'msgID': msg_id, 'eventID': event_id,
                            'from': best['from'], 'to': best['to'],
                            'uci': best['uci'],
                            'offset': best['offset'],
                            'vec_hex': inner.hex(),
                            'seat': move_seat,
                            'camp': mover_camp,
                            'is_own': is_own,
                        }
                        self.moves.append(rec)
                        own_tag = ' (我方)' if is_own else ''
                        ctx.log.info(f"  >>> [{move_label} #{self.move_n}] {best['uci']}{own_tag} <<<")
            except Exception as e:
                ctx.log.warn(f"  [GAME] 解析失败: {e}")

        # ---- 对局结束检测 ----
        if not m.from_client and self._check_game_end(msg_id, direction, encrypted, len(body)):
            # Game ended — tag moves and reset
            pass

        # 保存解码记录
        dec_rec = {
            'seq': self.total, 'time': ts, 'direction': direction,
            'msgID': msg_id, 'iFlag': i_flag, 'encrypted': encrypted,
        }
        if plain:
            dec_rec['decrypted_size'] = len(plain)
            dec_rec['decrypted_hex'] = plain[:128].hex()
            ss = []
            for m in re.finditer(rb'[\x20-\x7e]{3,}', plain):
                try: ss.append(m.group().decode('ascii'))
                except: pass
            dec_rec['strings'] = ss[:20]
        self.decoded.append(dec_rec)

    def websocket_end(self, flow):
        if not flow.metadata.get('ok'):
            return
        ctx.log.info(f"[QQ象棋] 断开 总={self.total} SEND={self.sends} RECV={self.recvs} moves={len(self.moves)}")
        if self.moves:
            ctx.log.info(f"[QQ象棋] 走子: {' '.join(m['uci'] for m in self.moves)}")
        if self._game_active and self.move_n > 0:
            self._end_game('ws_disconnect')
        self._save()

    def done(self):
        self._save()

    # ---- 对局结束检测 ----
    def _on_game_begin(self, seq):
        """Mark the start of a new game."""
        self._game_active = True
        self._game_start_seq = seq
        self._consecutive_86006 = 0
        ctx.log.info(f"[GAME] ====== 对局 #{self.game_count + 1} 开始 (seq={seq}) ======")

    def _on_game_end(self, reason):
        """Handle game end: save state, reset trackers."""
        self.game_count += 1
        moves_in_game = sum(1 for m in self.moves if m.get('game_idx') == self.game_count - 1
                            if 'game_idx' in m) if self.game_count > 1 else self.move_n
        ctx.log.info(
            f"[GAME] ====== 对局 #{self.game_count} 结束 "
            f"(moves={self.move_n}, reason={reason}) ======"
        )
        # Reset per-game state
        self.move_n = 0
        self.my_seat = None
        self.i_first_side = None
        self.my_camp = None
        self._game_active = False
        self._consecutive_86006 = 0

    def _check_game_end(self, msg_id, direction, encrypted, body_size):
        """Detect game-end signals from server messages.

        Server sends two kinds of end signals:
          1. 86006 RECV × 2 — game room settle events (contain result data)
          2. 85075 RECV — data change notification, small (<200B) when game ends

        Pattern observed across all sessions:
          ...86005 RECV (last move) → 86006 RECV × 2 → 85075 RECV
        """
        if not self._game_active:
            return

        if msg_id == 86005 and direction == 'RECV' and not encrypted:
            # Track consecutive 86005 for potential game end
            pass

        if msg_id == 86006 and direction == 'RECV':
            self._consecutive_86006 += 1
            if self._consecutive_86006 >= 2 and self.move_n > 0:
                ctx.log.info(f"  [END] 检测到连续 86006 事件 (对局结算)")

        if msg_id == 85075 and direction == 'RECV' and not encrypted and body_size < 200:
            self._end_game('85075_end_notify')
            return True

        if msg_id not in (86005, 86006, 86004):
            # Non-battle message — reset consecutive counter
            self._consecutive_86006 = 0

        return False

    def _end_game(self, reason):
        """Trigger game end cleanup."""
        # Tag all moves in current game
        game_idx = self.game_count
        for m in self.moves:
            if 'game_idx' not in m:
                m['game_idx'] = game_idx
        self._on_game_end(reason)

    def _save(self):
        if not self.raw:
            return
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        out = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'sessions')
        os.makedirs(out, exist_ok=True)
        files = {
            f'qqchess_ws_raw_{ts}.json': self.raw,
            f'qqchess_ws_decoded_{ts}.json': self.decoded,
            f'qqchess_moves_{ts}.json': self.moves,
        }
        for fn, d in files.items():
            p = os.path.join(out, fn)
            with open(p, 'w', encoding='utf-8') as f:
                json.dump(d, f, ensure_ascii=False, indent=2)
            ctx.log.info(f"[SAVE] {fn} ({len(d)}条)")
        # Group moves by game
        game_moves = {}
        for m in self.moves:
            gid = m.get('game_idx', 0)
            game_moves.setdefault(gid, []).append(m['uci'])

        sm = {
            'start': self.st.isoformat(), 'end': datetime.now().isoformat(),
            'total': self.total, 'sends': self.sends, 'recvs': self.recvs,
            'moves': len(self.moves), 'move_list': [m['uci'] for m in self.moves],
            'session_key': self.session_key.hex() if self.session_key else None,
            'uin': self.uin,
            'my_seat': self.my_seat,
            'i_first_side': self.i_first_side,
            'my_camp': self.my_camp,
            'game_count': self.game_count,
            'per_game_moves': {str(k): v for k, v in game_moves.items()},
        }
        sp = os.path.join(out, f'qqchess_summary_{ts}.json')
        with open(sp, 'w') as f:
            json.dump(sm, f, ensure_ascii=False, indent=2)
        ctx.log.info(f"[SAVE] qqchess_summary_{ts}.json")


addons = [QQChessWSProxy()]
