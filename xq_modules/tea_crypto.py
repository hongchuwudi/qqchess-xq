"""TEA-CBC encryption/decryption + session key derivation.
   Strictly matches JS module 294 TEAUtils.
"""

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

    JS: la=""+la; for(...)ia[ea]=255&la.charCodeAt(ea)
    QQ和微信登录都使用 TResponseLogin.uUin(field 1) 做密钥派生。
    """
    tk = str(uin).encode('latin-1').ljust(16, b'\x00')[:16]
    ssec_bytes = bytes.fromhex(ssec_hex)
    sk = tea_zjb_decrypt(ssec_bytes, tk)
    if sk:
        return sk[:16]
    return None
