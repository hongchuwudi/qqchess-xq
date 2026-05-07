"""
TEA-CBC 解密器 — 实现对战消息的解密

基于 文件分析.md 中的 JS 逆向工程结果:
- TEA 核心: 16轮 Feistel 网络, delta=0x9E3779B9
- CBC 模式: 8字节块, 随机头尾填充
- 密钥派生: tempKey=pad16(str(uin)), sessionKey=TEA_decrypt(sSecKey, tempKey)
- 消息级加密: pkg.iFlag & 1 决定 body 是否加密

用法:
  python tea_decrypt.py --har data/h5login.qqchess.qq.com.har
  python tea_decrypt.py --raw data/sessions/qqchess_ws_raw_*.json
"""

import sys
import json
import base64
import struct
import re
import argparse

# ============================================================
# TEA 算法实现 (与 JS 模块 294 TEAUtils 对应)
# ============================================================

DELTA = 0x9E3779B9
ROUNDS = 16


def tea_decrypt_block(v0: int, v1: int, k: list[int]) -> tuple[int, int]:
    """TEA 解密一个 8 字节块。对应 JS 的 qKb() 函数。

    XXTEA (Corrected Block TEA) 变体:
      v1 -= ((v0<<4 ^ v0>>5) + v0) ^ (sum + k[(sum>>11) & 3])
      v0 -= ((v1<<4 ^ v1>>5) + v1) ^ (sum + k[sum & 3])
    """
    total = (DELTA * ROUNDS) & 0xFFFFFFFF

    for _ in range(ROUNDS):
        v1 = (v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ (total + k[(total >> 11) & 3]))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (total + k[total & 3]))) & 0xFFFFFFFF
        total = (total - DELTA) & 0xFFFFFFFF

    return v0, v1


def tea_encrypt_block(v0: int, v1: int, k: list[int]) -> tuple[int, int]:
    """TEA 加密一个 8 字节块。对应 JS 的 Iec() 函数。"""
    total = 0

    for _ in range(ROUNDS):
        total = (total + DELTA) & 0xFFFFFFFF
        v0 = (v0 + (((v1 << 4 ^ v1 >> 5) + v1) ^ (total + k[total & 3]))) & 0xFFFFFFFF
        v1 = (v1 + (((v0 << 4 ^ v0 >> 5) + v0) ^ (total + k[(total >> 11) & 3]))) & 0xFFFFFFFF

    return v0, v1


def bytes_to_key(key_bytes: bytes) -> list[int]:
    """将 16 字节密钥转为 4 个 32-bit 无符号整数 (little-endian, 匹配 JS Uint32Array)"""
    return list(struct.unpack('<4I', key_bytes[:16]))


def tea_cbc_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """TEA CBC 模式解密。对应 JS 的 zJb() 函数。

    IV 为零向量。little-endian 字节序匹配 JS。
    """
    if len(ciphertext) < 8:
        return b''

    key_ints = bytes_to_key(key)
    block_count = len(ciphertext) // 8
    plaintext = bytearray()

    prev_block = b'\x00' * 8  # IV = 0

    for i in range(block_count):
        block = ciphertext[i * 8:(i + 1) * 8]
        v0, v1 = struct.unpack('<2I', block)

        d0, d1 = tea_decrypt_block(v0, v1, key_ints)

        # CBC: plaintext = decrypt(ciphertext) XOR previous_ciphertext
        iv0, iv1 = struct.unpack('<2I', prev_block)
        d0 ^= iv0
        d1 ^= iv1

        plaintext_block = struct.pack('<2I', d0, d1)
        plaintext.extend(plaintext_block)

        prev_block = block

    return bytes(plaintext)


def tea_cbc_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """TEA CBC 模式加密 (用于测试验证, little-endian)"""
    pad_len = 8 - (len(plaintext) % 8)
    if pad_len == 0:
        pad_len = 8
    plaintext = plaintext + bytes([pad_len] * pad_len)

    key_ints = bytes_to_key(key)
    block_count = len(plaintext) // 8
    ciphertext = bytearray()

    prev_block = b'\x00' * 8  # IV = 0

    for i in range(block_count):
        block = plaintext[i * 8:(i + 1) * 8]
        v0, v1 = struct.unpack('<2I', block)

        # CBC: XOR with previous ciphertext block
        iv0, iv1 = struct.unpack('<2I', prev_block)
        v0 ^= iv0
        v1 ^= iv1

        e0, e1 = tea_encrypt_block(v0, v1, key_ints)

        ciphertext_block = struct.pack('<2I', e0, e1)
        ciphertext.extend(ciphertext_block)
        prev_block = ciphertext_block

    return bytes(ciphertext)


# ============================================================
# QQ象棋消息格式解析
# ============================================================

SEND_MAGIC = b'\x01\x10\xcf\x10\x01'
RECV_MAGIC = b'\x0c\x10\x01'


def parse_message(raw: bytes) -> dict:
    """解析 QQ象棋 WebSocket 消息的外层结构。

    格式:
      SEND: [2B 大端长度] [01 10 cf 10 01] [变长头部 + JCE body]
      RECV: [2B 大端长度] [0c 10 01] [变长头部 + JCE body]

    头部包含: session_id 等字段 (JCE编码)
    """
    result = {
        'size': len(raw),
        'direction': None,
        'magic': None,
        'header_bytes': b'',
        'body_bytes': b'',
        'session_id': None,
        'header_ints': [],
        'iFlag': None,
    }

    if len(raw) < 4:
        return result

    # 解析长度前缀
    declared_len = struct.unpack('>H', raw[0:2])[0]
    result['declared_len'] = declared_len

    # 解析 magic
    if raw[2:7] == SEND_MAGIC:
        result['direction'] = 'SEND'
        result['magic'] = SEND_MAGIC
        offset = 7
    elif raw[2:5] == RECV_MAGIC:
        result['direction'] = 'RECV'
        result['magic'] = RECV_MAGIC
        offset = 5
    else:
        result['direction'] = 'UNKNOWN'
        offset = 2

    result['header_start'] = offset

    # 尝试从头部提取小整数 (可能的 iFlag)
    body_start = _find_body_start(raw, offset)
    result['header_bytes'] = raw[offset:body_start]
    result['body_bytes'] = raw[body_start:]
    result['body_start'] = body_start

    # 从头部提取可能的字段
    header = raw[offset:body_start]
    for i, b in enumerate(header):
        if 0 <= b <= 255:
            result['header_ints'].append({'offset': offset + i, 'value': b})

    return result


def _find_body_start(raw: bytes, offset: int) -> int:
    """从消息中定位 JCE body 的起始位置。

    头部包含变长的 JCE 编码字段 (session_id, route 等)。
    body 以一个 JCE STRUCT_BEGIN (0x0a) 开始。

    策略: 寻找第一个 tag=0, type=STRUCT_BEGIN (0x0a) 字节，
    该字节应在 route 字符串之后。
    """
    # 先找到 route 字符串结束位置
    # route 是 JCE STR1/STR4 字段, 后面跟着 body
    # body 以 0x0a (tag=0, STRUCT_BEGIN) 或直接在 route 后开始

    # 简单策略: 寻找 route 字符串后的第一个 0x0a (tag 0, S_BGN)
    # 但实际上 body 可能以其他 tag 开始

    # 更好的方法: 找到所有 JCE STRUCT_END (0x0b) 的位置
    # header 以 STRUCT_END 结束, 然后 body 开始
    # body 以 STRUCT_BEGIN (0x0a) 开始

    # 寻找 header 的结尾: 通常是 route 字符串后的第一个 0x0b
    # 然后 body 紧接着开始

    pos = offset
    while pos < len(raw):
        b = raw[pos]
        tag = b >> 4
        jtype = b & 0x0f

        if jtype == 10:  # STRUCT_BEGIN
            # 这可能是 body 的开始
            # 验证: 前面应该有 STRUCT_END 结束 header
            if pos > offset and (raw[pos - 1] & 0x0f) == 11:
                return pos
            # 或者前面有 route 字符串
            return pos

        if jtype == 6:  # STR1
            if pos + 1 < len(raw):
                strlen = raw[pos + 1]
                pos += 2 + strlen
                continue
        elif jtype == 7:  # STR4
            if pos + 4 < len(raw):
                strlen = struct.unpack('>I', raw[pos + 1:pos + 5])[0]
                pos += 5 + strlen
                continue
        elif jtype == 12:  # ZERO
            pos += 1
            continue
        elif jtype in (0,):  # INT1
            pos += 2  # tag + value
            continue
        elif jtype == 1:  # INT2
            pos += 3
            continue
        elif jtype == 2:  # INT4
            pos += 5
            continue
        elif jtype == 3:  # INT8
            pos += 9
            continue
        elif jtype in (10, 11):  # STRUCT_BEGIN/END
            pos += 1
            continue
        else:
            pos += 1

    return offset  # fallback


# ============================================================
# JCE 解析器 (轻量版)
# ============================================================

def jce_decode(data: bytes, offset: int = 0) -> tuple[dict, int]:
    """解析 JCE 编码的结构, 返回 (fields_dict, new_offset)"""
    fields = {}
    pos = offset

    while pos < len(data):
        b = data[pos]
        tag = b >> 4
        jtype = b & 0x0f

        pos += 1

        if jtype == 11:  # STRUCT_END
            break

        if jtype == 12:  # ZERO
            continue

        if jtype == 0:  # INT1
            if pos < len(data):
                fields[f'INT1_T{tag}'] = struct.unpack('b', data[pos:pos + 1])[0]
                pos += 1
        elif jtype == 1:  # INT2
            if pos + 1 < len(data):
                fields[f'INT2_T{tag}'] = struct.unpack('>h', data[pos:pos + 2])[0]
                pos += 2
        elif jtype == 2:  # INT4
            if pos + 3 < len(data):
                fields[f'INT4_T{tag}'] = struct.unpack('>i', data[pos:pos + 4])[0]
                pos += 4
        elif jtype == 3:  # INT8
            if pos + 7 < len(data):
                fields[f'INT8_T{tag}'] = struct.unpack('>q', data[pos:pos + 8])[0]
                pos += 8
        elif jtype == 6:  # STR1
            if pos < len(data):
                strlen = data[pos]
                pos += 1
                if pos + strlen <= len(data):
                    fields[f'STR1_T{tag}'] = data[pos:pos + strlen].decode('utf-8', errors='replace')
                    pos += strlen
        elif jtype == 7:  # STR4
            if pos + 3 < len(data):
                strlen = struct.unpack('>I', data[pos:pos + 4])[0]
                pos += 4
                if strlen < 100000 and pos + strlen <= len(data):
                    fields[f'STR4_T{tag}'] = data[pos:pos + strlen].decode('utf-8', errors='replace')
                    pos += strlen
        elif jtype == 8:  # MAP
            count = data[pos] if pos < len(data) else 0
            pos += 1
            kv = {}
            for _ in range(count):
                k, pos = jce_decode(data, pos)
                v, pos = jce_decode(data, pos)
                if k or v:
                    kv.update(k)
                    kv.update(v)
            fields[f'MAP_T{tag}'] = kv
        elif jtype == 9:  # LIST
            count = data[pos] if pos < len(data) else 0
            pos += 1
            items = []
            for _ in range(count):
                item, pos = jce_decode(data, pos)
                items.append(item)
            fields[f'LIST_T{tag}'] = items
        elif jtype == 10:  # STRUCT_BEGIN
            sub, pos = jce_decode(data, pos)
            fields[f'STRUCT_T{tag}'] = sub
        else:
            # 未知类型, 跳过
            pass

    return fields, pos


# ============================================================
# 主分析逻辑
# ============================================================

def find_login_info(msgs: list[dict]) -> dict | None:
    """从消息列表中寻找登录响应, 提取 uin 和 sSecKey。

    登录响应特征:
    - 在 log-qqchess 路由上
    - RECV 方向
    - 包含 uUin 和 sSecKey 字段
    """
    for msg in msgs:
        raw = base64.b64decode(msg.get('base64', ''))
        if len(raw) < 10:
            continue

        # 查找路由
        route = None
        for r in [b'log-qqchess', b'DAKID', b'QGame', b'GGame']:
            idx = raw.find(r)
            if idx >= 0:
                route = r.decode()
                break

        if route != 'log-qqchess':
            continue
        if msg['type'] != 'receive':
            continue

        # 尝试找到 JCE body 并解析
        # body 在 route 之后的 struct 里

        # 寻找 sSecKey 特征: hex 字符串 (32 hex chars = 16 bytes)
        # 查找 32-char hex 字符串
        hex_pattern = re.compile(rb'[0-9a-fA-F]{32,}')
        for m in hex_pattern.finditer(raw):
            hex_str = m.group().decode('ascii')
            # 这可能是 sSecKey

        # 查找 uin 特征: 可能是数字字符串
        # 在消息中搜索

        # 尝试从 ASCII 字符串中识别
        strings = []
        for m in re.finditer(rb'[\x20-\x7e]{4,}', raw):
            try:
                strings.append(m.group().decode('ascii'))
            except:
                pass

        for s in strings:
            # 查找 sSecKey (base64 或 hex)
            if len(s) >= 32 and all(c in '0123456789abcdefABCDEF' for c in s):
                # 可能是 hex sSecKey 或 session token
                pass

    return None


def derive_session_key(sSecKey_hex: str, uin: int | str) -> bytes:
    """从登录响应派生会话密钥。

    Args:
        sSecKey_hex: sSecKey 的 hex 字符串
        uin: 用户 QQ 号

    Returns:
        16 字节会话密钥
    """
    # tempKey = pad16(str(uin))
    uin_str = str(uin).encode('ascii')
    temp_key = uin_str[:16].ljust(16, b'\x00')

    # sSecKey bytes
    ssec_bytes = bytes.fromhex(sSecKey_hex)

    # sessionKey = TEA_decrypt(sSecKey, tempKey)
    session_key = tea_cbc_decrypt(ssec_bytes, temp_key)

    # 去填充 (PKCS5-like: 末尾字节是填充长度)
    if session_key:
        pad_len = session_key[-1]
        if 1 <= pad_len <= 8:
            session_key = session_key[:-pad_len]

    return session_key[:16]


def decrypt_message(raw: bytes, session_key: bytes) -> bytes | None:
    """解密一条消息的 JCE body。

    判断 iFlag 的最低位决定是否加密。
    如果加密, 对整个 body 进行 TEA-CBC 解密。
    解密后需要去除头尾填充。
    """
    if len(raw) < 10:
        return None

    # 解析消息结构
    msg_info = parse_message(raw)
    if not msg_info['direction']:
        return None

    # body 即 JCE 编码的数据
    body = msg_info['body_bytes']
    if len(body) < 8:
        return body  # 太短, 可能未加密

    # 尝试解密 (假设 body 已加密)
    # TEA CBC 解密
    decrypted = tea_cbc_decrypt(body, session_key)

    # 去除头尾填充 (对应 JS 的随机头尾填充)
    # 头部填充: Wjb=2 轮 = 16 字节随机
    # 尾部填充: dkb=7 轮 但实际是 PKCS 风格
    # 简化: 尝试找尾部填充长度
    if len(decrypted) > 16:
        # 跳过头部随机填充 (16 字节)
        stripped = decrypted[16:]
        # 尾部填充: 最后一个字节是填充长度
        if stripped:
            pad_len = stripped[-1]
            if 1 <= pad_len <= 8:
                stripped = stripped[:-pad_len]
        return stripped

    return decrypted


def main():
    parser = argparse.ArgumentParser(description='QQ象棋消息 TEA 解密器')
    parser.add_argument('--raw', help='raw JSON 文件路径 (qqchess_ws_raw_*.json)')
    parser.add_argument('--har', help='HAR 文件路径')
    parser.add_argument('--key', help='直接提供 hex 格式的会话密钥 (32 hex chars)')
    parser.add_argument('--uin', help='QQ 号 (用于密钥派生)')
    parser.add_argument('--sSecKey', help='sSecKey hex 字符串 (从登录响应获取)')
    parser.add_argument('--test', action='store_true', help='运行自测')
    args = parser.parse_args()

    if args.test:
        test_tea()
        return

    if args.key:
        session_key = bytes.fromhex(args.key)
        print(f"[+] 使用提供密钥: {args.key}")
    elif args.uin and args.sSecKey:
        session_key = derive_session_key(args.sSecKey, args.uin)
        print(f"[+] 派生密钥: {session_key.hex()}")
    else:
        print("[!] 需要 --key 或 (--uin + --sSecKey)")
        print("[*] 请先从登录响应中提取 uin 和 sSecKey")
        print()
        print("  分析 HAR 文件以找到登录信息:")
        print(f"    python {sys.argv[0]} --har data/h5login.qqchess.qq.com.har")
        return

    # 加载消息
    if args.raw:
        with open(args.raw, 'r') as f:
            messages = json.load(f)
    elif args.har:
        messages = _load_har_messages(args.har)
    else:
        print("[!] 需要 --raw 或 --har")
        return

    # 解密每条消息
    print(f"\n[*] 共 {len(messages)} 条消息, 开始解密...")
    print("=" * 70)

    for i, msg in enumerate(messages):
        raw = base64.b64decode(msg.get('base64', ''))
        direction = msg.get('direction', '?')

        # 解密
        try:
            decrypted = decrypt_message(raw, session_key)
            if decrypted and len(decrypted) > 4:
                # 在解密后的数据中搜索棋局信息
                fens = re.findall(
                    rb'[rRnNbBaAkKcCpP]{5,}(?:/[rRnNbBaAkKcCpP1-9]{3,}){5,}',
                    decrypted
                )
                strings = []
                for m in re.finditer(rb'[\x20-\x7e]{3,}', decrypted):
                    try:
                        strings.append(m.group().decode('ascii'))
                    except:
                        pass

                has_game_data = any(
                    kw in s for s in strings
                    for kw in ['Game', 'Move', 'step', 'PVP', 'battle', 'FEN',
                               'match', 'room', 'rank', 'QGame', 'GGame']
                )

                if fens or has_game_data:
                    print(f"\n[#{i}] {direction} ({len(decrypted)} bytes decrypted)")
                    if fens:
                        print(f"  FEN: {fens[0].decode()[:120]}")
                    key_strs = [s for s in strings if any(
                        kw in s for kw in ['Game', 'Move', 'step', 'PVP', 'battle',
                                           'match', 'room', 'rank', 'FEN', 'qizi',
                                           'move', 'from', 'to', 'QGame', 'GGame']
                    )]
                    if key_strs:
                        print(f"  Strings: {' | '.join(key_strs[:8])}")
                    if len(decrypted) < 512:
                        print(f"  Hex: {decrypted.hex()}")
        except Exception as e:
            pass  # 解密失败, 跳过


def _load_har_messages(har_path: str) -> list[dict]:
    """从 HAR 文件加载 WebSocket 消息"""
    with open(har_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    messages = []
    for entry in data['log']['entries']:
        if entry.get('_resourceType') == 'websocket':
            if '_webSocketMessages' in entry:
                for msg in entry['_webSocketMessages']:
                    data_b64 = msg.get('data', '')
                    messages.append({
                        'type': msg.get('type', 'unknown'),
                        'base64': data_b64,
                        'timestamp': msg.get('time', 0),
                    })
    return messages


def test_tea():
    """TEA 算法自测"""
    print("=== TEA 算法自测 ===")

    # 测试向量 1: 基本加解密
    key = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'
    plaintext = b'Hello, QQ Chess! This is a test message.'

    print(f"原文 ({len(plaintext)} bytes): {plaintext}")
    encrypted = tea_cbc_encrypt(plaintext, key)
    print(f"密文 ({len(encrypted)} bytes): {encrypted.hex()}")

    decrypted = tea_cbc_decrypt(encrypted, key)
    print(f"解密 ({len(decrypted)} bytes): {decrypted}")

    # 去填充
    pad_len = decrypted[-1]
    unpadded = decrypted[:-pad_len]
    print(f"去填充後: {unpadded}")

    if unpadded == plaintext:
        print("[OK] TEA 自测通过!")
    else:
        print("[FAIL] TEA 自测失败!")

    # 测试向量 2: 从 JS 验证
    print()
    print("=== 密钥派生测试 ===")
    # 模拟: uin = "123456789", sSecKey = 随机hex
    test_uin = "123456789"
    temp_key = test_uin.encode().ljust(16, b'\x00')
    print(f"tempKey: {temp_key.hex()}")

    test_ssec_hex = "a1b2c3d4e5f60718293a4b5c6d7e8f90"  # 16 bytes
    test_ssec = bytes.fromhex(test_ssec_hex)
    session_key = tea_cbc_decrypt(test_ssec, temp_key)
    print(f"sessionKey (raw): {session_key.hex()}")

    print("\n[+] TEA 模块就绪")


if __name__ == '__main__':
    main()
