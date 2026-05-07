"""
QQ象棋 WebSocket 消息解码器
============================
解码base64编码的JCE二进制消息，提取象棋对局数据。

用法:
  python xq_decode.py <base64字符串>
  python xq_decode.py --file messages.txt
  python xq_decode.py --interact
"""

import sys
import base64
import struct
import re

START_FEN = "rnbakabnr/9/1c5c1/p1p1p1p1p/9/9/P1P1P1P1P/1C5C1/9/RNBAKABNR w"

JCE_TYPES = {
    0: 'INT1', 1: 'INT2', 2: 'INT4', 3: 'INT8',
    4: 'FLOAT', 5: 'DOUBLE', 6: 'STR1', 7: 'STR4',
    8: 'MAP', 9: 'LIST', 10: 'S_BGN', 11: 'S_END', 12: 'ZERO',
}

ROUTES = ['log-qqchess', 'GGame', 'UpdateConfig', 'QGame', 'DAKID',
           'Notify', 'invincible', 'PVP', 'battle', 'GameData', 'GM_']


def tagn(b):
    return b >> 4


def typen(b):
    return b & 0x0f


def safe_ascii(data):
    return ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)


def hexdump(data, offset=0, limit=512):
    lines = []
    end = min(len(data), limit)
    for i in range(0, end, 16):
        chunk = data[i:i+16]
        hx = ' '.join(f'{b:02x}' for b in chunk)
        asc = safe_ascii(chunk)
        lines.append(f"    {offset+i:04x}: {hx:<48s} {asc}")
    if len(data) > limit:
        lines.append(f"    ... ({len(data) - limit} more bytes)")
    return '\n'.join(lines)


def find_route(data):
    """在数据中查找路由，返回 (route_name, offset, jce_tag)"""
    for route in ROUTES:
        idx = data.find(route.encode())
        if idx >= 0:
            jce_tag = None
            # 检查是否有JCE STR1前缀 (tag_byte + len_byte)
            if idx >= 2:
                tb = data[idx - 2]
                lb = data[idx - 1]
                if typen(tb) == 6 and lb == len(route):
                    jce_tag = tagn(tb)
            return route, idx, jce_tag
    return None, -1, None


def find_fen(data):
    """搜索FEN棋局字符串"""
    pattern = re.compile(
        b'[rRnNbBaAkKcCpP]{5,}(?:/[rRnNbBaAkKcCpP1-9]{3,}){5,}'
    )
    return [m.group().decode('ascii') for m in pattern.finditer(data)]


def find_coords(data):
    """
    搜索可能的走子坐标。
    在JCE中，棋子的fromCol/fromRow/toCol/toRow可能是连续的INT1字段。
    特征: 4个连续字节，值在cols 0-8, rows 0-9之间。
    同时也会在周围搜索上下文标记。
    """
    results = []
    for i in range(len(data) - 4):
        vals = list(data[i:i+4])
        if (0 <= vals[0] <= 8 and 0 <= vals[1] <= 9 and
            0 <= vals[2] <= 8 and 0 <= vals[3] <= 9):
            if vals == [0, 0, 0, 0]:
                continue
            # 检查前后是否有JCE tag标记
            before = data[max(0, i-3):i]
            after = data[i+4:min(len(data), i+6)]
            results.append({
                'offset': i,
                'from': (vals[0], vals[1]),
                'to': (vals[2], vals[3]),
                'ctx_before': before.hex(),
                'ctx_after': after.hex(),
            })
    return results


def find_jce_structs(data):
    """扫描数据中所有的JCE结构边界 (STRUCT_BEGIN和STRUCT_END)"""
    structs = []
    for i, b in enumerate(data):
        jtype = typen(b)
        tag = tagn(b)
        if jtype in (10, 11):
            structs.append({
                'offset': i,
                'type': 'BEGIN' if jtype == 10 else 'END',
                'tag': tag,
            })
    return structs


def scan_message(raw):
    """全面扫描一条消息，返回所有发现"""
    info = {
        'size': len(raw),
        'total_len': struct.unpack('>H', raw[0:2])[0] if len(raw) >= 2 else 0,
        'direction': None,
        'strings': [],
        'route': None,
        'fen': [],
        'coords': [],
        'struct_boundaries': [],
        'footer_offset': -1,
        'interesting_ints': [],
    }

    # 判断方向
    if len(raw) >= 7:
        if raw[2:7] == b'\x01\x10\xcf\x10\x01':
            info['direction'] = 'SEND'
        elif raw[2:5] == b'\x0c\x10\x01':
            info['direction'] = 'RECV'

    # 路由
    route_name, route_off, jce_tag = find_route(raw)
    if route_name:
        info['route'] = {'name': route_name, 'offset': route_off, 'tag': jce_tag}

    # 可读字符串
    for m in re.finditer(b'[\x20-\x7e]{3,}', raw):
        try:
            info['strings'].append(m.group().decode('ascii'))
        except:
            pass

    # FEN
    info['fen'] = find_fen(raw)

    # 坐标
    info['coords'] = find_coords(raw)

    # JCE结构边界
    info['struct_boundaries'] = find_jce_structs(raw)

    # 搜索尾部
    footer_pat = b'\x0b\xe0\x04\xf6\x10\x00\xf0\x11'
    idx = raw.rfind(footer_pat)
    if idx >= 0:
        info['footer_offset'] = idx

    # 提取小整数值(0-9范围内)及其上下文，可能是棋局参数
    for i, b in enumerate(raw):
        if 0 <= b <= 9:
            tag_byte = raw[i-1] if i > 0 else 0
            info['interesting_ints'].append({
                'offset': i,
                'value': b,
                'prev_tag': tag_byte,
                'prev_tag_type': JCE_TYPES.get(typen(tag_byte), '?'),
                'prev_tag_num': tagn(tag_byte),
            })

    return info


def format_report(info, verbose=True):
    """格式化输出"""
    lines = []
    lines.append("=" * 70)
    direction = info.get('direction', '?')
    lines.append(f"[{direction}]  {info['size']} bytes  "
                 f"(声明长度: {info['total_len']})")

    # 路由
    route = info.get('route')
    if route:
        lines.append(f"Route: {route['name']} (offset={route['offset']})")

    # 关键字符串
    strings = info.get('strings', [])
    important = [s for s in strings if any(
        kw in s for kw in ['Game', 'Move', 'step', 'FEN', 'match', 'room',
                           'PVP', 'battle', 'rank', 'Version', 'config',
                           'user', 'Notify', 'Android', 'iOS'])]
    if important:
        lines.append(f"Strings: {' | '.join(important[:10])}")
    elif verbose and strings:
        lines.append(f"Strings: {' | '.join(strings[:6])}")

    # FEN
    if info['fen']:
        lines.append(f"*** FEN: {' ; '.join(info['fen'])}")

    # 走子坐标候选
    coords = info.get('coords', [])
    if coords:
        # 去重: 合并相邻的候选 (偏移差<3的视为同一组)
        groups = []
        for c in coords:
            if not groups or c['offset'] - groups[-1][-1]['offset'] > 2:
                groups.append([c])
            else:
                groups[-1].append(c)

        lines.append(f"*** 走子坐标候选 ({len(coords)}个, {len(groups)}组):")
        for gi, grp in enumerate(groups[:8]):
            c = grp[0]  # 显示每组的第一个
            fc, fr = c['from']
            tc, tr = c['to']
            uci = f"{chr(ord('a')+fc)}{fr}{chr(ord('a')+tc)}{tr}"
            ctx = f"{c['ctx_before']}|{c['ctx_after']}"
            lines.append(f"  [{gi}] offset={c['offset']:4d}  "
                         f"({fc},{fr})->({tc},{tr})  [{uci}]  "
                         f"ctx:[{ctx}]")

    # JCE结构概览
    bounds = info.get('struct_boundaries', [])
    if verbose and bounds:
        summary = []
        for b in bounds[:30]:
            summary.append(f"{b['type'][0]}{b['tag']}@{b['offset']}")
        lines.append(f"JCE结构: {' '.join(summary)}")

    # Footer
    if info['footer_offset'] >= 0:
        trailer = info['raw'][info['footer_offset']+8:info['footer_offset']+12]
        lines.append(f"Footer: offset={info['footer_offset']} trailer={trailer.hex()}")

    # 有趣的小整数 (可能的棋局参数)
    if verbose:
        ints = info.get('interesting_ints', [])
        # 过滤: 只显示那些前面是INT1 tag的
        jce_ints = [x for x in ints if x['prev_tag_type'] in ('INT1', 'ZERO', '?')]
        # 去重显示
        if jce_ints:
            lines.append(f"小整数 ({len(jce_ints)}个, 可能是坐标/棋局参数):")
            for x in jce_ints[:20]:
                lines.append(f"  offset={x['offset']:4d}  value={x['value']}  "
                             f"(preceded by: tag{x['prev_tag_num']} {x['prev_tag_type']})")

    lines.append("=" * 70)
    return '\n'.join(lines)


def decode(b64):
    """解码一条base64消息并返回分析结果"""
    raw = base64.b64decode(b64)
    info = scan_message(raw)
    info['raw'] = raw
    return info


def interactive():
    print("=" * 70)
    print("  QQ象棋 WebSocket 解码器 - 交互模式")
    print("=" * 70)
    print("  从浏览器 DevTools → Network → WS → Messages")
    print("  复制 base64 消息，粘贴解码")
    print()
    print("  命令:")
    print("    :v / :s  详细/简要模式")
    print("    :hex     显示完整hex dump")
    print("    :last    重放上一条")
    print("    :q       退出")
    print("=" * 70)
    print()

    verbose = True
    show_hex = False
    count = 0
    history = []

    while True:
        try:
            line = input(f"[{count}]> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n退出")
            break

        if not line:
            continue
        if line == ':q':
            break
        if line == ':v':
            verbose = True
            print("  -> 详细模式")
            continue
        if line == ':s':
            verbose = False
            print("  -> 简要模式")
            continue
        if line == ':hex':
            show_hex = not show_hex
            print(f"  -> HEX {'ON' if show_hex else 'OFF'}")
            continue
        if line == ':last':
            if history:
                line = history[-1]
                print("  (重放最后一条)")
            else:
                continue
        if line == ':h':
            print("  命令: :v详细 :s简要 :hex切换hex :last重放 :q退出")
            continue

        try:
            info = decode(line)
            history.append(line)
            info['raw'] = base64.b64decode(line)

            print(format_report(info, verbose=verbose))

            if show_hex:
                print(hexdump(info['raw']))

            count += 1

            if info['fen'] or info['coords']:
                print(">>> 检测到棋局数据! 使用 :hex 查看完整hex")
                if not verbose:
                    print("   (输入 :v 查看更多细节)")
        except Exception as e:
            print(f"  解码失败: {e}")


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
        print(__doc__)
        return

    if sys.argv[1] == '--interact':
        interactive()
    elif sys.argv[1] == '--file':
        with open(sys.argv[2], 'r') as f:
            for i, line in enumerate(f):
                line = line.strip()
                if line and not line.startswith('#'):
                    print(f"\n--- 消息 #{i} ---")
                    info = decode(line)
                    info['raw'] = base64.b64decode(line)
                    print(format_report(info, verbose=True))
                    print(hexdump(info['raw']))
    else:
        info = decode(sys.argv[1])
        info['raw'] = base64.b64decode(sys.argv[1])
        print(format_report(info, verbose=True))
        print(hexdump(info['raw']))


if __name__ == '__main__':
    main()
