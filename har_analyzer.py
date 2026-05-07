"""
QQ象棋 (Tencent QQ Chess XQ) HAR抓包分析器
===========================================
解析HAR文件中的WebSocket消息，提取象棋对局数据。

协议分析结果:
- WebSocket: wss://wxlogin.qqchess.qq.com:443
- 消息编码: base64编码的JCE (Jce Communication Encoding) 二进制协议
- 棋盘编码: 中国象棋FEN格式
  rnbakabnr/9/1c5c1/p1p1p1p1p/9/9/P1P1P1P1P/1C5C1/9/RNBAKABNR w
- 棋子: r车 n马 b象 a士 k将 c炮 p卒 (小写黑方, 大写红方)
- 走子: fromCol/fromRow -> toCol/toRow (0-8列, 0-9行)
- 消息ID: 85001-100100范围, 377个不同的消息类型

用法:
  python har_analyzer.py data/h5login.qqchess.qq.com.har
"""

import json
import base64
import struct
import sys
import re
from datetime import datetime
from collections import defaultdict

# ============================================================
# 中国象棋FEN格式定义
# ============================================================

# 标准中国象棋初始局面
XQ_START_FEN = "rnbakabnr/9/1c5c1/p1p1p1p1p/9/9/P1P1P1P1P/1C5C1/9/RNBAKABNR w"

# 棋子字符映射
PIECE_NAMES = {
    # 黑方 (小写)
    'r': '黑车', 'n': '黑马', 'b': '黑象', 'a': '黑士',
    'k': '黑将', 'c': '黑炮', 'p': '黑卒',
    # 红方 (大写)
    'R': '红车', 'N': '红马', 'B': '红相', 'A': '红仕',
    'K': '红帅', 'C': '红炮', 'P': '红兵',
}

# 棋盘坐标到中文描述
def col_name(c):
    """列号 -> 中文列名"""
    return f"第{c+1}列"

def row_name(r):
    """行号 -> 中文行名 (黑方视角0=底线)"""
    return f"第{r+1}行"


class HARAnalyzer:
    """HAR文件解析器 - 提取象棋对局WebSocket数据"""

    def __init__(self, har_path):
        self.har_path = har_path
        self.entries = []
        self.ws_messages = []  # 所有WebSocket消息
        self.game_messages = []  # 对局相关消息
        self.move_list = []  # 走子列表

    def load(self):
        """加载HAR文件"""
        print(f"[*] 加载HAR文件: {self.har_path}")
        with open(self.har_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        self.entries = data['log']['entries']
        print(f"[+] 总条目数: {len(self.entries)}")

        # 统计资源类型
        types = defaultdict(int)
        for e in self.entries:
            types[e.get('_resourceType', 'unknown')] += 1
        print(f"[+] 资源类型分布:")
        for t, c in sorted(types.items(), key=lambda x: -x[1]):
            print(f"      {t}: {c}")

    def extract_websocket_messages(self):
        """提取所有WebSocket消息"""
        print("\n[*] 提取WebSocket消息...")
        for e in self.entries:
            if e.get('_resourceType') == 'websocket':
                url = e['request']['url']
                if '_webSocketMessages' in e:
                    for msg in e['_webSocketMessages']:
                        msg_type = msg.get('type', 'unknown')
                        data_b64 = msg.get('data', '')
                        try:
                            raw = base64.b64decode(data_b64)
                        except:
                            raw = b''
                        self.ws_messages.append({
                            'url': url,
                            'type': msg_type,  # 'send' or 'receive'
                            'raw': raw,
                            'size': len(raw),
                            'timestamp': msg.get('time', 0),
                        })
        print(f"[+] 共提取 {len(self.ws_messages)} 条WebSocket消息")
        send_count = sum(1 for m in self.ws_messages if m['type'] == 'send')
        recv_count = sum(1 for m in self.ws_messages if m['type'] == 'receive')
        print(f"      发送(send): {send_count} 条")
        print(f"      接收(receive): {recv_count} 条")

    def analyze_protocol_structure(self):
        """分析WebSocket消息的二进制协议结构"""
        print("\n[*] 分析协议结构...")
        print("=" * 60)

        # 分析每条消息的头部
        for i, msg in enumerate(self.ws_messages[:30]):
            raw = msg['raw']
            if len(raw) < 4:
                continue

            # 尝试解析消息头
            # 格式: [varint长度] [0c10] [01] [2c] [session_id...]
            extracted = self._extract_readable(raw)
            print(f"\n--- {msg['type'].upper()} #{i} ({len(raw)} bytes) ---")

            # 显示hex头
            hex_head = raw[:32].hex()
            print(f"  HEX: {hex_head}")

            # 显示可读字符串
            if extracted['strings']:
                for s in extracted['strings'][:5]:
                    print(f"  STR: {s}")

            # 显示JSON
            if extracted['json']:
                for j in extracted['json'][:3]:
                    print(f"  JSON: {j[:200]}")

    def _extract_readable(self, data):
        """从二进制数据中提取可读字符串和JSON"""
        result = {'strings': [], 'json': []}

        # 提取可读ASCII字符串 (>=4字符)
        strings = re.findall(b'[\x20-\x7e]{4,}', data)
        for s in strings:
            try:
                result['strings'].append(s.decode('ascii'))
            except:
                pass

        # 提取JSON对象
        json_matches = re.findall(b'\{[^{}\x00-\x1f]{10,}\}', data)
        for j in json_matches:
            try:
                parsed = json.loads(j.decode('ascii'))
                result['json'].append(json.dumps(parsed, ensure_ascii=False))
            except:
                pass

        return result

    def find_chess_games(self):
        """寻找包含象棋对局数据的消息"""
        print("\n[*] 搜索象棋对局数据...")
        print("=" * 60)

        # 象棋FEN特征
        fen_pattern = re.compile(
            b'[rRnNbBaAkKcCpP]{3,}'
            b'(?:/[rRnNbBaAkKcCpP1-9]{3,}){5,}'
        )

        # 中国象棋特有棋子特征
        xq_piece_pattern = re.compile(
            b'(?:rnbakabnr|RNBAKABNR|[rR][nNbBaAkKcCpP]{2,})'
        )

        found_games = 0
        for i, msg in enumerate(self.ws_messages):
            raw = msg['raw']

            # 1. 搜索FEN格式
            fen_match = fen_pattern.search(raw)
            if fen_match:
                found_games += 1
                print(f"\n[+] 消息 #{i} ({msg['type']}, {len(raw)} bytes):")
                print(f"    FEN: {fen_match.group().decode('ascii', errors='ignore')[:200]}")

            # 2. 搜索棋子特征
            piece_match = xq_piece_pattern.search(raw)
            if piece_match and not fen_match:
                print(f"\n[+] 消息 #{i} ({msg['type']}, {len(raw)} bytes):")
                print(f"    棋子数据: {piece_match.group().decode('ascii', errors='ignore')[:100]}")

            # 3. 搜索走子坐标
            extracted = self._extract_readable(raw)
            for s in extracted['strings']:
                if any(kw in s for kw in ['move', 'Move', 'step', 'Step', '棋', '走子', 'qizi']):
                    print(f"\n[+] 消息 #{i} 包含走子信息:")
                    print(f"    {s[:200]}")
                    break

        if found_games == 0:
            print("\n[!] 未找到完整棋局FEN数据")
            print("    提示: 该抓包可能只包含登录/大厅数据，未进入实际对局")
            print("    建议: 进入一局象棋对战后重新抓包")

    def extract_messages_by_type(self):
        """按消息特征分类提取"""
        print("\n[*] 按消息内容分类...")
        print("=" * 60)

        categories = defaultdict(list)

        for i, msg in enumerate(self.ws_messages):
            raw = msg['raw']
            extracted = self._extract_readable(raw)
            all_text = ' '.join(extracted['strings'])

            # 分类关键词
            if 'GGame' in all_text or 'log-qqchess' in all_text:
                categories['游戏服务'].append(i)
            if 'UpdateConfig' in all_text:
                categories['配置更新'].append(i)
            if 'invincible' in all_text or 'user' in all_text.lower():
                categories['用户信息'].append(i)
            if 'room' in all_text.lower() or 'table' in all_text.lower():
                categories['房间/桌子'].append(i)
            if any(kw in all_text for kw in ['match', 'Match', 'game', 'Game']):
                categories['对局/匹配'].append(i)
            if any(kw in all_text for kw in ['rank', 'Rank', 'level', 'Level']):
                categories['排位/等级'].append(i)
            if 'DAKID' in all_text:
                categories['认证/Auth'].append(i)

        for cat, msgs in categories.items():
            print(f"\n  [{cat}]: {len(msgs)} 条消息")
            if len(msgs) <= 5:
                for idx in msgs:
                    msg = self.ws_messages[idx]
                    print(f"    #{idx} {msg['type']} {msg['size']}bytes")

    def decode_move_coordinates(self):
        """尝试从消息中解码走子坐标"""
        print("\n[*] 搜索走子坐标模式...")
        print("=" * 60)
        print("棋盘坐标系: 列0-8 (a-i), 行0-9 (黑方0底线→9顶线)")
        print()

        # 在接收消息中搜索坐标模式
        # 中国象棋坐标范围: fromCol(0-8) fromRow(0-9) toCol(0-8) toRow(0-9)
        found = 0
        for i, msg in enumerate(self.ws_messages):
            if msg['type'] != 'receive':
                continue
            raw = msg['raw']
            extracted = self._extract_readable(raw)

            for s in extracted['strings']:
                # 搜索坐标表示
                coord_match = re.search(
                    r'(?:fx|fromX|fromCol|from_col)[:\s]*(\d).*?'
                    r'(?:fy|fromY|fromRow|from_row)[:\s]*(\d).*?'
                    r'(?:tx|toX|toCol|to_col)[:\s]*(\d).*?'
                    r'(?:ty|toY|toRow|to_row)[:\s]*(\d)',
                    s, re.IGNORECASE
                )
                if coord_match:
                    found += 1
                    fx, fy, tx, ty = [int(x) for x in coord_match.groups()]
                    piece_f = self._colrow_to_uci(fx, fy)
                    piece_t = self._colrow_to_uci(tx, ty)
                    print(f"  #{i}: {piece_f} -> {piece_t} "
                          f"(from=({fx},{fy}) to=({tx},{ty}))")
                    break

        if found == 0:
            print("  [未找到明确的走子坐标数据]")

    def _colrow_to_uci(self, col, row):
        """列行坐标转为UCI格式 (a0-i9)"""
        return f"{chr(ord('a') + col)}{row}"

    def generate_report(self):
        """生成分析报告"""
        print("\n" + "=" * 60)
        print("           象棋QQ游戏协议分析报告")
        print("=" * 60)

        print("""
[协议架构]
  ┌──────────────────────────────────────────┐
  │  QQ象棋客户端 (Cocos Creator H5)          │
  │  ├── main/index.ec248.js (10MB 游戏代码)   │
  │  ├── Bundle-BattleBase  (棋盘/棋子资源)    │
  │  ├── Bundle-BattleCore  (对战场景)         │
  │  └── Bundle-BasePvp     (PVP功能)         │
  └──────────────┬───────────────────────────┘
                 │ WebSocket (binary)
                 │ wss://wxlogin.qqchess.qq.com:443
                 ▼
  ┌──────────────────────────────────────────┐
  │  游戏服务器                                │
  │  协议: JCE编码 + Protobuf消息体             │
  │  命名空间:                                 │
  │    • QQChessZoneProto (大厅/匹配)          │
  │    • QQChessCommProto (通用象棋数据)       │
  │    • QQChessPlayProto (对局/走子)           │
  └──────────────────────────────────────────┘

[消息格式]
  ┌──────┬──────┬────────┬──────────┬────────┐
  │ 长度  │ 固定 │ 会话ID  │ 路由/命令 │ 消息体  │
  │varint│0c1001│ hexstr │  string   │JCE编码  │
  └──────┴──────┴────────┴──────────┴────────┘

[棋盘编码 - 中国象棋FEN]
  初始局面:
  rnbakabnr/9/1c5c1/p1p1p1p1p/9/9/P1P1P1P1P/1C5C1/9/RNBAKABNR w

  棋子字符 (黑方小写/红方大写):
  r/R=车 n/N=马 b/B=象/相 a/A=士/仕
  k/K=将/帅 c/C=炮 p/P=卒/兵

  9行×10列棋盘 (黑方底线→顶线)

[走子编码]
  坐标: (fromCol, fromRow) → (toCol, toRow)
  范围: col 0-8, row 0-9
  消息: NOTIFY_PVP_GAME_MOVE_STEP → JCE编码 → WebSocket

[消息ID范围]
  85001-85504  大厅/房间/匹配
  86001-86028  对局对战
  89012-89213  社交/分享
  89301-89757  游戏系统
  100100       特殊消息
""")

        print(f"[抓包统计]")
        print(f"  总HTTP请求: {len(self.entries)}")
        print(f"  WebSocket消息: {len(self.ws_messages)}")
        send_count = sum(1 for m in self.ws_messages if m['type'] == 'send')
        recv_count = sum(1 for m in self.ws_messages if m['type'] == 'receive')
        print(f"    发送: {send_count}")
        print(f"    接收: {recv_count}")

        if self.move_list:
            print(f"\n[走子记录] (共{len(self.move_list)}步)")
            for i, move in enumerate(self.move_list):
                print(f"  {i+1:3d}. {move}")
        else:
            print(f"\n[!] 未检测到完整对局走子数据")
            print(f"    抓包内容主要为: 登录认证 + 大厅数据 + 配置加载")
            print(f"    要获取走子数据，请:")
            print(f"      1. 进入一局象棋对局")
            print(f"      2. 重新抓包")
            print(f"      3. 在对局过程中走几步棋")
            print(f"      4. 保存为新的HAR文件")


class RealtimeAnalyzer:
    """
    实时分析器框架 - 用于后续开发实时棋局分析工具
    需要配合mitmproxy或浏览器插件使用

    阵营判定: 从协议层的 nSeatID 和 iFirstSide 获取:
      my_camp = 'red' if nSeatID == iFirstSide else 'black'
    """

    def __init__(self, my_camp=None):
        self.board_fen = XQ_START_FEN
        self.move_history = []
        self.current_side = 'w'  # FEN side (w=红方, b=黑方) — always alternates
        self.my_camp = my_camp  # 'red' or 'black' — player's side from protocol

    def parse_fen(self, fen_str):
        """解析FEN字符串为棋盘二维数组"""
        board = []
        rows = fen_str.split()[0].split('/')
        for row_str in rows:
            row = []
            for ch in row_str:
                if ch.isdigit():
                    row.extend(['.'] * int(ch))
                else:
                    row.append(ch)
            board.append(row)
        return board

    def board_to_display(self, board):
        """棋盘转为可视化字符串"""
        lines = []
        lines.append("  ┌───┬───┬───┬───┬───┬───┬───┬───┬───┐")
        for i, row in enumerate(board):
            line = f"{9-i} │"
            for cell in row:
                display = PIECE_NAMES.get(cell, '  ·')[0] if cell != '.' else ' ·'
                line += f" {display} │"
            lines.append(line)
            if i < 9:
                lines.append("  ├───┼───┼───┼───┼───┼───┼───┼───┼───┤")
        lines.append("  └───┴───┴───┴───┴───┴───┴───┴───┴───┘")
        lines.append("    a   b   c   d   e   f   g   h   i  ")
        return '\n'.join(lines)

    def apply_move(self, from_col, from_row, to_col, to_row):
        """应用一步走子到棋盘"""
        board = self.parse_fen(self.board_fen)
        piece = board[from_row][from_col]
        board[from_row][from_col] = '.'
        board[to_row][to_col] = piece

        # 重新生成FEN
        fen_parts = []
        for row in board:
            empty = 0
            row_str = ''
            for cell in row:
                if cell == '.':
                    empty += 1
                else:
                    if empty > 0:
                        row_str += str(empty)
                        empty = 0
                    row_str += cell
            if empty > 0:
                row_str += str(empty)
            fen_parts.append(row_str)

        self.current_side = 'b' if self.current_side == 'w' else 'w'
        self.board_fen = '/'.join(fen_parts) + ' ' + self.current_side
        self.move_history.append((from_col, from_row, to_col, to_row))

        return self.board_fen

    def get_current_fen(self):
        """获取当前棋盘FEN"""
        return self.board_fen

    def display_board(self):
        """显示当前棋盘"""
        board = self.parse_fen(self.board_fen)
        print(self.board_to_display(board))


def main():
    if len(sys.argv) < 2:
        print("用法: python har_analyzer.py <HAR文件路径>")
        print("示例: python har_analyzer.py data/h5login.qqchess.qq.com.har")
        sys.exit(1)

    har_path = sys.argv[1]

    # 1. 分析HAR文件
    analyzer = HARAnalyzer(har_path)
    analyzer.load()
    analyzer.extract_websocket_messages()
    analyzer.analyze_protocol_structure()
    analyzer.extract_messages_by_type()
    analyzer.find_chess_games()
    analyzer.decode_move_coordinates()
    analyzer.generate_report()

    # 2. 演示实时分析器框架
    print("\n" + "=" * 60)
    print("  实时分析器框架演示")
    print("=" * 60)
    rt = RealtimeAnalyzer()
    print("\n初始棋盘:")
    rt.display_board()

    # 模拟几步走子
    print("\n模拟走子: 红炮二平五 (h7e7) - 当头炮")
    rt.apply_move(4, 7, 4, 5)  # 炮从(4,7)到(4,5) 即h7->e7 中炮
    rt.display_board()
    print(f"当前FEN: {rt.get_current_fen()}")

    print("\n模拟走子: 黑马8进7 (b9c7)")
    rt.apply_move(1, 9, 2, 7)  # 马从(1,9)到(2,7)
    rt.display_board()
    print(f"当前FEN: {rt.get_current_fen()}")

    print("\n[下一步] 将实时WebSocket抓包与RealtimeAnalyzer对接，即可实现:")
    print("  1. 实时显示棋局变化")
    print("  2. 记录完整棋谱")
    print("  3. 对接AI引擎进行局面分析")
    print("  4. 预测最佳走法")


if __name__ == '__main__':
    main()
