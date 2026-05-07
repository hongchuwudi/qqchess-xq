"""
QQ象棋实时棋局分析器 (WebSocket代理)
=====================================
通过代理WebSocket连接，实时拦截象棋对局数据，
解析走子，维护棋盘状态，对接AI引擎预测最佳走法。

用法:
  # 模式1: HAR离线分析
  python xq_analyzer.py --har data/h5login.qqchess.qq.com.har

  # 模式2: 实时代理 (需要mitmproxy)
  python xq_analyzer.py --proxy --port 8888

  # 模式3: 回放已保存的代理会话 (无需重新开局)
  python xq_analyzer.py --session data/sessions/qqchess_ws_raw_20260506_174656.json

  # 模式4: 棋盘模拟
  python xq_analyzer.py --demo
"""

import sys
import json
import struct
import base64
import re
import argparse
from collections import defaultdict
from datetime import datetime

# ============================================================
# 象棋引擎接口 (可对接多种引擎)
# ============================================================

class ChessEngine:
    """
    象棋AI引擎接口
    支持对接:
      - 象眼 (XiangEye / 旋风)
      - 皮卡鱼 (Pikafish) - 开源中国象棋引擎
      - 本地简易评估
    """

    def __init__(self, engine_type='builtin'):
        self.engine_type = engine_type

    def analyze(self, fen, depth=10, time_limit=3000):
        """分析当前局面，返回最佳走法"""
        if self.engine_type == 'builtin':
            return self._builtin_analyze(fen)
        elif self.engine_type == 'pikafish':
            return self._pikafish_analyze(fen, depth, time_limit)
        else:
            return self._builtin_analyze(fen)

    def _builtin_analyze(self, fen):
        """内置简易局面评估 (棋子价值法)"""
        board = XQFenParser.parse(fen)
        score = self._evaluate_material(board)
        moves = self._generate_legal_moves(board)

        best_move = None
        best_score = float('-inf')
        best_line = []

        for move in moves[:50]:  # 限制搜索范围
            new_board = self._apply_move_simple(board, move)
            new_score = self._evaluate_material(new_board)
            # 如果走子方是黑方，取负值
            if board.get('side', 'w') == 'b':
                new_score = -new_score

            if new_score > best_score:
                best_score = new_score
                best_move = move

        return {
            'best_move': self._format_move_uci(best_move),
            'score': best_score,
            'depth': 1,
            'line': [self._format_move_uci(best_move)] if best_move else [],
        }

    def _format_move_uci(self, move):
        """格式化走子为UCI"""
        if not move:
            return '0000'
        fc, fr, tc, tr = move
        return f'{chr(ord("a")+fc)}{fr}{chr(ord("a")+tc)}{tr}'

    def _evaluate_material(self, board):
        """棋子价值评估"""
        values = {
            'K': 10000, 'k': 10000,  # 将/帅
            'R': 900, 'r': 900,       # 车
            'C': 450, 'c': 450,       # 炮
            'N': 400, 'n': 400,       # 马
            'B': 200, 'b': 200,       # 象/相
            'A': 200, 'a': 200,       # 士/仕
            'P': 100, 'p': 100,       # 兵/卒
        }

        score = 0
        grid = board.get('grid', [])
        for row in grid:
            for cell in row:
                if cell in values:
                    val = values[cell]
                    score += val if cell.isupper() else -val
        return score

    def _generate_legal_moves(self, board):
        """生成候选走法 (简化版)"""
        grid = board.get('grid', [])
        moves = []

        for r in range(10):
            for c in range(9):
                piece = grid[r][c]
                if piece == '.':
                    continue
                # 简化: 只生成周围1格的走法作为候选
                for dr, dc in [(-1,0),(1,0),(0,-1),(0,1),
                               (-1,-1),(-1,1),(1,-1),(1,1),
                               (-2,0),(2,0),(0,-2),(0,2)]:
                    nr, nc = r + dr, c + dc
                    if 0 <= nr < 10 and 0 <= nc < 9:
                        target = grid[nr][nc]
                        # 不能吃己方棋子
                        if target != '.' and target.isupper() == piece.isupper():
                            continue
                        moves.append((c, r, nc, nr))

        return moves

    def _apply_move_simple(self, board, move):
        """应用走子到棋盘"""
        fc, fr, tc, tr = move
        grid = [row[:] for row in board.get('grid', [])]
        piece = grid[fr][fc]
        grid[fr][fc] = '.'
        grid[tr][tc] = piece
        side = 'b' if board.get('side', 'w') == 'w' else 'w'
        return {'grid': grid, 'side': side}

    def _pikafish_analyze(self, fen, depth, time_limit):
        """对接皮卡鱼引擎"""
        # 需要安装 pikafish 引擎
        try:
            import subprocess
            import shutil

            engine_path = shutil.which('pikafish')
            if not engine_path:
                return {'error': 'pikafish引擎未找到，请安装: pip install pikafish'}

            proc = subprocess.Popen(
                [engine_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            commands = [
                'ucci\n',
                f'position fen {fen}\n',
                f'go depth {depth} movetime {time_limit}\n',
            ]

            output = ''
            for cmd in commands:
                proc.stdin.write(cmd)
                proc.stdin.flush()

            proc.stdin.write('quit\n')
            proc.stdin.flush()
            output = proc.stdout.read()

            # 解析引擎输出
            best_move = None
            score = 0
            for line in output.split('\n'):
                if line.startswith('bestmove'):
                    parts = line.split()
                    if len(parts) > 1:
                        best_move = parts[1]
                if 'score cp' in line:
                    score_match = re.search(r'score cp (-?\d+)', line)
                    if score_match:
                        score = int(score_match.group(1))

            return {
                'best_move': best_move,
                'score': score,
                'depth': depth,
                'engine': 'pikafish',
            }
        except Exception as e:
            return {'error': str(e)}


# ============================================================
# FEN解析器
# ============================================================

class XQFenParser:
    """中国象棋FEN解析器"""

    @staticmethod
    def parse(fen_str):
        """解析FEN字符串"""
        parts = fen_str.strip().split()
        if not parts:
            return None

        rows = parts[0].split('/')
        if len(rows) != 10:
            return None

        grid = []
        for row_str in rows:
            row = []
            for ch in row_str:
                if ch.isdigit():
                    row.extend(['.'] * int(ch))
                else:
                    row.append(ch)
            if len(row) != 9:
                return None
            grid.append(row)

        side = parts[1] if len(parts) > 1 else 'w'

        return {
            'fen': fen_str,
            'grid': grid,
            'side': side,
        }

    @staticmethod
    def to_string(grid, side='w'):
        """棋盘网格转FEN字符串"""
        fen_parts = []
        for row in grid:
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
        return '/'.join(fen_parts) + ' ' + side

    @staticmethod
    def display(grid):
        """可视化棋盘"""
        labels_cn = {
            'r': '车', 'n': '马', 'b': '象', 'a': '士',
            'k': '将', 'c': '炮', 'p': '卒',
            'R': '車', 'N': '馬', 'B': '相', 'A': '仕',
            'K': '帥', 'C': '砲', 'P': '兵', '.': '  ',
        }

        lines = []
        lines.append("  ┌────┬────┬────┬────┬────┬────┬────┬────┬────┐")

        for i, row in enumerate(grid):
            # 棋子行
            line = f"{9-i} │"
            for cell in row:
                display = labels_cn.get(cell, ' ?')
                line += f" {display}│"
            lines.append(line)

            if i < 9:
                lines.append("  ├────┼────┼────┼────┼────┼────┼────┼────┼────┤")

        lines.append("  └────┴────┴────┴────┴────┴────┴────┴────┴────┘")
        lines.append("    0    1    2    3    4    5    6    7    8  ")
        lines.append("    a    b    c    d    e    f    g    h    i  ")

        return '\n'.join(lines)


# ============================================================
# WebSocket消息协议解析
# ============================================================

class MessageParser:
    """WebSocket消息解析器 - 解析JCE编码的象棋协议"""

    # 可读的路由名称
    ROUTES = {
        'log-qqchess': '登录认证',
        'GGame': '游戏服务',
        'UpdateConfig.json': '配置更新',
    }

    @staticmethod
    def parse_header(raw):
        """解析消息头"""
        if len(raw) < 6:
            return None

        result = {
            'size': len(raw),
            'readable_strings': [],
            'route': None,
            'session_id': None,
            'has_json': False,
            'json_data': None,
        }

        # 提取所有可读字符串
        strings = re.findall(b'[\x20-\x7e]{3,}', raw)
        for s in strings:
            try:
                decoded = s.decode('ascii')
                result['readable_strings'].append(decoded)
            except:
                pass

        # 提取路由
        for route in MessageParser.ROUTES:
            for s in result['readable_strings']:
                if route in s:
                    result['route'] = route
                    break

        # 提取会话ID (32字符hex)
        for s in result['readable_strings']:
            if re.match(r'^[0-9A-Fa-f]{30,40}$', s):
                result['session_id'] = s
                break

        # 提取版本号
        for s in result['readable_strings']:
            if re.match(r'^V\d+\.\d+\.\d+\.\d+$', s):
                result['version'] = s

        # 提取JSON
        for s in result['readable_strings']:
            if s.startswith('{') and s.endswith('}'):
                try:
                    result['json_data'] = json.loads(s)
                    result['has_json'] = True
                except:
                    pass

        return result


# ============================================================
# 棋局状态追踪器
# ============================================================

class GameStateTracker:
    """追踪完整对局状态"""

    def __init__(self, my_camp=None):
        """
        my_camp: 'red' or 'black' — player's side (from nSeatID vs iFirstSide)
        """
        self.start_fen = "rnbakabnr/9/1c5c1/p1p1p1p1p/9/9/P1P1P1P1P/1C5C1/9/RNBAKABNR w"
        self.current_fen = self.start_fen
        self.move_history = []
        self.board = XQFenParser.parse(self.start_fen)
        self.move_count = 0
        self.game_started = False
        self.my_camp = my_camp  # 'red' or 'black'
        self._side_toggle = 'w'  # internal FEN side tracker (always alternates)

    def apply_move(self, from_col, from_row, to_col, to_row):
        """应用一步走子"""
        if not self.board:
            return None

        grid = [row[:] for row in self.board['grid']]

        # 检查坐标有效性
        if not (0 <= from_col < 9 and 0 <= from_row < 10 and
                0 <= to_col < 9 and 0 <= to_row < 10):
            return None

        piece = grid[from_row][from_col]
        if piece == '.':
            return None

        captured = grid[to_row][to_col]
        grid[from_row][from_col] = '.'
        grid[to_row][to_col] = piece

        side = 'b' if self.board['side'] == 'w' else 'w'
        self._side_toggle = side
        self.current_fen = XQFenParser.to_string(grid, side)
        self.board = XQFenParser.parse(self.current_fen)
        self.move_count += 1

        # Camp determination:
        # - In Chinese chess FEN, 'w' always goes first (Red), 'b' second (Black)
        # - The side_to_move tells us who just moved (BEFORE toggle, it was their turn)
        mover_camp = 'red' if self.board['side'] == 'w' else 'black'
        is_own = (self.my_camp == mover_camp) if self.my_camp else None

        move_record = {
            'num': self.move_count,
            'from': (from_col, from_row),
            'to': (to_col, to_row),
            'piece': piece,
            'captured': captured if captured != '.' else None,
            'fen': self.current_fen,
            'side': self.board['side'],
            'side_name': '红方' if mover_camp == 'red' else '黑方',
            'is_own': is_own,
        }
        self.move_history.append(move_record)

        return move_record

    def get_status(self):
        """获取当前状态"""
        return {
            'fen': self.current_fen,
            'move_count': self.move_count,
            'side': self.board['side'] if self.board else 'w',
            'last_move': self.move_history[-1] if self.move_history else None,
            'my_camp': self.my_camp,
        }

    def display(self):
        """显示当前棋盘"""
        if self.board:
            print(XQFenParser.display(self.board['grid']))
            side_name = '红方' if self.board['side'] == 'w' else '黑方'
            camp_str = ''
            if self.my_camp:
                camp_str = f' | 我方: {"红方" if self.my_camp == "red" else "黑方"}'
            print(f"  当前: {side_name}走棋 | 第{self.move_count + 1}回合{camp_str}")

    def get_move_uci_list(self):
        """获取UCI格式走子列表"""
        uci_list = []
        for m in self.move_history:
            fc, fr = m['from']
            tc, tr = m['to']
            uci_list.append(f'{chr(ord("a")+fc)}{fr}{chr(ord("a")+tc)}{tr}')
        return uci_list


# ============================================================
# 主程序
# ============================================================

def analyze_har(har_path):
    """离线分析HAR文件"""
    from har_analyzer import HARAnalyzer
    analyzer = HARAnalyzer(har_path)
    analyzer.load()
    analyzer.extract_websocket_messages()
    analyzer.analyze_protocol_structure()
    analyzer.extract_messages_by_type()
    analyzer.find_chess_games()
    analyzer.decode_move_coordinates()
    analyzer.generate_report()


def demo_mode():
    """演示模式 - 模拟一局象棋"""
    tracker = GameStateTracker()
    engine = ChessEngine('builtin')

    print("=" * 60)
    print("     QQ象棋实时分析器 - 演示模式")
    print("=" * 60)

    print("\n初始棋盘:")
    tracker.display()

    # 模拟一局经典开局
    demo_moves = [
        (4, 7, 4, 5),   # 1. 炮二平五 (当头炮)
        (1, 9, 2, 7),   # 2. 马8进7
        (1, 7, 2, 5),   # 3. 马二进三
        (4, 9, 4, 7),   # 4. 炮8平6
        (4, 6, 4, 5),   # 5. 车一进一
        (2, 7, 0, 5),   # 6. 马7进8 (弃马)
    ]

    move_names = [
        "炮二平五 (当头炮)",
        "马8进7",
        "马二进三",
        "炮8平6 (顺手炮)",
        "车一进一",
        "马7进8",
    ]

    print("\n" + "=" * 60)
    print("模拟对局:")
    print("=" * 60)

    for i, (move, name) in enumerate(zip(demo_moves, move_names)):
        fc, fr, tc, tr = move
        result = tracker.apply_move(fc, fr, tc, tr)

        piece_names = {
            'R': '红车', 'N': '红马', 'B': '红相', 'A': '红仕',
            'K': '红帅', 'C': '红炮', 'P': '红兵',
            'r': '黑车', 'n': '黑马', 'b': '黑象', 'a': '黑士',
            'k': '黑将', 'c': '黑炮', 'p': '黑卒',
        }

        if result:
            side = result.get('side_name', '?')
            is_own = result.get('is_own')
            owner_str = f' [我方]' if is_own else ('' if is_own is None else f' [对手]')
            piece = piece_names.get(result['piece'], result['piece'])

            print(f"\n第{i+1}步: {name}")
            print(f"  {piece} ({fc},{fr}) → ({tc},{tr}) [{side}走]{owner_str}")
            if result['captured']:
                captured = piece_names.get(result['captured'], result['captured'])
                print(f"  !! 吃掉: {captured}")

            # AI分析
            analysis = engine.analyze(tracker.current_fen)
            if analysis.get('best_move'):
                print(f"  [AI建议] 最佳走法: {analysis['best_move']} "
                      f"(评分: {analysis.get('score', 0)})")

            tracker.display()

    # 最终统计
    print("\n" + "=" * 60)
    print("对局统计:")
    print(f"  总步数: {tracker.move_count}")
    print(f"  走子列表(UCI): {' '.join(tracker.get_move_uci_list())}")
    print(f"  最终FEN: {tracker.current_fen}")

    print("\n" + "=" * 60)
    print("  实时分析器使用说明")
    print("=" * 60)
    print("""
[对接实时WebSocket数据]
  需要将WebSocket消息拦截后调用:
    tracker.apply_move(from_col, from_row, to_col, to_row)

[对接AI引擎]
  推荐引擎:
  1. 皮卡鱼 (Pikafish) - 开源, 棋力强
     pip install pikafish
  2. 象眼 (XiangEye) - 商业引擎, 分析功能丰富
  3. 使用内置简易评估器 (当前演示)

[下一步开发]
  1. 编写mitmproxy脚本来拦截WebSocket
  2. 解析JCE二进制协议获取走子数据
  3. 接入AI引擎进行实时分析
  4. 在GUI中显示推荐走法
""")


def analyze_session(session_path):
    """回放已保存的代理会话 —— 无需重新开局即可分析历史对局"""
    import os

    # ---- 文件发现 ----
    base = os.path.basename(session_path)
    dir_name = os.path.dirname(session_path) or '.'

    # 从文件名提取时间戳: qqchess_ws_raw_20260506_174656.json → 20260506_174656
    ts_match = re.search(r'(\d{8}_\d{6})', base)
    if ts_match:
        ts = ts_match.group(1)
        raw_path = os.path.join(dir_name, f'qqchess_ws_raw_{ts}.json')
        decoded_path = os.path.join(dir_name, f'qqchess_ws_decoded_{ts}.json')
        summary_path = os.path.join(dir_name, f'qqchess_summary_{ts}.json')
        moves_path = os.path.join(dir_name, f'qqchess_moves_{ts}.json')
        fens_path = os.path.join(dir_name, f'qqchess_fens_{ts}.json')
    else:
        raw_path = session_path
        decoded_path = session_path.replace('_raw_', '_decoded_')
        summary_path = session_path.replace('_raw_', '_summary_').replace('_decoded_', '_summary_')
        moves_path = session_path.replace('_raw_', '_moves_').replace('_decoded_', '_moves_')
        fens_path = session_path.replace('_raw_', '_fens_').replace('_decoded_', '_fens_')

    raw_data = None
    decoded_data = None

    for label, path in [('raw', raw_path), ('decoded', decoded_path)]:
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                if not content:
                    continue
                if label == 'raw':
                    raw_data = json.loads(content)
                else:
                    decoded_data = json.loads(content)
            except (json.JSONDecodeError, FileNotFoundError):
                pass

    if not decoded_data and not raw_data:
        print(f"[!] 找不到可解析的会话文件")
        print(f"    尝试过: {raw_path}")
        print(f"    尝试过: {decoded_path}")
        return

    # 用 decoded 做主力索引, raw 提供 base64 载荷
    if decoded_data:
        raw_by_seq = {}
        if raw_data:
            raw_by_seq = {m.get('seq'): m for m in raw_data if isinstance(m, dict)}
    else:
        decoded_data = raw_data
        raw_by_seq = {m.get('seq'): m for m in raw_data if isinstance(m, dict)}

    # ---- 消息分类 ----
    HEARTBEAT = {85000}
    LOGIN = {89055, 85001}
    LOBBY = {85005, 85006, 85008, 85018, 85031, 85039, 85047, 85053, 85060, 85067,
             85075, 85077, 85078, 85083, 85211, 85217, 85218, 85301,
             89040, 89043, 89050, 89054, 89061, 89085,
             89100, 89113, 89115, 89150, 89151, 89152,
             89300, 89504, 89505, 89513, 89621, 89671}
    BATTLE = {86001, 86003, 86004, 86005, 86006, 86028}
    GAME_CTRL = {85075, 85077}  # 对局开始/结束

    PHASE_LABELS = {
        89055: '握手',
        85001: '登录',
        85005: '进房',
        85018: '大厅信息',
        85031: '房间信息',
        85075: '对局通知',
        85077: '匹配/准备',
        86001: '战斗就绪',
        86004: '走子',
        86005: '棋盘状态',
        86006: '游戏事件',
        89113: '挑战/应战',
        89151: '匹配信息',
    }

    def classify(msg_id):
        if msg_id in HEARTBEAT: return 'heartbeat'
        if msg_id in LOGIN: return 'login'
        if msg_id in BATTLE: return 'battle'
        if msg_id in GAME_CTRL: return 'game_ctrl'
        if msg_id in LOBBY: return 'lobby'
        return 'other'

    # ---- 加载 summary 获取 session_key 和 camp ----
    summary = {}
    if os.path.exists(summary_path):
        try:
            with open(summary_path, 'r', encoding='utf-8') as f:
                summary = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            pass

    session_key_hex = summary.get('session_key')
    session_key = bytes.fromhex(session_key_hex) if session_key_hex else None
    uin = summary.get('uin')
    my_seat = summary.get('my_seat')
    i_first_side = summary.get('i_first_side')
    my_camp = summary.get('my_camp')

    # ---- 加载 moves 获取带 camp 的走子列表 ----
    moves_data = []
    if os.path.exists(moves_path):
        try:
            with open(moves_path, 'r', encoding='utf-8') as f:
                moves_data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            pass
    moves_by_seq = {m['seq']: m for m in moves_data if isinstance(m, dict)}

    # ---- 输出 ----
    print("=" * 70)
    print("   QQ象棋 会话回放")
    print("=" * 70)
    print(f"   会话文件: {os.path.basename(raw_path) if raw_data else os.path.basename(decoded_path)}")
    if ts_match:
        print(f"   时间戳:   {ts}")
    print(f"   总消息数: {len(decoded_data)}")
    sends = sum(1 for m in decoded_data if m.get('direction') == 'SEND')
    recvs = sum(1 for m in decoded_data if m.get('direction') == 'RECV')
    print(f"   发送: {sends}  接收: {recvs}")
    if session_key:
        print(f"   Session Key: {session_key_hex[:32]}... (已解密)")
    else:
        print(f"   Session Key: (未捕获 — 战斗消息加密)")
    if uin:
        print(f"   UIN: {uin}")
    moves_found = summary.get('moves', 0)
    print(f"   已提取走子: {moves_found}")
    my_seat = summary.get('my_seat')
    i_first_side = summary.get('i_first_side')
    my_camp = summary.get('my_camp')
    if my_camp:
        camp_label = '红方' if my_camp == 'red' else '黑方'
        print(f"   我方阵营: {camp_label} (seat={my_seat}, first_side={i_first_side})")
    elif my_seat is not None:
        print(f"   我方座位: seat={my_seat} (first_side未捕获)")
    game_count = summary.get('game_count', 0)
    if game_count > 0:
        print(f"   完成对局: {game_count} 局")
        per_game = summary.get('per_game_moves', {})
        if per_game:
            for gid, moves in per_game.items():
                print(f"     第{gid}局: {len(moves)} 步 — {' '.join(moves)}")
    print()

    # ---- 时间线 ----
    print("=" * 70)
    print("   消息时间线")
    print("=" * 70)
    print(f"   {'序号':>5s}  {'时间':>10s}  {'方向':>4s}  {'msgID':>6s}  {'大小':>5s}  {'加密':>4s}  {'说明'}")
    print(f"   {'-'*5}  {'-'*10}  {'-'*4}  {'-'*6}  {'-'*5}  {'-'*4}  {'-'*40}")

    phase_stats = defaultdict(lambda: {'count': 0, 'encrypted': 0, 'total_bytes': 0})
    battle_moves_sent = 0

    for m in decoded_data:
        seq = m.get('seq', 0)
        ts_str = m.get('time', '')[-12:] if m.get('time') else ''
        ts_str = ts_str[:12]  # HH:MM:SS.fff
        direction = m.get('direction', '?')
        direction_icon = '↑' if direction == 'SEND' else '↓'
        msg_id = m.get('msgID', 0)
        encrypted = m.get('encrypted', False) or m.get('iFlag', 0) == 1
        enc_str = 'E' if encrypted else ' '

        # 从 raw 获取精确大小
        raw = raw_by_seq.get(seq, {})
        size = raw.get('size', 0)

        cat = classify(msg_id)
        phase_stats[cat]['count'] += 1
        phase_stats[cat]['total_bytes'] += size
        if encrypted:
            phase_stats[cat]['encrypted'] += 1

        label = PHASE_LABELS.get(msg_id, '')
        if not label:
            label = {
                'login': '登录流程', 'lobby': '大厅', 'battle': '战斗',
                'game_ctrl': '游戏控制', 'heartbeat': '心跳', 'other': ''
            }.get(cat, '')

        # 特殊标记
        if msg_id == 86004 and direction == 'SEND':
            battle_moves_sent += 1
            label = f'走子 #{battle_moves_sent}'
            if my_camp:
                label += ' [我方]'
        elif msg_id == 86004 and direction == 'RECV':
            if my_camp:
                label += ' [对手]'
        elif msg_id == 86001:
            if i_first_side is not None:
                label += f' (红先: seat={i_first_side})'
        elif msg_id == 85075:
            label = '对局结束' if direction == 'RECV' and size < 200 else '对局通知'

        line = (f"   {seq:>5d}  {ts_str:>10s}  "
                f"{direction_icon:>2s} {direction:>2s}  "
                f"{msg_id:>6d}  {size:>5d}B  [{enc_str}]  {label}")
        print(line)

    # ---- 汇总 ----
    print()
    print("=" * 70)
    print("   会话统计")
    print("=" * 70)
    for cat in ['heartbeat', 'login', 'lobby', 'battle', 'game_ctrl']:
        s = phase_stats.get(cat, {})
        if not s.get('count'):
            continue
        cat_name = {'heartbeat': '心跳', 'login': '登录', 'lobby': '大厅/社交',
                    'battle': '战斗', 'game_ctrl': '游戏控制'}.get(cat, cat)
        print(f"   {cat_name:10s}: {s['count']:>4d} 条  "
              f"加密 {s['encrypted']:>3d} / {s['count']:>3d}  "
              f"流量 {s['total_bytes']:>6d} B")

    print()
    print(f"   [提示] 使用 --session 可反复回放，无需重新开局")
    if not session_key:
        print(f"   [提示] Session Key 未捕获，战斗走子不可见。")
        print(f"          完善 TEA-CBC 密钥派生后可解密离线数据。")



def main():
    parser = argparse.ArgumentParser(
        description='QQ象棋实时棋局分析器'
    )
    parser.add_argument('--har', type=str, help='HAR文件路径 (离线分析)')
    parser.add_argument('--session', type=str, help='回放已保存的代理会话JSON文件')
    parser.add_argument('--demo', action='store_true', help='演示模式')
    parser.add_argument('--proxy', action='store_true', help='启动WebSocket代理')

    args = parser.parse_args()

    if args.har:
        analyze_har(args.har)
    elif args.session:
        analyze_session(args.session)
    elif args.proxy:
        print("[!] WebSocket代理模式需要安装mitmproxy: pip install mitmproxy")
        print("[!] 代理脚本模板见 xq_ws_proxy.py")
    elif args.demo:
        demo_mode()
    else:
        # 默认演示模式
        demo_mode()


if __name__ == '__main__':
    main()
