"""
QQ象棋 WebSocket 拦截脚本 (mitmproxy addon) — 完整版 v2
=====================================================
JCE 解析 → 密钥派生 → TEA-CBC 解密 → 走子提取

启动: mitmdump --listen-port 8888 -s xq_ws_proxy.py

模块拆分:
  xq_modules/tea_crypto.py   — TEA-CBC 加解密 + 会话密钥派生
  xq_modules/jce_parser.py   — JCE 二进制解析器
  xq_modules/protocol.py     — TPackage/TMsg/登录/游戏事件 协议解析
  xq_modules/move_utils.py   — WS帧剥离 + vecMsgBody 走子提取
  xq_modules/coord_conv.py   — raw UCI → FEN UCI 坐标转换 + 格式锁定
"""

import sys
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

import json
import re
import os
import base64
from datetime import datetime

from mitmproxy import ctx

from xq_modules.tea_crypto import tea_zjb_decrypt, derive_session_key
from xq_modules.jce_parser import JceIn
from xq_modules.protocol import (parse_pkg, parse_login, parse_game_event,
                                   parse_request_play, parse_game_context)
from xq_modules.move_utils import unwrap_ws, extract_fen, find_moves_in_vec
from xq_modules.coord_conv import game_to_fen, detect_format


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
        self._format = None       # 'A' or 'B', locked on first move per game
        self._last_sent_uci = None  # raw UCI of last SEND, for echo filtering
        self._inject_template = None   # raw WS frame of last SEND (auto-play template)
        self._inject_old_coords = None # 4B 1-indexed coords in template

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

        # 检查自动走子注入（在消息处理之前，避免模板被覆盖）
        self._check_inject(flow, raw)

        ts = datetime.now().isoformat()

        # 保存原始消息
        self.raw.append({
            'seq': self.total, 'time': ts, 'direction': direction,
            'size': len(raw), 'base64': base64.b64encode(raw).decode(),
        })

        # 剥离 WS 帧
        d, jce_data = unwrap_ws(raw)
        if not d:
            ctx.log.info(f"[?] #{self.total:04d} {len(raw):5d}B  unwrap_ws failed  head={raw[:16].hex()}")
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
                ssec = login['sSecKey'] or login['sWXGameSessionKey']
                uin = login['uUin']
                iOpenPlatType = pkg.get('iOpenPlatType', 0)
                plat_label = {0: '?', 1: 'WX', 2: 'QQ', 3: 'PC'}.get(iOpenPlatType, str(iOpenPlatType))
                ctx.log.info(
                    f"  [LOGIN] plat={plat_label} uUin={uin}  "
                    f"sSecKey={'ok' if ssec else 'MISSING'}"
                )
                if ssec:
                    self.session_key = derive_session_key(ssec, uin)
                    self.uin = uin
                    if self.session_key:
                        ctx.log.info(f"  [KEY] session_key={self.session_key.hex()}")
                    else:
                        ctx.log.warn(f"  [KEY] 派生失败 (ssec={ssec[:16]}... uin={uin})")
            except Exception as e:
                ctx.log.error(f"  [LOGIN] 解析失败: {e}")

        # ---- 解密 ----
        plain = None
        if encrypted and self.session_key and body:
            try:
                plain = tea_zjb_decrypt(body, self.session_key)
            except Exception as e:
                ctx.log.error(f"  [DEC] 失败: {e}")

        # ---- 游戏上下文 (86001) — 新对局检测 (tableID变化=新一局) ----
        check_body_ctx = plain if encrypted else body
        if msg_id == 86001 and not m.from_client and check_body_ctx:
            try:
                ctx2 = parse_game_context(check_body_ctx)
                table_id = ctx2.get('iFirstSide', 0)  # field2 is actually tableID
                ctx.log.info(
                    f"  [86001] tableID={table_id}  "
                    f"qm={ctx2.get('qm')}  hxb={ctx2.get('hxb')}"
                )
                if not hasattr(self, '_last_table_id'):
                    self._last_table_id = None
                table_changed = self._last_table_id is not None and self._last_table_id != table_id
                if table_changed:
                    if self._game_active:
                        self._end_game('new_table')
                    self._last_table_id = table_id
                    self._on_game_begin(self.total)
                elif self._last_table_id is None or not self._game_active:
                    self._last_table_id = table_id
                    self._on_game_begin(self.total)
                # else: same table, game active = reconnection (no state change)
            except Exception as e:
                ctx.log.warn(f"  [CTX] 解析失败: {e}")

        # ---- 游戏事件 (86004 走子, 86005/86011 服务器事件) ----
        check_body = plain if encrypted else body
        if msg_id in (86004, 86005, 86011) and check_body:
            try:
                if msg_id == 86004:
                    ev = parse_request_play(check_body)
                    if not self._game_active:
                        self._on_game_begin(self.total)
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
                        is_echo = direction == 'RECV' and best['uci'] == self._last_sent_uci
                        if is_echo:
                            ctx.log.info(f"  [ECHO] skip {best['uci']}")
                        if direction == 'SEND' and msg_id == 86004:
                            self._last_sent_uci = best['uci']
                            self._inject_template = raw
                            self._inject_old_coords = bytes([
                                best['from'][0] + 1, best['from'][1] + 1,
                                best['to'][0] + 1, best['to'][1] + 1,
                            ])

                        if not is_echo:
                            self.move_n += 1
                            event_id = ev.get('nEventID', ev.get('nCmdID', 0))
                            move_seat = ev.get('nSeatID', -1)
                            if self.my_camp is None and self.move_n == 1:
                                self.my_camp = 'red' if direction == 'SEND' else 'black'
                                self._format = detect_format(best['uci'])
                                ctx.log.info(f"  [CAMP] first move is {direction} → {self.my_camp}  fmt={self._format}")

                            is_own = (direction == 'SEND') if self.my_camp else None

                            if self.my_camp:
                                opp_camp = 'red' if self.my_camp == 'black' else 'black'
                                mover_camp = self.my_camp if is_own else opp_camp
                            else:
                                mover_camp = None

                            board_uci = game_to_fen(best['uci'], mover_camp, self._format)
                            rec = {
                                'num': self.move_n, 'seq': self.total,
                                'time': ts, 'direction': direction,
                                'msgID': msg_id, 'eventID': event_id,
                                'from': best['from'], 'to': best['to'],
                                'uci': best['uci'],
                                'board_uci': board_uci,
                                'offset': best['offset'],
                                'vec_hex': inner.hex(),
                                'seat': move_seat,
                                'camp': mover_camp,
                                'is_own': is_own,
                                'format': self._format,
                            }
                            self.moves.append(rec)
                            self._save()
                            flip_mark = f' [{self._format}]' if self._format else ''
                            if board_uci != best['uci']:
                                ctx.log.info(f"  [RAW] {best['uci']}")
                            own_tag = ' (我方)' if is_own else (' (对手)' if is_own is False else '')
                            ctx.log.info(f"  >>> [{move_label} #{self.move_n}] {best['uci']}{own_tag} <<<")
            except Exception as e:
                ctx.log.warn(f"  [GAME] 解析失败: {e}")

        # ---- 对局结束检测 ----
        if not m.from_client and self._check_game_end(msg_id, direction, encrypted, len(body)):
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

    def _check_inject(self, flow, raw):
        """检查 _inject.json, 有则替换模板坐标并注入到服务器."""
        import json as _json
        sessions_dir = os.environ.get('QQCHESS_DATA_DIR',
                        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'sessions'))
        inject_path = os.path.join(sessions_dir, '_inject.json')
        if not os.path.exists(inject_path):
            return
        try:
            with open(inject_path, 'r', encoding='utf-8') as f:
                data = _json.load(f)
            os.remove(inject_path)
        except Exception as e:
            ctx.log.warn(f"[INJECT] read error: {e}")
            return

        uci = data.get('uci', '')
        if not uci or not self._inject_template:
            ctx.log.warn(f"[INJECT] missing uci or template")
            return

        cols = 'abcdefghi'
        try:
            fc = cols.index(uci[0]) + 1
            fr = int(uci[1]) + 1
            tc = cols.index(uci[2]) + 1
            tr = int(uci[3]) + 1
        except (ValueError, IndexError):
            ctx.log.warn(f"[INJECT] bad uci: {uci}")
            return
        new_coords = bytes([fc, fr, tc, tr])

        # Replace LAST occurrence (coords are near end of template; first occurrence
        # might be a false positive in JCE headers or other fields)
        idx = self._inject_template.rfind(self._inject_old_coords)
        if idx < 0:
            ctx.log.warn(f"[INJECT] coords {self._inject_old_coords.hex()} not found in template")
            return
        modified = (self._inject_template[:idx] + new_coords +
                     self._inject_template[idx + 4:])
            return

        ctx.log.info(f"[INJECT] {uci}  {self._inject_old_coords.hex()}→{new_coords.hex()}")
        try:
            flow.inject_message(flow.server_conn, modified)
            ctx.log.info(f"[INJECT] OK")
        except Exception as e:
            ctx.log.error(f"[INJECT] failed: {e}")

    def websocket_end(self, flow):
        if not flow.metadata.get('ok'):
            return
        if self.moves:
            raw_moves = ' '.join(m.get('uci', '') for m in self.moves)
            board_moves = ' '.join(m.get('board_uci', '') for m in self.moves)
            ctx.log.info(f"[QQ象棋] 走子(协议): {raw_moves}")
        ctx.log.info(f"[QQ象棋] 断开 总={self.total} SEND={self.sends} RECV={self.recvs} moves={len(self.moves)}")
        if self.moves:
            ctx.log.info(f"[QQ象棋] 走子: {' '.join(m['uci'] for m in self.moves)}")
        self._save(force=True)

    def done(self):
        self._save()

    def _on_game_begin(self, seq):
        self._game_active = True
        self._game_start_seq = seq
        self._consecutive_86006 = 0
        self._format = None
        self._last_sent_uci = None
        self.move_n = 0
        ctx.log.info(f"[GAME] ====== 对局 #{self.game_count + 1} 开始 (seq={seq}) ======")

    def _on_game_end(self, reason):
        self.game_count += 1
        moves_in_game = sum(1 for m in self.moves if m.get('game_idx') == self.game_count - 1
                            if 'game_idx' in m) if self.game_count > 1 else self.move_n
        ctx.log.info(
            f"[GAME] ====== 对局 #{self.game_count} 结束 "
            f"(moves={self.move_n}, reason={reason}) ======"
        )
        self.move_n = 0
        self.my_seat = None
        self.i_first_side = None
        self.my_camp = None
        self._game_active = False
        self._consecutive_86006 = 0

    def _check_game_end(self, msg_id, direction, encrypted, body_size):
        if not self._game_active:
            return

        if msg_id == 86005 and direction == 'RECV' and not encrypted:
            pass

        if msg_id == 86006 and direction == 'RECV':
            self._consecutive_86006 += 1
            if self._consecutive_86006 >= 2 and self.move_n > 0:
                ctx.log.info(f"  [END] 检测到连续 86006 事件 (对局结算)")
                self._end_game('86006_settle')
                return True

        if msg_id == 85075 and direction == 'RECV' and not encrypted and body_size < 200:
            if self._game_active:
                self._end_game('85075_end_notify')
            return True

        if msg_id not in (86005, 86006, 86004):
            self._consecutive_86006 = 0

        return False

    def _end_game(self, reason):
        game_idx = self.game_count
        for m in self.moves:
            if 'game_idx' not in m:
                m['game_idx'] = game_idx
        self._on_game_end(reason)

    def _save(self, force=False):
        if not force:
            now = datetime.now()
            if hasattr(self, '_last_save') and (now - self._last_save).total_seconds() < 3:
                return
            self._last_save = now
        if not self.raw:
            return
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        out = os.environ.get('QQCHESS_DATA_DIR',
               os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'sessions'))
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
        game_moves = {}
        for m in self.moves:
            gid = m.get('game_idx', 0)
            game_moves.setdefault(gid, []).append(m.get('board_uci', m.get('uci', '')))

        sm = {
            'start': self.st.isoformat(), 'end': datetime.now().isoformat(),
            'total': self.total, 'sends': self.sends, 'recvs': self.recvs,
            'moves': len(self.moves),
            'move_list': [m.get('board_uci', m.get('uci', '')) for m in self.moves],
            'session_key': self.session_key.hex() if self.session_key else None,
            'uin': self.uin,
            'my_seat': self.my_seat,
            'i_first_side': self.i_first_side,
            'my_camp': self.my_camp,
            'game_count': self.game_count,
            'per_game_moves': {str(k): v for k, v in game_moves.items()},
            'format': self._format,
        }
        sp = os.path.join(out, f'qqchess_summary_{ts}.json')
        with open(sp, 'w') as f:
            json.dump(sm, f, ensure_ascii=False, indent=2)
        ctx.log.info(f"[SAVE] qqchess_summary_{ts}.json")


addons = [QQChessWSProxy()]
