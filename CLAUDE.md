# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Reverse-engineering toolkit for Tencent QQ Chess (天天象棋) H5 game's network protocol. Captures, decodes, and analyzes the WebSocket communication between the Cocos Creator H5 client and Tencent's servers.

## Commands

```bash
# Offline HAR analysis — extract WS messages, moves, FENs from a captured session
python har_analyzer.py data/h5login.qqchess.qq.com.har

# Live proxy — mitmproxy addon intercepting QQ Chess traffic in real time
mitmweb --listen-port 8888 -s xq_ws_proxy.py

# Decode individual base64 JCE messages
python xq_decode.py <base64_string>
python xq_decode.py --interact        # interactive REPL
python xq_decode.py --file msgs.txt   # batch decode

# Chess analyzer with AI engine integration
python xq_analyzer.py --har data/h5login.qqchess.qq.com.har
python xq_analyzer.py --demo           # simulated game demo
python xq_analyzer.py --proxy          # proxy mode

# Download the QQ Chess H5 client source from Tencent CDN
python download_qqchess.py

# Electron wrapper — one-click proxy + game launcher (no manual Windows proxy needed)
cd electron-app && npm start
```

Dependencies (no `requirements.txt`): `mitmproxy`, `requests`. Install manually.

## Architecture

### Protocol stack (bottom-up)

1. **Transport**: WebSocket binary messages on `wss://wxlogin.qqchess.qq.com:443`
2. **Framing**: `[2B big-endian length][magic][route string][JCE body]`
   - SEND magic: `01 10 cf XX YY` (5 bytes — first 3 fixed, last 2 = session identifier)
   - RECV magic: `0c XX YY` (3 bytes — first 1 fixed, last 2 = session identifier)
   - Session bytes vary per connection (QQ login: `10 01`, WeChat login: `1c 2c`, etc.)
   - Implementation: `unwrap_ws()` in `xq_modules/move_utils.py` uses prefix matching (not exact match)
3. **Encryption**: TEA-CBC (16 rounds, delta=0x9E3779B9), 128-bit key, with random head/tail padding. `iFlag & 1` on each message indicates encrypted.
4. **Serialization**: JCE (Jce Communication Encoding), Tencent's proprietary binary format — similar to Protobuf with tagged fields
5. **Session key derivation**: Login response 85001 delivers `sSecKey` + `uUin`. Derive: `sessionKey = TEA_decrypt(hexToBytes(sSecKey), pad16(str(uUin)))`. WeChat login uses the same derivation — `uUin` is always from TResponseLogin field 1, never from OpenID.
6. **Board state**: Chinese Chess FEN (10 rows × 9 cols, uppercase=red, lowercase=black)

#### QQ vs WeChat login (TResponseLogin variants)

The server sends one of two TResponseLogin structures depending on login type:

| Field | QQ variant | WeChat variant |
|-------|-----------|---------------|
| 0 | iResultID | iResultID |
| 1 | **uUin** | **uUin** |
| 10 | **sSecKey** | bShowButton (boolean) |
| 11 | banEndTime | **sSecKey** |
| 15 | iRoundID | sWXGameSessionKey |

Key derivation is identical for both: `RFe(sSecKey, uUin)` — `str(uin)` padded to 16 bytes as TEA key.

`parse_login()` in `xq_modules/protocol.py` uses raw-body byte scanning (not sequential JCE reads) to find sSecKey at either field 10 or 11, avoiding JCE reader position corruption from type mismatches.

### Coordinate systems & conversion

Three coordinate spaces exist, and every move must be converted correctly between them:

| System | Rows | Columns | Description |
|--------|------|---------|-------------|
| **Raw bytes** (protocol) | 1-indexed, 1–10 | 1-indexed, 1–9 (left→right: a=1..i=9) | Server's binary encoding in vecMsgBody |
| **Raw UCI** (0-indexed) | 0-indexed, 0–9 | a–i (left→right) | `_raw_move()` output — server's original intent, no interpretation |
| **FEN** (target) | 0–9, Red 5–9 bottom, Black 0–4 top | a=left, i=right | Canonical board coordinate; used by Pikafish engine and demo board rendering |

**Conversion chain**: Raw bytes → `_raw_move()` → Raw UCI → `game_to_fen()` / `rawToFenUci()` → FEN

#### Why conversion is non-trivial

The game protocol encodes moves from the **mover's perspective** (mover's own pieces at rows 0–4), using Chinese chess column numbering (right-to-left: 九→一). But `_raw_move()` maps columns left-to-right (a=1, b=2, ..., i=9). This creates a column mismatch: a Chinese column 八(h) may be encoded as raw byte 2 (b).

Additionally, the server sometimes pre-flips rows (Red at 5–9, matching FEN) while leaving columns in raw encoding. The result: a given move can arrive in one of two **formats**, distinguishable by the first move's `from_row`:

#### Format locking (final solution, 2026-05-10)

The format is detected once on the first move of a game and **locked for the entire game**. All moves within a game use the same operation — `mover_camp` (red/black) does NOT affect which operation to apply.

| Format | First move `from_row` | Operation (all moves) |
|--------|----------------------|----------------------|
| **A** | ≤ 4 | **Flip rows**: `fr = 9 - fr`, `tr = 9 - tr` |
| **B** | > 4 | **Mirror columns**: `fc = 8 - fc`, `tc = 8 - tc` |

- **Format A**: Both red and black moves → flip rows (columns unchanged)
- **Format B**: Both red and black moves → mirror columns (rows unchanged)

This replaced the previous "four cases" per-move `from_row` approach, which incorrectly split red/black into different operations. Empirical testing confirmed: the format is a property of the **game session**, not of individual moves. The mover's camp does not determine which operation to use.

#### Why the four-cases approach was wrong

The earlier analysis (cases #1-#4 below, now superseded) assumed `mover_camp` + `from_row` jointly determine the operation. This led to format A having "Red→flip rows, Black→mirror columns" and format B the reverse. But actual game data showed that within a format-A game, Black moves crossing the river also need flip rows (not mirror columns). The format is simpler than originally thought: **one game, one operation**.

<details>
<summary>Superseded: the four cases (kept for historical reference)</summary>

| # | Mover | from_row | Meaning | Operation | Example |
|---|-------|----------|---------|-----------|---------|
| 1 | Red | ≤4 | Red's perspective (Red at 0–4) | **Flip rows** | h0g2 → h9g7 |
| 2 | Red | >4 | Rows already FEN, columns raw | **Mirror columns** | b9c7 → h9g7 |
| 3 | Black | ≤4 | Black's perspective, columns raw | **Mirror columns** | h0g2 → b0c2 |
| 4 | Black | >4 | Red's perspective (Black at 5–9) | **Flip rows** | g6g5 → g3g4 |

</details>

#### Implementation locations

- **`xq_modules/coord_conv.py`**: `game_to_fen(uci, mover_camp, fmt)` + `detect_format(first_uci)` — format-locked conversion with `fmt='A'` (all flip rows) or `fmt='B'` (all mirror columns).
- **`electron-app/renderer.js`**: `rawToFenUci(uci, userSide, isSent)` — same format-locked logic, uses `_format` detected from proxy `[CAMP]` log line.
- **`electron-app/renderer.js`**: `bx(c)`, `by(r)` — map FEN coordinates to canvas pixels. For Black user, applies 180° rotation (`8-c` for columns, `9-r` for rows) so Black pieces appear at bottom.

#### Key pitfalls discovered

1. **Echo doubling**: RECV messages that echo the user's own SEND must be filtered BEFORE conversion, because `mover_camp` differs (SEND=mover=self, RECV appears as opponent). The proxy's `[ECHO]` filter compares raw UCI before any conversion.
2. **Format locking > per-move from_row**: The format is a property of the game session, not individual moves. `from_row` varies naturally (pieces cross the river), but the conversion operation does NOT. First move's `from_row` determines the format; lock it and apply the same operation to every move regardless of mover camp or position.
3. **Dual conversion danger**: Never chain two conversions. The `>>> [MOVE]` log line always carries Raw UCI (server's original). Only the renderer's `rawToFenUci()` converts it to FEN for board application. The `_rawUci` field preserves the raw value for the "游戏" display line.
4. **SEND vs RECV format consistency**: Both SEND and RECV moves in the same game use the same format. The earlier hypothesis that SEND is "always format A" was incorrect — the format is determined by the game session, not by message direction.

### Core modules

| File | Role |
|---|---|
| `har_analyzer.py` | Parses `.har` HTTP Archive files, extracts WebSocket binary messages, classifies by direction (send/recv), runs the JCE decoder on each message |
| `xq_decode.py` | Standalone JCE binary decoder: scans for FEN strings, move coordinates (0-8 col, 0-9 row), message routes, and string fields inside JCE-tagged structures. Accepts base64 input |
| `xq_ws_proxy.py` | mitmproxy addon (`QQChessWSProxy` class) — hooks `websocket_message` events, decodes in real time, saves 5 timestamped JSON files per session (raw, decoded, moves, fens, summary) |
| `xq_analyzer.py` | Chess-specific layer: `XQFenParser` for FEN parsing, `GameStateTracker` for board state, `ChessEngine` for AI engine integration. Also mirrors HAR/proxy analysis entry points |
| `download_qqchess.py` | Fetches the H5 client (`index.html` + `index.ec248.js`, ~10 MB) from Tencent's CDN |

### Message ID ranges

- 85001-85504: lobby/room
- 86001-86028: battle (move relay, game events)
- 89012-89213: social
- 89301-89757: system

The HAR file (`data/h5login.qqchess.qq.com.har`, 127 MB) is the primary captured data source.

### Project structure

```
├── xq_ws_proxy.py          # mitmproxy addon (core)
├── har_analyzer.py          # HAR offline parser
├── xq_decode.py             # JCE binary decoder
├── xq_analyzer.py           # Chess analysis + AI engine
├── tea_decrypt.py           # TEA-CBC decryptor
├── download_qqchess.py      # CDN client downloader
├── _find_key.py             # sSecKey extractor
├── _fix_session.py          # Session key re-derivation
├── _brute_key.py            # Brute-force key discovery
├── electron-app/            # Electron wrapper (auto proxy + game launcher)
├── data/
│   ├── h5login.qqchess.qq.com.har
│   └── sessions/            # Proxy session output (qqchess_*.json)
├── qqchess_src/             # Downloaded H5 client source
├── docs/                    # Analysis documentation
└── engines/                 # Chess engines (e.g. Pikayu)
```

### Generated data files

Each proxy session produces 5 files saved to `data/sessions/`: `qqchess_ws_raw_*.json`, `qqchess_ws_decoded_*.json`, `qqchess_moves_*.json`, `qqchess_fens_*.json`, `qqchess_summary_*.json`. These are gitignored artifacts — do not commit them.

## Key constraints

- No build system, no tests, no linting config, no `requirements.txt` — raw Python scripts
- FEN detection from decoded messages is unreliable (regex-based search against binary payload yields mostly empty results)
- Move coordinate detection has false positives from fixed protocol fields
- A full Python TEA-CBC decryptor matching the JS implementation from `docs/文件分析.md` has not yet been built
