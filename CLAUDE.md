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
2. **Framing**: `[varint length][0x0c1001 magic][session_id hex][route string][JCE body]`
3. **Encryption**: TEA-CBC (16 rounds, delta=0x9E3779B9), 128-bit key, with random head/tail padding. `iFlag & 1` on each message indicates encrypted.
4. **Serialization**: JCE (Jce Communication Encoding), Tencent's proprietary binary format — similar to Protobuf with tagged fields
5. **Session key derivation**: Login response 85001 delivers `sSecKey` + `uUin`. Derive: `sessionKey = TEA_decrypt(hexToBytes(sSecKey), pad16(str(uUin)))`
6. **Board state**: Chinese Chess FEN (10 rows × 9 cols, uppercase=red, lowercase=black)

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
