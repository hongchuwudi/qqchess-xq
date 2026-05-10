# 天天象棋网络协议分析器

天天象棋 (QQ Chess) H5 版网络协议逆向工程工具套件。支持实时抓包、协议解码、棋局分析、AI 引擎辅助走子，并提供一键启动的 Electron 封装。

> ⚠️ **免责声明**：本项目**仅供技术研究和学习参考**，禁止用于任何商业用途或破坏游戏公平性的行为。使用者需自行遵守腾讯天天象棋的用户协议。

---

## 目录

- [功能特性](#功能特性)
- [目录结构](#目录结构)
- [环境要求](#环境要求)
- [快速开始](#快速开始)
- [使用指南](#使用指南)
- [打包发布](#打包发布)
- [技术架构](#技术架构)
- [开源许可](#开源许可)

---

## 功能特性

- **WebSocket 实时抓包** — 基于 mitmproxy，捕获天天象棋 H5 客户端与服务端的全部通信
- **JCE 协议解码** — 完整还原腾讯 JCE 序列化协议，支持全部 14 种数据类型
- **TEA-CBC 加解密** — 完整还原客户端加密算法，含密钥派生、加密、解密全部流程
- **走子实时提取** — 自动检测走子消息、提取 UCI 坐标、记录对局棋谱
- **棋盘状态可视化** — Canvas 渲染中国象棋棋盘，支持红方/黑方翻转、中文记谱
- **AI 引擎集成** — 内置皮卡鱼引擎，实时局面评估、最佳走法推荐、自动走子
- **断连恢复** — 对局中意外断连，自动从会话文件回放走子，不丢失记录
- **一键启动** — Electron 封装，自动配置代理 + 启动抓包 + 加载游戏
- **跨平台打包** — 支持 Windows (安装版/绿色版)、macOS、Linux

---

## 目录结构

```
qqchess-xq/
├── xq_ws_proxy.py              # [核心] mitmproxy 抓包 addon (800+ 行)
├── xq_decode.py                # JCE 二进制手动解码器 (交互式)
├── xq_analyzer.py              # 棋局分析 + AI 引擎对接 (Python 版)
├── har_analyzer.py             # HAR 离线文件分析器
├── tea_decrypt.py              # [实验版] TEA 解密器
├── download_qqchess.py         # 下载天天象棋 H5 客户端源码
├── _find_key.py                # [工具] 从登录消息提取 sSecKey
├── _fix_session.py             # [工具] 修复/回放已保存的会话
├── _brute_key.py               # [工具] 暴力尝试会话密钥
├── electron-app/               # Electron 桌面应用
│   ├── main.js                 #   主进程 (mitmproxy 管理 + IPC)
│   ├── renderer.js             #   渲染进程 (棋盘 + 日志 + 引擎 UI)
│   ├── pikafish-bridge.js      #   皮卡鱼引擎 UCCI 协议桥接
│   ├── preload.js              #   安全桥接 (contextBridge)
│   ├── index.html              #   控制台界面
│   ├── style.css               #   样式
│   └── package.json            #   依赖 + 打包配置
├── engines/                    # 象棋引擎 (需自行下载)
│   └── pikayu-YYYYMMDD/        #   皮卡鱼 (Pikafish) — 自动匹配最新日期
├── data/
│   ├── h5login.qqchess.qq.com.har  # 127 MB HAR 抓包样本
│   └── sessions/                   # 代理会话输出 (自动生成)
├── qqchess_src/                # 下载的游戏客户端源码
├── docs/                       # 分析文档
│   ├── 文件分析.md              #   JS 客户端分析记录
│   └── RESEARCH.md              #   完整技术研究报告
├── CLAUDE.md                   # 项目说明书 (AI 开发用)
└── README.md                   # 本文档
```

---

## 环境要求

### 运行 Electron 桌面应用（推荐）

| 依赖 | 说明 | 安装方式 |
|------|------|---------|
| **Node.js** | ≥ 18.x | https://nodejs.org |
| **Python** | ≥ 3.9 | https://www.python.org |
| **mitmproxy** | ≥ 10.x | `pip install mitmproxy` |

确保 `python` 和 `mitmdump` 在系统 PATH 中可用。

### 运行 Python 脚本（命令行）

```bash
pip install mitmproxy requests
```

---

## 快速开始

### 1. 克隆项目

```bash
git clone <repo-url>
cd qqchess-xq
```

### 2. 安装依赖

```bash
cd electron-app
npm install
```

### 3. 启动应用

```bash
npm start
```

应用启动后会自动：
1. 检测 Python + mitmproxy 环境
2. 启动 mitmdump 代理（端口 8888）
3. 打开天天象棋 H5 客户端
4. 点击「启动游戏」开始

### 4. 命令行方式（不使用 Electron）

```bash
# 启动 mitmproxy 抓包
mitmdump --listen-port 8888 -s xq_ws_proxy.py --ssl-insecure

# 手动设置 Windows 代理: 127.0.0.1:8888
# 浏览器打开 https://h5login.qqchess.qq.com/

# 或使用 mitmproxy Web 界面
mitmweb --listen-port 8888 -s xq_ws_proxy.py --ssl-insecure
```

---

## 使用指南

### 主界面说明

```
┌─────────────────────────────────────────────────────┐
│  [启动代理] [重启代理] [启动游戏]                    │
│  [清空日志] [分析局面] [自动走子] [翻转棋盘]         │
│  [设置]                                              │
├────────────────┬────────────────────────────────────┤
│  状态栏         │  走子列表 (红方 / 黑方)            │
│  红方/黑方      │  皮卡鱼引擎分析面板                │
│  对局统计       │  bestmove / score / depth / pv     │
│  数据用量       │                                    │
├────────────────┴────────────────────────────────────┤
│  中国象棋棋盘 (Canvas)                               │
│  - 绿色光晕+箭头 = 上一步走子                        │
│  - 琥珀色方块+箭头 = 引擎推荐走法                    │
├─────────────────────────────────────────────────────┤
│  实时日志 (可按类型过滤)                             │
└─────────────────────────────────────────────────────┘
```

### 操作说明

| 操作 | 说明 |
|------|------|
| **启动游戏** | 在 webview 中加载天天象棋 H5，自动走代理 |
| **分析局面** | 手动触发皮卡鱼分析当前棋盘 |
| **自动走子** | 对手走完后，引擎自动选择最佳招法并注入 |
| **翻转棋盘** | 红方/黑方视角切换 |
| **清空日志** | 清空所有日志和走子记录 |
| **过滤日志** | 勾选「走子」或「消息」过滤日志类型 |

### 首次启动设置

首次启动会弹出设置面板，检测：
- Python 是否安装
- mitmproxy 是否安装

如果检测失败，按照引导安装即可。也可以选择自定义数据保存目录。

### 数据文件说明

每局对局自动保存到数据目录（默认 `data/sessions/`）：

| 文件 | 内容 |
|------|------|
| `qqchess_ws_raw_*.json` | 原始 WebSocket 消息 (base64) |
| `qqchess_ws_decoded_*.json` | 解码后的消息 (msgID、加解密状态) |
| `qqchess_moves_*.json` | 提取的走子列表 (UCI + 坐标 + 阵营) |
| `qqchess_summary_*.json` | 会话摘要 (密钥、统计、按局分组) |

数据目录超过 100MB 时自动清理旧文件。

---

## 打包发布

### 打包命令

```bash
cd electron-app

npm run build           # Windows (安装版 + 绿色版)
npm run build:setup     # 仅 Windows 安装版 (NSIS)
npm run build:portable  # 仅 Windows 绿色版 (单文件)
npm run build:mac       # macOS .dmg
npm run build:linux     # Linux .AppImage
npm run build:all       # 全平台
npm run build:dir       # 解包目录版 (调试用)
```

### 产物位置

```
electron-app/dist/
├── QQ象棋协议分析器 Setup 1.0.0.exe   # Windows 安装版
├── QQ象棋协议分析器_1.0.0_portable.exe # Windows 绿色版
├── QQ象棋协议分析器_1.0.0_mac.dmg      # macOS
└── QQ象棋协议分析器_1.0.0_linux.AppImage # Linux
```

### 注意事项

- 打包不含 Python 和 mitmproxy，用户需自行安装
- macOS 版本在 Windows 上交叉打包**无法签名**，用户首次打开需右键 → 打开
- 正式分发 macOS 版本需在 Mac 上打包 + Apple Developer 账号签名公证

---

## 技术架构

### 协议栈

```
应用层  JCE 序列化业务消息 (登录/走子/房间)
加密层  TEA-CBC (iFlag 控制是否加密)
路由层  session_id + route string
帧格式  [varint length] [magic] [session_id] [route] [JCE body]
传输层  WebSocket binary (wss://wxlogin.qqchess.qq.com:443)
```

### 核心模块

| 模块 | 文件 | 功能 |
|------|------|------|
| TEA 加解密 | `xq_ws_proxy.py` | 250+ 行，大端标准 TEA-CBC，加密+解密 |
| JCE 解析器 | `xq_ws_proxy.py` | 350+ 行，完整 14 种类型支持 |
| 走子检测 | `xq_ws_proxy.py` | SEND/RECV 双路径坐标提取 |
| 对局边界 | `xq_ws_proxy.py` | 86001/85075/86006 检测新局/终局/重连 |
| 棋盘渲染 | `renderer.js` | Canvas 2D 中国象棋棋盘 + 走子标记 |
| 引擎桥接 | `pikafish-bridge.js` | UCCI 协议，stdin/stdout 双向通信 |
| 会话恢复 | `renderer.js` | 断连后从 JSON 回放走子 |

### 关键技术发现

- **密钥派生**: 登录 85001 下发 `sSecKey` + `uUin`，`sessionKey = TEA_decrypt(sSecKey, pad16(uUin))`
- **加密标志**: `iFlag & 1` 控制消息是否加密，仅加密 `vecMsgBody` 部分
- **消息路由**: 服务端通过 route 字符串 (`log-qqchess`/`GGame`/`QGame`) 分发
- **棋盘编码**: 中国象棋 FEN，10行×9列，大写红方/小写黑方
- **阵营检测**: 中国象棋红方先走，首步 SEND = 执红，首步 RECV = 执黑

详细技术文档请参阅 [RESEARCH.md](./docs/RESEARCH.md)。

---

## 开源许可

### 本项目

MIT License © 2026

本项目代码仅供学习和研究使用。使用者需遵守腾讯天天象棋的用户协议，不得用于破坏游戏公平性或任何商业用途。

### 皮卡鱼 (Pikafish) 象棋引擎

项目自动检测 `engines/pikayu-*` 目录，取日期最新者。放置步骤：

1. 从 [Pikafish Releases](https://github.com/pikafish/Pikafish/releases) 下载最新 Windows 压缩包
2. 解压后得到 `pikafish-*.exe` 和 `pikafish.nnue`
3. 在 `engines/` 下创建目录，命名格式 `pikayu-YYYYMMDD`（如 `pikayu-20260131`）
4. 将 exe 和 nnue 文件放入该目录

```
engines/
└── pikayu-20260131/
    ├── pikafish-avx2.exe
    ├── pikafish-bmi2.exe
    ├── pikafish-sse41-popcnt.exe
    └── pikafish.nnue
```

启动时自动选择兼容当前 CPU 的最优版本（优先级：sse41-popcnt → bmi2 → avx2 → avxvnni → avx512）。

本项目集成的皮卡鱼引擎为 **GNU General Public License v3 (GPLv3)** 开源软件。

- 项目主页: https://github.com/pikafish/Pikafish
- NNUE 神经网络权重文件 (`pikafish.nnue`) 同为 GPLv3 许可
- 对本项目的皮卡鱼集成代码（`pikafish-bridge.js`）同样受 GPLv3 约束

### 其他依赖

| 依赖 | 许可 |
|------|------|
| mitmproxy | MIT |
| Electron | MIT |
| electron-builder | MIT |

---

> 本项目仅为技术研究和学习参考目的。请尊重知识产权，合理使用。
