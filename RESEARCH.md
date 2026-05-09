# 天天象棋 (QQ Chess XQ) 网络协议逆向工程 — 完整研究报告

> 最后更新: 2026-05-09
> 作者: Claude Code 协助分析
> 状态: 协议层完整破解，Electron 封装接近成品

---

## 目录

1. [概述](#1-概述)
2. [游戏客户端分析](#2-游戏客户端分析)
3. [网络协议架构](#3-网络协议架构)
4. [WebSocket 帧格式](#4-websocket-帧格式)
5. [JCE 序列化协议](#5-jce-序列化协议)
6. [TEA 加密体系](#6-tea-加密体系)
7. [会话密钥派生](#7-会话密钥派生)
8. [消息类型与 ID 枚举](#8-消息类型与-id-枚举)
9. [走子数据结构](#9-走子数据结构)
10. [棋盘编码 — 中国象棋 FEN](#10-棋盘编码--中国象棋-fen)
11. [反作弊与安全体系](#11-反作弊与安全体系)
12. [工具套件文档](#12-工具套件文档)
13. [Electron 封装方案](#13-electron-封装方案)
14. [对局状态追踪与阵营检测](#14-对局状态追踪与阵营检测)
15. [棋盘渲染与 AI 引擎集成](#15-棋盘渲染与-ai-引擎集成)
16. [重连恢复与对局边界检测](#16-重连恢复与对局边界检测)
17. [已知问题与未来方向](#17-已知问题与未来方向)

---

## 1. 概述

### 1.1 项目目标

对**腾讯天天象棋** H5 版本的网络通信协议进行完整逆向，实现：

- WebSocket 实时流量捕获与解码
- 对局走子的实时提取
- 棋盘状态 (FEN) 的解析与追踪
- TEA-CBC 加密消息的解密
- AI 引擎对接框架
- 一键启动的 Electron 封装（自动代理配置，无需手动设 Windows 代理）

### 1.2 技术栈全景

```
┌─ 腾讯服务器 ─────────────────────────────────────────────┐
│  wss://wxlogin.qqchess.qq.com:443                        │
│  协议: WebSocket binary + JCE + TEA-CBC                  │
└────────────┬─────────────────────────────────────────────┘
             │
    ┌────────┴─────────┐
    │   mitmproxy      │  ← 中间人代理，端口 8888
    │   xq_ws_proxy.py │  ← addon: 实时解码 + 密钥派生
    └────────┬─────────┘
             │
    ┌────────┴─────────┐
    │   Electron App   │  ← 自动配代理 + 启动游戏
    │   (main.js)      │     session.setProxy()
    └────────┬─────────┘
             │
    ┌────────┴─────────┐
    │  QQ Chess H5     │  ← Cocos Creator 游戏引擎
    │  (h5login.qqchess.qq.com) │
    └──────────────────┘
```

### 1.3 核心发现总结

| 层次 | 发现 |
|------|------|
| **传输** | WebSocket binary，服务端 `wxlogin.qqchess.qq.com:443` |
| **帧格式** | `[2B大端长度] [magic: SEND=01 10 cf 10 01 / RECV=0c 10 01] [session_id hex] [route string] [JCE body]` |
| **序列化** | **JCE** (Jce Communication Encoding)，腾讯自研，类似 Protobuf 的 TLV 格式 |
| **加密算法** | **TEA-CBC**，16 轮 Feistel 网络，delta=0x9E3779B9，128-bit 密钥，大端字节序 |
| **密钥派生** | 登录响应 85001 下发 `sSecKey` + `uUin` → `sessionKey = TEA_decrypt(sSecKey, pad16(str(uUin)))` |
| **消息加密** | `iFlag & 1` 控制是否加密，加密范围为 JCE body 部分 |
| **棋盘编码** | 中国象棋 FEN，10行×9列，大写红方/小写黑方 |
| **走子坐标** | `(fromCol, fromRow) → (toCol, toRow)`，0-indexed，col 0-8, row 0-9 |
| **消息路由** | `log-qqchess`（登录）、`GGame`（游戏）、`QGame`（棋局） |

---

## 2. 游戏客户端分析

### 2.1 客户端架构

QQ 象棋支持多平台运行，通过统一的 H5 代码库 + 平台适配层实现：

```
┌──────────────────────────────────────┐
│         Cocos Creator H5 引擎        │
│         (index.html + index.ec248.js)│
├──────────────────────────────────────┤
│  平台适配层 (模块化 JS)              │
│  ├── Web (浏览器直接运行)            │
│  ├── WeChat (微信 JSSDK)             │
│  ├── MobileQQ (手Q JSSDK)            │
│  └── ElectronSDK (PC 桌面端)         │
│      ├── window.electron 检测        │
│      ├── ipcRenderer (进程通信)      │
│      ├── child_process (系统调用)    │
│      └── fs (文件系统)               │
└──────────────────────────────────────┘
```

### 2.2 客户端下载

CDN 地址: `https://h5login.qqchess.qq.com/`

核心文件：

| 文件 | 大小 | 说明 |
|------|------|------|
| `index.html` | ~3 KB | 入口页面，加载 Cocos 引擎和游戏模块 |
| `index.ec248.js` | ~10 MB | **主 JS 包**，包含全部游戏逻辑、协议处理、加密模块 |
| `cocos2d-js-min.5b96a.js` | ~1 MB | Cocos Creator 引擎 |
| `settings.9cf77.js` | ~2 KB | 游戏设置 |
| `main.de785.js` | ~4 KB | 主逻辑入口 |
| `AppDefines.9da37.js` | ~1 KB | 常量定义 |
| `midas.0bdc8.js` | ~5 KB | 米大师支付模块 |
| `style-desktop.9aeb1.css` | ~1 KB | PC 桌面端样式 |

### 2.3 关键 JS 模块定位

主包 `index.ec248.js`（约 10 MB）由 Webpack 打包，共 900+ 个模块。关键模块：

| 模块 ID | 名称 | 功能 |
|---------|------|------|
| **294** | `TEAUtils` | **TEA 加密/解密核心**，5 个关键函数 |
| **157** | `SecurityModel` | 安全 SDK 对接，反作弊数据收发 |
| **641** | `AntiCheatManager` | PC 端反作弊：进程监控、录屏检测 |
| **881** | `JCEProtocol` | JCE 协议编解码，消息路由，加解密调度 |
| **563** | `FiveJCEProtocol` | 五子棋等小游戏的独立协议通道 |
| **819** | `ElectronSDK` | PC 原生平台接口（窗口、进程、注册表） |

---

## 3. 网络协议架构

### 3.1 协议栈

```
Layer 5  应用层    JCE 序列化的业务消息 (登录/走子/房间...)
Layer 4  加密层    TEA-CBC (iFlag 控制是否加密)
Layer 3  路由层    session_id → route string → 服务端分发
Layer 2  帧格式    varint length + magic + header + body
Layer 1  传输层    WebSocket binary (wss://wxlogin.qqchess.qq.com:443)
```

### 3.2 完整消息结构

```
┌────────────┬──────────────┬───────────────┬───────────┬─────────────┐
│  length    │    magic     │   session_id  │   route   │  JCE body   │
│  (2B BE)   │  (5B or 3B)  │   (hex str)   │  (string) │  (JCE bin)  │
└────────────┴──────────────┴───────────────┴───────────┴─────────────┘

SEND (客户端→服务端):
  [0xNN 0xNN] [01 10 cf 10 01] [session_id...] [route...] [body...]
              └── 5 字节 magic ──┘

RECV (服务端→客户端):
  [0xNN 0xNN] [0c 10 01] [session_id...] [route...] [body...]
              └─ 3 字节 magic ─┘
```

- **长度**: 大端 2 字节，不包含自身
- **Magic**: 区分消息方向。SEND 的 `01` 和 RECV 的 `0c` 可能是协议版本或方向标识
- **Session ID**: 32 字符 hex 字符串，标识客户端连接
- **Route**: 可读 ASCII 字符串，服务端用此做消息路由分发
- **JCE Body**: JCE 编码的 `TPackage` 结构

### 3.3 服务端端点

| 端点 | 用途 |
|------|------|
| `wss://wxlogin.qqchess.qq.com:443` | WebSocket 主连接 |
| `https://h5login.qqchess.qq.com/` | H5 客户端 CDN |

### 3.4 命名空间体系

```
QQChessZoneProto   — 大厅/匹配/房间/登录
QQChessCommProto   — 通用象棋数据（棋盘、棋子）
QQChessPlayProto   — 对局/走子/战斗
```

---

## 4. WebSocket 帧格式

### 4.1 帧类型 `TPackage`

JCE 结构定义（对应 `xq_ws_proxy.py` 的 `parse_pkg()`）：

| Tag | 字段名 | 类型 | 说明 |
|-----|--------|------|------|
| 0 | `iClientVer` | INT32 | 客户端版本号 |
| 1 | `iOpenPlatType` | INT32 | 开放平台类型 (1=微信, 2=手Q, 3=PC) |
| 2 | `iOSType` | INT32 | 操作系统 (1=Android, 2=iOS, 3=Windows...) |
| 3 | `uUin` | UInt32/INT64 | 用户 QQ 号 |
| 4 | `sOpenID` | STRING | 开放平台 OpenID |
| 5 | `iZoneID` | INT32 | 分区 ID |
| 6 | `iGameID` | INT32 | 游戏 ID |
| 7 | `iSequence` | INT32 | 消息序列号 |
| 8 | **`iFlag`** | INT32 | **标志位 (bit 0 = 加密标志)** |
| 9 | `stMsg` | STRUCT | **消息体 `TMsg`** |
| 10 | `iRoomID` | INT32 | 房间 ID |
| 11 | `sSig` | STRING | 签名 |
| 12 | `sChannelID` | STRING | 渠道 ID |
| 13 | `sClientVersion` | STRING | 客户端版本字符串 (如 `V2.3.4.5`) |
| 14 | `iClientType` | INT32 | 客户端类型 |

### 4.2 `TMsg` 子结构

| Tag | 字段名 | 类型 | 说明 |
|-----|--------|------|------|
| 0 | `stMsgHead` | STRUCT | 消息头 |
| 1 | `vecMsgBody` | BYTES | **消息体 (可能是 JCE 或加密的密文)** |

### 4.3 `stMsgHead` 子结构

| Tag | 字段名 | 类型 | 说明 |
|-----|--------|------|------|
| 0 | `iMsgType` | INT32 | 消息类型 |
| 1 | **`iMsgID`** | INT32 | **消息 ID (关键分类字段)** |
| 2 | `iResult` | INT32 | 返回码 |
| 3 | `ts` | INT64 | 时间戳 |

### 4.4 `iFlag` 加密标志

```
iFlag & 1 == 1  → 消息体已 TEA-CBC 加密
iFlag & 1 == 0  → 消息体为明文
```

在实际抓包中，观察到：
- 登录流程 (85001) 之前的大部分消息：`iFlag=0`（明文）
- 登录成功后的对局消息 (86004 等)：`iFlag=1`（加密）
- 心跳消息 (85000)：`iFlag=0`（明文）
- 大厅/房间消息：`iFlag=0` 或 `iFlag=1`，取决于消息类型

### 4.5 方向识别

```python
# xq_ws_proxy.py unwrap_ws()
SEND_MAGIC = b'\x01\x10\xcf\x10\x01'  # 客户端 → 服务端
RECV_MAGIC = b'\x0c\x10\x01'          # 服务端 → 客户端
```

通过检查 magic 字节来区分消息方向，无需依赖 HAR 的 type 字段。

---

## 5. JCE 序列化协议

### 5.1 JCE 概述

**JCE** (Jce Communication Encoding) 是腾讯自研的二进制序列化协议，功能类似 Protobuf 但使用不同的 wire format。

核心特点：
- **Tag-Length-Value** 格式，tag 和 type 编码在同一字节中
- **字段按 tag 升序排列**（类似 Protobuf）
- 支持嵌套结构（STRUCT）
- 变长整数编码

### 5.2 类型系统

每个字段的头部 1 字节编码为：**高 4 位 = field_id (tag)，低 4 位 = type**

| Type ID | 名称 | 编码 | 说明 |
|---------|------|------|------|
| 0 | INT1 | `[tag<<4\|0] [1B value]` | 单字节有符号整数 |
| 1 | INT2 | `[tag<<4\|1] [2B BE value]` | 双字节有符号整数 |
| 2 | INT4 | `[tag<<4\|2] [4B BE value]` | 四字节有符号整数 |
| 3 | INT8 | `[tag<<4\|3] [8B BE value]` | 八字节有符号整数 |
| 4 | FLOAT | `[tag<<4\|4] [4B]` | 单精度浮点 |
| 5 | DOUBLE | `[tag<<4\|5] [8B]` | 双精度浮点 |
| 6 | **STR1** | `[tag<<4\|6] [1B len] [data]` | 短字符串 (≤255 字节) |
| 7 | **STR4** | `[tag<<4\|7] [4B BE len] [data]` | 长字符串 |
| 8 | MAP | `[tag<<4\|8] [1B count] [kv pairs...]` | 键值对 |
| 9 | LIST | `[tag<<4\|9] [1B count] [items...]` | 列表 |
| 10 | **STRUCT_BEGIN** | `[tag<<4\|10]` | 结构体开始 |
| 11 | **STRUCT_END** | `[tag<<4\|11]` | 结构体结束 |
| 12 | ZERO | `[tag<<4\|12]` | 零值占位 |
| 13 | BYTES | `[tag<<4\|13] [inner_tag] [varint_len] [data]` | 原始字节 |

### 5.3 Tag 扩展

当 tag ≥ 15 时，使用扩展编码：
```
[0xF0 | type] [extended_tag_byte] [value...]
```
即第一个字节的高 4 位 = 15 表示扩展，后续紧跟一个字节表示真实 tag。

### 5.4 解析算法

```
while not end_of_stream:
    read tag_byte
    tag = tag_byte >> 4
    type = tag_byte & 0x0F
    
    if type == STRUCT_END: break
    if type == ZERO: continue
    
    read value based on type:
        INT1:    read 1B
        INT2:    read 2B BE
        INT4:    read 4B BE
        INT8:    read 8B BE
        STR1:    read len(1B), then read len bytes
        STR4:    read len(4B BE), then read len bytes
        BYTES:   read inner tag, read varint length, read data
        STRUCT:  recurse (push context)
        MAP:     read count, then count pairs
        LIST:    read count, then count items
```

### 5.5 JCE 在实际消息中的分布

典型登录消息 (85001) 的 JCE 层级：

```
TPackage                          ← JCE struct (tag=9 in outer wrapper)
├── iClientVer, iOSType, ...
├── stMsg (TMsg)
│   ├── stMsgHead
│   │   ├── iMsgType, iMsgID=85001, iResult, ts
│   └── vecMsgBody (bytes) → TResponseLogin
│       ├── iResultID (tag 0)
│       ├── uUin (tag 1)           ← 用户 QQ 号
│       ├── tPlayerInfo (tag 4)    ← 玩家信息 (struct)
│       ├── sSecKey (tag 10)       ← 加密的会话密钥
│       └── ...其他字段
└── iRoomID, sSig, sChannelID...
```

---

## 6. TEA 加密体系

### 6.1 算法概述

QQ 象棋使用**自定义 TEA-CBC** (Tiny Encryption Algorithm, Cipher Block Chaining) 加密对战消息的 `vecMsgBody`。

**关键特征**:
- 标准 TEA 算法（非 XXTEA）
- **大端**字节序（与 JS `DataView.setInt32/getInt32` 默认行为一致）
- CBC 模式，IV 为零向量 (8 字节 0x00)
- 16 轮 Feistel 网络
- Delta 常量: `0x9E3779B9`（标准 TEA 黄金数）

### 6.2 算法常量

| 常量 | 值 | JS 变量名 | 含义 |
|------|-----|-----------|------|
| DELTA | `0x9E3779B9` | `adc` | TEA 标准黄金数 |
| ROUNDS | `16` | `cdd` | Feistel 加密轮数 |
| WJB | `2` | `Wjb` | 头部随机填充字节数 |
| DKB | `7` | `dkb` | 尾部零填充字节数 |
| QDE | `4` | `Qde` | 解密初始 total 的 delta 左移量 (delta×16) |

### 6.3 5 个核心函数 (JS 模块 294 TEAUtils)

#### Iec — 加密一个 8 字节块

```javascript
// 标准 TEA Feistel 网络
function Iec(input, offset, key, output, outOff) {
    let v0 = input[offset], v1 = input[offset+1];  // uint32 × 2
    let total = 0;
    for (let i = 0; i < 16; i++) {
        total += 0x9E3779B9;
        v0 += ((v1<<4)+k0 ^ v1+total ^ (v1>>5)+k1);
        v1 += ((v0<<4)+k2 ^ v0+total ^ (v0>>5)+k3);
    }
    output[outOff] = v0; output[outOff+1] = v1;
}
```

#### qKb — 解密一个 8 字节块

```javascript
function qKb(input, offset, key, output, outOff) {
    let v0 = input[offset], v1 = input[offset+1];
    let total = 0x9E3779B9 * 16;  // delta << 4
    for (let i = 0; i < 16; i++) {
        v1 -= ((v0<<4)+k2 ^ v0+total ^ (v0>>5)+k3);
        v0 -= ((v1<<4)+k0 ^ v1+total ^ (v1>>5)+k1);
        total -= 0x9E3779B9;
    }
}
```

#### zJb — TEA-CBC 解密 (带填充处理)

```javascript
function zJb(ciphertext, key, output) {
    // CBC模式，IV=0
    // 密文结构: [随机头填充(Wjb=2B)] [payload] [尾填充(dkb=7B)]
    // 第0个块解密后首字节低3位 = 随机头部长度
    // 解密公式: P[i] = D(C[i] ⊕ P[i-1], key) ⊕ C[i-1]
}
```

**Python 对应实现**: `xq_ws_proxy.py` 的 `tea_zjb_decrypt()` 函数（200+ 行，完整复现 JS 逻辑）

#### Aad — TEA-CBC 加密 (带填充)

```javascript
function Aad(plaintext, key) {
    // 加密前添加 Wjb 字节随机头部 + dkb 字节零尾部
    // 加密公式: C[i] = E(P[i] ⊕ C[i-1], key) ⊕ P[i-1]
}
```

**Python 对应实现**: `xq_ws_proxy.py` 的 `tea_aad_encrypt()` 函数

#### Bbe — 计算加密后大小

```javascript
function Bbe(plain_len) {
    // 返回加密后 buffer 大小（含填充、补齐到 8 字节边界）
}
```

### 6.4 填充方案

```
加密前明文布局:
  [1B: random_5bits | pad_len(3bits)]
  [pad_len bytes: 随机填充]
  [WJB=2 bytes: 头部随机填充]
  [payload bytes...]
  [DKB=7 bytes: 尾部零填充]
  [补齐到 8 字节倍数]

总开销 = 1 + pad_len + 2 + 7 = 10 + pad_len 字节
pad_len = 0~7 (补齐到 8 字节边界)
实际开销 = 10~17 字节
```

### 6.5 重要实现细节

**`tea_decrypt.py` vs `xq_ws_proxy.py` 的 TEA 实现差异**：

| 特性 | `tea_decrypt.py` | `xq_ws_proxy.py` |
|------|-----------------|-----------------|
| 字节序 | **小端** (Little Endian) | **大端** (Big Endian) |
| TEA 变体 | XXTEA (Corrected Block TEA) | 标准 TEA |
| 轮函数偏移 | `(total>>11) & 3` 变体 | 标准 k0-k3 固定偏移 |
| 状态 | 早期实验版本 | **当前工作版本，匹配 JS** |

**结论**: `xq_ws_proxy.py` 中的大端标准 TEA 实现是正确匹配 JS 客户端的版本。

### 6.6 加密范围

```
只有 vecMsgBody (TMsg 的 tag 1) 被加密
外层 TPackage 字段 (iFlag, msgID, uUin 等) 始终明文

加密判断:
  if (sessionKey && (pkg.iFlag & 1)):
      body = tea_zjb_decrypt(vecMsgBody_bytes, sessionKey)
  else:
      body = vecMsgBody_bytes  (明文)
```

---

## 7. 会话密钥派生

### 7.1 完整流程图

```
① 客户端发送登录请求 (msgID=85001)
        ↓
② 服务端返回登录响应 (msgID=85001)
   { uUin: 123456789, sSecKey: "a1b2c3d4..." }
        ↓
③ 客户端派生会话密钥:
   tempKey = String(uUin).bytes().padEnd(16, 0x00)
   // tempKey = b'123456789\x00\x00\x00\x00\x00\x00\x00'
   
   sSecKey_bytes = hexToBytes(sSecKey)
   // sSecKey = "a1b2c3d4e5f6..." → bytes
   
   sessionKey = TEAUtils.zJb(sSecKey_bytes, tempKey)
   // 用 tempKey 解密 sSecKey 得到真正的 16 字节会话密钥
        ↓
④ 后续所有 msgID > 85001 的消息:
   if (iFlag & 1):
       body = TEAUtils.zJb(encrypted_body, sessionKey)
```

### 7.2 Python 实现

```python
# xq_ws_proxy.py derive_session_key()
def derive_session_key(ssec_hex, uin):
    """派生会话密钥"""
    # tempKey = pad16(str(uin))
    tk = str(uin).encode('latin-1').ljust(16, b'\x00')
    
    # sSecKey_bytes = hex_to_bytes(sSecKey)
    ssec_bytes = bytes.fromhex(ssec_hex)
    
    # sessionKey = TEA_decrypt(sSecKey, tempKey)
    sk = tea_zjb_decrypt(ssec_bytes, tk)
    if sk:
        return sk[:16]
    return None
```

### 7.3 密钥安全性分析

- 密钥**不在客户端硬编码**，由服务端在登录时动态下发
- sSecKey 本身经过 TEA 加密（用 uin 做临时密钥），防止明文传输
- 会话密钥绑定用户 uin，不同用户的密钥不同
- 密钥在单次会话中不变，断开重连后重新协商

---

## 8. 消息类型与 ID 枚举

### 8.1 ID 范围分布

| ID 范围 | 分类 | 说明 |
|---------|------|------|
| **85000-85099** | 心跳/系统 | 85000=心跳，85001=登录，85005=进房，85018=大厅信息，85031=房间信息，85075=对局通知，85077=匹配 |
| **86001-86028** | 对局/战斗 | 86001=战斗就绪，86004=**走子**，86005=棋盘状态，86006=游戏事件 |
| **89012-89213** | 社交 | 89113=挑战/应战，89151=匹配信息 |
| **89301-89757** | 游戏系统 | 89300、89504、89505、89513、89621、89671 |

### 8.2 已知消息 ID 详表

#### 心跳/连接

| msgID | 方向 | 说明 |
|-------|------|------|
| 85000 | SEND↔RECV | **心跳**，保持连接活跃 |
| 85001 | RECV | **登录响应**，携带 sSecKey + uUin |
| 89055 | SEND | 握手/连接初始化 |

#### 大厅/房间

| msgID | 方向 | 说明 |
|-------|------|------|
| 85005 | RECV | 进入房间 |
| 85006 | RECV | 房间信息更新 |
| 85008 | RECV | 大厅列表 |
| 85018 | RECV | 大厅信息 |
| 85031 | RECV | 房间信息 |
| 85039 | RECV | 用户信息 |
| 85047 | RECV | 排行榜 |
| 85053 | RECV | 活动信息 |
| 85060 | RECV | 任务信息 |
| 85067 | RECV | 邮件/通知 |
| 85075 | RECV | **对局通知** (开始/结束/结果) |
| 85077 | RECV | 匹配/准备状态 |
| 85078 | RECV | 匹配取消 |
| 85083 | RECV | 背包/道具 |

#### 对局/战斗 (关键)

| msgID | 方向 | 说明 |
|-------|------|------|
| 86001 | RECV | **战斗就绪** (对局开始) |
| 86003 | SEND | 准备完毕 |
| **86004** | **SEND** | **走子请求** (客户端发出，cmdID=1 表示走子) |
| 86005 | RECV | 棋盘状态更新 (对方走子/服务器确认) |
| 86006 | RECV | 游戏事件 (超时/弃权/求和/认输) |
| 86028 | SEND↔RECV | AI 走子 (人机对战) |

#### 社交/匹配

| msgID | 方向 | 说明 |
|-------|------|------|
| 89113 | RECV | 挑战/应战 |
| 89115 | SEND | 发起挑战 |
| 89150 | RECV | 好友列表 |
| 89151 | RECV | 匹配信息 |
| 89152 | SEND | 开始匹配 |

#### 其他

| msgID | 方向 | 说明 |
|-------|------|------|
| 85211 | RECV | 活动奖励 |
| 85217 | RECV | 签到信息 |
| 85218 | SEND | 签到 |
| 85301 | SEND↔RECV | 商城 |
| 89040 | RECV | 公告 |
| 89043 | RECV | 弹窗信息 |
| 89050 | RECV | 红点提示 |
| 89054 | RECV | 配置更新 |
| 89061 | RECV | 服务器推送 |
| 89085 | RECV | 系统消息 |
| 89100 | RECV | 段位信息 |
| 89504 | RECV | 成就 |
| 89505 | RECV | 称号 |
| 89513 | RECV | 赛季信息 |
| 89621 | RECV | 数据统计 |
| 89671 | RECV | 对局记录 |

### 8.3 消息路由

消息通过 `route` 字符串分发到不同的服务端处理器：

| Route | 说明 |
|-------|------|
| `log-qqchess` | 登录认证服务 |
| `GGame` | 游戏主服务 |
| `QGame` | 棋局对局服务 |
| `UpdateConfig.json` | 配置更新 |
| `DAKID` | 身份认证 (腾讯 DAKID 体系) |
| `Notify` | 推送通知 |
| `PVP` | 玩家对战 |

---

## 9. 走子数据结构

### 9.1 走子消息 (86004)

走子通过 `TRequestPlay` 结构发送：

| Tag | 字段名 | 类型 | 说明 |
|-----|--------|------|------|
| 0 | `nCmdID` | INT16 | 命令 ID (1=走子, 2=求和, 3=认输...) |
| 1 | `nRoomID` | INT16 | 房间 ID |
| 2 | `nTableID` | INT16 | 桌号 |
| 3 | `nSeatID` | INT16 | 座位号 |
| 4 | `vecMsgBody` | BYTES | **走子数据载荷** |

### 9.2 走子坐标编码

走子数据在 `vecMsgBody` 中按协议坐标编码：

```
格式: [4 字节] fromCol, fromRow, toCol, toRow

坐标系:
  col: 1-9 (列, a-i)
  row: 1-10 (行, 0-9, 黑方底线→顶线)

注意: 协议使用 1-indexed 坐标
  fromCol=1 → 第 a 列
  fromRow=1 → 第 0 行

UCI 转换:
  协议坐标 (fc, fr, tc, tr) → UCI
  col_char = chr(ord('a') + fc - 1)
  from_uci = col_char + str(fr - 1)
  to_uci   = col_char + str(tr - 1)
```

### 9.3 vecMsgBody 结构

走子消息的内部载荷包含：

```
[0xff 标记字节 (86004 走子)]
[fromCol (1B)]
[fromRow (1B)]
[toCol (1B)]
[toRow (1B)]
[可能的额外数据...]
```

### 9.4 走子检测算法

```python
# xq_ws_proxy.py find_moves_in_vec()
def find_moves_in_vec(body):
    """在 vecMsgBody 中扫描走子坐标候选"""
    for i in range(len(body) - 3):
        fc, fr, tc, tr = body[i], body[i+1], body[i+2], body[i+3]
        
        # 跳过零值 (协议固定字段)
        if 0 in (fc, fr, tc, tr): continue
        
        # 验证范围 (协议使用 1-indexed)
        if not (1<=fc<=9 and 1<=fr<=10 and 1<=tc<=9 and 1<=tr<=10): continue
        
        # 起点≠终点
        if fc == tc and fr == tr: continue
        
        # 评分系统:
        score = nearby_jce_tags  # 周围 JCE tag 密度
              + marker_bonus      # 0xff 标记加分
              + offset * 0.01    # 靠后的候选更可信
        
        # 转换为 UCI
        uci = f"{cols[fc-1]}{fr-1}{cols[tc-1]}{tr-1}"
        
        candidates.append({...})
    
    # 返回按 score 降序排列的候选
    return sorted(candidates, key=lambda x: -x['tag_score'])
```

### 9.5 走子类型 (nCmdID)

| cmdID | 含义 |
|-------|------|
| 1 | 走子 (正常行棋) |
| 2 | 求和 |
| 3 | 认输 |
| 4 | 悔棋请求 |
| 5 | 悔棋同意/拒绝 |

### 9.6 游戏事件类型 (nEventID)

服务端通过 86005/86006 推送游戏事件：

| EventID | 含义 |
|---------|------|
| 1 | 走子广播 |
| 2 | 棋盘状态同步 |
| 3 | 超时判负 |
| 4 | 对方认输 |
| 5 | 对方求和 |
| 6 | 游戏结束 |

---

## 10. 棋盘编码 — 中国象棋 FEN

### 10.1 FEN 格式

初始局面：
```
rnbakabnr/9/1c5c1/p1p1p1p1p/9/9/P1P1P1P1P/1C5C1/9/RNBAKABNR w
```

格式：`[10行棋盘 (用/分隔)] [走子方 w/b]`

### 10.2 棋子字符映射

| 黑方 (小写) | 红方 (大写) | 中文名称 |
|------------|------------|---------|
| r | R | 车 |
| n | N | 马 |
| b | B | 象/相 |
| a | A | 士/仕 |
| k | K | 将/帅 |
| c | C | 炮 |
| p | P | 卒/兵 |

### 10.3 棋盘结构

```
行 0: a b c d e f g h i  ← 黑方底线
行 1: a b c d e f g h i
...
行 9: a b c d e f g h i  ← 红方底线

UCI 坐标: {列字母}{行号}
  例: h2e2 = 炮二平五 (红炮从 h2 到 e2)
```

### 10.4 数字压缩规则

连续的空位用数字表示：
- `9` = 9 个连续空位 (整行空)
- `1c5c1` = 1空 + 黑炮 + 5空 + 黑炮 + 1空

---

## 11. 反作弊与安全体系

### 11.1 SecurityModel (模块 157)

对接腾讯原生 `window.security` SDK (TSS 安全 SDK)：

- **cmd: 86026** — 反作弊数据收发
- **cmd: 85021** — 安全验证
- **cmd: 89036** — 上报客户端信息
- **cmd: 85031** — 接收服务端安全事件

### 11.2 AntiCheatManager (模块 641)

PC 端的反作弊措施：

| 功能 | 实现方式 |
|------|---------|
| 监控进程列表 | 通过 `child_process.exec('tasklist')` 枚举所有进程，检测外挂特征 |
| 检测录屏软件 | 检查 OBS、Bandicam 等进程名 |
| 检测无障碍辅助 | 检测 Android AccessibilityService (移动端) |
| 定时扫描 | 定时器定期执行扫描 |

### 11.3 设备指纹

通过 `ElectronSDK` 读写注册表：
```
HKEY_CURRENT_USER\SOFTWARE\TENCENT\RRDIFTT\identify\QQCHESS_MAC_ADDRESS
```
存储设备 MAC 地址作为设备唯一标识。

### 11.4 多平台适配

```
Android  → 检测 root + Xposed + 无障碍
iOS      → 检测越狱
PC       → 检测进程列表 + 注册表
微信小程序 → 微信安全 API
```

---

## 12. 工具套件文档

### 12.1 文件清单

```
qqchess-xq/
├── xq_ws_proxy.py          # [核心] mitmproxy 实时抓包 addon (800+ 行)
├── har_analyzer.py          # HAR 离线文件分析器
├── xq_analyzer.py           # 棋局实时分析 + AI 引擎对接
├── xq_decode.py             # JCE 二进制手动解码器 (交互式)
├── tea_decrypt.py           # [早期] 小端 XXTEA 实验版本
├── download_qqchess.py      # 下载 QQ 象棋 H5 客户端
├── _find_key.py             # [工具] 从登录消息提取 sSecKey
├── _fix_session.py          # [工具] 修复/回放已保存的会话
├── _brute_key.py            # [工具] 暴力尝试会话密钥
├── electron-app/            # Electron 封装 (一键启动 + 棋盘 + 引擎)
│   ├── main.js              #   主进程: mitmproxy 管理 + IPC
│   ├── renderer.js          #   渲染进程: 棋盘 + 日志 + 引擎 UI (1100+ 行)
│   ├── pikafish-bridge.js   #   皮卡鱼引擎 UCCI 协议桥接
│   ├── preload.js           #   安全桥接 (contextBridge)
│   ├── index.html           #   控制台界面
│   └── style.css            #   样式
├── data/
│   ├── h5login.qqchess.qq.com.har  # 127 MB HAR 抓包
│   └── sessions/                   # 代理会话输出 (qqchess_*.json)
├── qqchess_src/             # 下载的游戏客户端源码
├── docs/                    # 分析文档
├── engines/                 # 象棋引擎 (皮卡鱼 pikayu)
├── CLAUDE.md                # 项目说明书
└── RESEARCH.md              # 本文档
```

### 12.2 xq_ws_proxy.py — mitmproxy 实时抓包插件

**核心模块，250+ 行 TEA（加密+解密）+ 350+ 行 JCE 解析器 + mitmproxy 事件钩子**

```bash
# 启动
mitmdump --listen-port 8888 -s xq_ws_proxy.py
# 或带 Web 界面
mitmweb --listen-port 8888 -s xq_ws_proxy.py
```

**功能流程**:

```
websocket_start  → 过滤 qqchess URL，初始化会话
       ↓
websocket_message → ① unwrap_ws() 剥离帧头
                    ② parse_pkg() JCE 解析 TPackage
                    ③ 检测 85001 (登录响应) → derive_session_key()
                    ④ 检测 iFlag & 1 → tea_zjb_decrypt()
                    ⑤ 检测 86001 → 解析游戏上下文 → 对局边界检测
                    ⑥ 检测 86004/86005/86011 → parse_request_play / parse_game_event
                       → find_moves_in_vec() → 坐标提取 + 评分
                    ⑦ 检测 85075/86006 → 对局结束检测
                    ⑧ 记录 raw + decoded + moves
       ↓
websocket_end    → _save(force=True) 强制写入 4 个 JSON 文件
```

**完整实现的功能**:

| 功能 | 状态 | 说明 |
|------|------|------|
| TEA-CBC 解密 (zJb) | ✅ | 完全匹配 JS 客户端，大端标准 TEA，16 轮 |
| TEA-CBC 加密 (Aad) | ✅ | 完整实现，含随机头尾填充 |
| JCE 解析 (TPackage/TMsg) | ✅ | 支持全部 14 种 JCE 类型，嵌套结构 |
| 登录密钥派生 | ✅ | 85001 → sSecKey + uUin → sessionKey |
| 走子坐标提取 | ✅ | 含评分机制，SEND/RECV 双路径 |
| 阵营检测 | ✅ | 首步 SEND → red，RECV → black |
| FEN 提取 | ✅ | 从 eventID=63 (MIDGAME) 提取完整 FEN |
| 对局边界检测 | ✅ | 86001 tableID 变化 → 新局；85075/86006 → 终局 |
| 重连恢复 | ✅ | 同 tableID + game_active → 保持状态不清除 |
| 多局累积 | ✅ | 每局走子带 game_idx 标记，按局分组 |
| 节流保存 | ✅ | 3 秒节流，断开时强制写入 |

**输出文件** (保存到 `data/sessions/`):

| 文件 | 内容 |
|------|------|
| `qqchess_ws_raw_*.json` | 原始消息 (base64 + 元数据) |
| `qqchess_ws_decoded_*.json` | 解码后的消息 (msgID, iFlag, 解密状态) |
| `qqchess_moves_*.json` | 提取的走子列表 (UCI + 坐标) |
| `qqchess_fens_*.json` | FEN 棋盘状态 (预留) |
| `qqchess_summary_*.json` | 会话摘要 (密钥, 走子数, 时间) |

### 12.3 har_analyzer.py — HAR 离线分析器

```bash
python har_analyzer.py data/h5login.qqchess.qq.com.har
```

功能：
- 解析 HAR JSON 文件
- 提取 WebSocket 消息 (send/receive)
- 按消息特征分类 (登录/房间/对局/社交...)
- 搜索 FEN 棋盘数据
- 搜索走子坐标模式
- 生成协议分析报告
- 包含 `RealtimeAnalyzer` 类用于棋盘状态追踪

### 12.4 xq_analyzer.py — 棋局分析器

```bash
# HAR 离线分析
python xq_analyzer.py --har data/h5login.qqchess.qq.com.har

# 回放已保存的代理会话
python xq_analyzer.py --session data/sessions/qqchess_ws_raw_*.json

# 演示模式 (模拟对局)
python xq_analyzer.py --demo

# 代理模式 (实时分析)
python xq_analyzer.py --proxy
```

核心类：
- **`XQFenParser`**: FEN 解析/生成/可视化
- **`GameStateTracker`**: 完整对局状态追踪 (走子应用、棋谱记录)
- **`ChessEngine`**: AI 引擎接口 (内置简易评估 + 皮卡鱼对接)
- **`analyze_session()`**: 会话回放，详细的 msgID 时间线和分类统计

**注意**: `xq_analyzer.py` 和 Electron `renderer.js` 中有两套并行的 `GameStateTracker` 实现（Python 版和 JavaScript 版），功能基本对等。JS 版本额外支持中文记谱、棋盘翻转、引擎 UI 集成。

### 12.5 xq_decode.py — JCE 交互式解码器

```bash
# 单条 base64 解码
python xq_decode.py "base64_string"

# 交互模式
python xq_decode.py --interact

# 批量解码
python xq_decode.py --file messages.txt
```

功能：
- base64 → hex dump + 结构化分析
- 自动识别方向 (SEND/RECV)
- 搜索路由字符串
- 扫描 JCE 结构边界
- 检测 FEN 和走子坐标候选
- 小整数上下文分析

### 12.6 tea_decrypt.py — TEA 解密器 [实验版]

**⚠ 此文件为早期实验版本，使用小端 XXTEA 变体，不与 JS 客户端匹配。**

当前工作版本位于 `xq_ws_proxy.py`（大端标准 TEA）。

```bash
# 自测
python tea_decrypt.py --test
```

### 12.7 辅助工具

| 工具 | 用法 | 说明 |
|------|------|------|
| `_find_key.py` | `python _find_key.py [raw.json]` | 从登录响应中扫描/提取 sSecKey |
| `_fix_session.py` | `python _fix_session.py [raw.json]` | 用新的密钥派生逻辑重新处理旧会话 |
| `_brute_key.py` | `python _brute_key.py [raw.json]` | 从 85001 body 中暴力尝试每个字符串作为 sSecKey |
| `download_qqchess.py` | `python download_qqchess.py` | 从 CDN 下载最新 H5 客户端 |

### 12.8 会话 JSON 数据格式

**raw 消息记录**:
```json
{
  "seq": 1,
  "time": "2026-05-06T17:45:12.123456",
  "direction": "SEND",
  "size": 512,
  "base64": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIj..."
}
```

**decoded 消息记录**:
```json
{
  "seq": 1,
  "time": "2026-05-06T17:45:12.123456",
  "direction": "SEND",
  "msgID": 86004,
  "iFlag": 1,
  "encrypted": true,
  "decrypted_size": 128,
  "decrypted_hex": "ff01020304050607...",
  "strings": ["move", "from", "to"]
}
```

**moves 记录**:
```json
{
  "num": 1,
  "seq": 42,
  "time": "2026-05-06T17:45:30.000",
  "direction": "SEND",
  "msgID": 86004,
  "eventID": 1,
  "from": [4, 7],
  "to": [4, 5],
  "uci": "e7e5",
  "offset": 18,
  "vec_hex": "ff05080504..."
}
```

---

## 13. Electron 封装方案

### 13.1 架构全景

```
┌──────────────────────────────────────────────────────────────┐
│                    Electron Main Process                     │
│                                                              │
│  ┌──────────────┐  ┌────────────────────────────────────┐    │
│  │ mitmdump      │  │ session.setProxy()                │    │
│  │ child_process │  │ → 127.0.0.1:8888                 │    │
│  │ -s xq_ws_    │  │ (仅 webview，不影响系统代理)      │    │
│  │   proxy.py   │  └────────────────────────────────────┘    │
│  └──────┬───────┘                                            │
│         │ stdout pipe                                        │
│  ┌──────┴───────┐  ┌────────────────────────────────────┐    │
│  │ 日志解析      │  │ Pikafish Bridge (UCCI 协议)       │    │
│  │ GBK/UTF-8    │  │ stdin/stdout 双向通信              │    │
│  │ 过滤 + 分类   │  │ analyze(fen, moves) → {best,score}│    │
│  └──────┬───────┘  └────────────────────────────────────┘    │
│         │ IPC push                                           │
│  ┌──────┴──────────────────────────────────────────────┐    │
│  │              IPC Handlers (12+)                      │    │
│  │  proxy管理 | 日志查询 | 会话文件 | 引擎分析 | 自动走子│    │
│  │  数据统计 | 清理 | 设置 | Python检测 | 目录选择      │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐    │
│  │ fs.watch(SESSIONS_DIR) → session-file-changed event  │    │
│  │ 触发: 防抖清理检查 (5s)                              │    │
│  └──────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
         │
         │ IPC (contextBridge)
         ▼
┌──────────────────────────────────────────────────────────────┐
│              Electron Renderer Process                       │
│                                                              │
│  ┌─────────────────┐  ┌────────────────────────────────┐     │
│  │ Webview         │  │ 控制台 UI                      │     │
│  │ h5login.qqchess │  │ ┌──────────┐ ┌──────────────┐ │     │
│  │ .qq.com         │  │ │ 棋盘画布  │ │ 引擎分析面板 │ │     │
│  │ (Cocos Creator) │  │ │ (canvas) │ │ bestmove/score│ │     │
│  │                 │  │ │          │ │ depth/pv     │ │     │
│  │                 │  │ │ 走子列表  │ │ fen          │ │     │
│  │                 │  │ │ 红方/黑方│ │              │ │     │
│  │                 │  │ └──────────┘ └──────────────┘ │     │
│  │                 │  │ ┌──────────────────────────┐  │     │
│  │                 │  │ │ 实时日志 (过滤+分类)     │  │     │
│  └─────────────────┘  │ └──────────────────────────┘  │     │
│                       └────────────────────────────────┘     │
│                                                              │
│  GameStateTracker: FEN解析 → UCI走子 → 中文记谱 → 棋盘更新   │
│  restoreMovesFromSession: 断连重连 → 回放当前局走子          │
│  _gameActive 标记: 区分新局 vs 重连                          │
└──────────────────────────────────────────────────────────────┘
```

### 13.2 主进程 (main.js) 核心模块

**mitmproxy 生命周期管理**:
```javascript
// GBK/UTF-8 双编码自动检测（Windows 中文环境兼容）
function _decodeMitm(buf) {
    try { return new TextDecoder("utf-8", { fatal: true }).decode(buf); }
    catch (_) { return _gbkDecoder.decode(buf); }
}

// 资源日志过滤 — 只保留 QQ Chess addon 输出
function _isResourceLog(line) {
    // 过滤 HTTP 请求、WS 流、TCP 连接等 mitmdump 自身日志
}

// 健康检查 — TCP 端口探测，最多 8 秒
async function waitForProxy(timeoutMs = 8000) { ... }
```

**Pikafish 引擎桥接** (`pikafish-bridge.js`):
```javascript
// UCCI 协议 (Universal Chinese Chess Interface)
// 双向通信: stdin → 引擎, stdout → 解析
class PikafishBridge {
    start()    // 启动引擎进程，等待 ucciok 握手
    stop()     // 发送 quit，清理进程
    analyze(fen, moveList)  // position fen ... moves ... → go depth 18
    // 解析输出: info depth N score cp X pv ..., bestmove XXXX
}
```

**会话文件监听 + 自动清理**:
```javascript
// fs.watch 监听 sessions 目录
// 新文件写入 → 通知 renderer → 防抖 5s 后检查大小
// 超过 100MB → cleanupOldData() 从最旧文件开始删除
```

**IPC 接口清单** (14 个 handler):
| Handler | 功能 |
|---------|------|
| `get-proxy-status` | 代理运行状态 + PID + 统计 |
| `get-logs` | 获取最近 200 条日志 |
| `start-proxy / stop-proxy / restart-proxy` | 代理控制 |
| `get-session-files / read-session-file` | 会话文件管理 |
| `analyze-position` | 皮卡鱼引擎分析 (fen + moves → bestmove) |
| `autoplay-move` | 自动走子注入 (executeJavaScript 模拟 PointerEvent) |
| `detect-python` | 检测 Python + mitmproxy 可用性 |
| `get-data-stats / cleanup-old-data` | 数据统计 + 自动清理 |
| `choose-data-dir` | 用户选择数据目录 |

### 13.3 渲染进程 (renderer.js) 核心模块

**GameStateTracker** — 中国象棋棋盘状态机:
```javascript
// 初始 FEN → parseFen(grid) → applyMove(uci, sent) → toFen(grid, side)
// 支持: UCI 走子验证、FEN 坐标翻转 (红方/黑方视角)
// 中文记谱: _toChinese(uci, piece, fc, fr, tc, tr)
//   例: h2e2 红炮 → "炮二平五"
```

**棋盘渲染** (Canvas 2D):
- 9×10 网格 + 楚河汉界 + 九宫对角线
- 列标注: 红方视角九~一，黑方视角 1~9
- 棋子: 圆形 + 双线边框 + 中文篆体字
- 红方/黑方翻转: `proxyToFenUci()` 处理坐标映射
- 上一步走子: 绿色光晕 + 箭头
- 引擎推荐走法: 琥珀色方块 + 实线箭头

**实时日志处理**:
```javascript
// 每条日志行经过 classifyLine() 分类:
//   move | login | key | error | system | gamedone | msg
// 关键事件触发:
//   [CAMP] → 权威阵营赋值 (_userSide)
//   [MIDGAME] fen=... → 中局加入，重置棋盘到当前 FEN
//   [MOVE #N] → 走子解析 + 去重 + 回声过滤
//   [GAME] 开始 → 重置全部状态 + _gameActive = true
//   [GAME] 结束 → 清除状态 + _gameActive = false
//   [86001] tableID= → 仅重连时 restore (检查 _gameActive)
```

**引擎分析调度**:
```javascript
// 300ms 防抖，每步走子后自动触发
// 发送完整 moveList → 引擎知道当前轮到谁走
// 分析结果: bestmove UCI → 转中文记谱 → 画到棋盘上
// 自动走子模式: opponent moves → analyze → autoPlayMove(bestmove)
```

### 13.4 打包配置

```json
// package.json build 配置
{
  "win": { "target": ["nsis", "portable"] },   // 安装版 + 绿色版
  "mac": { "target": "dmg" },                   // macOS 磁盘映像
  "linux": { "target": "AppImage" },            // Linux AppImage
  "extraResources": [                           // 打包进安装包
    { "from": "../engines", "to": "engines" },  // 皮卡鱼引擎
    { "from": "../xq_ws_proxy.py", "to": "xq_ws_proxy.py" }
  ]
}

// 打包命令:
npm run build          // Windows (nsis + portable)
npm run build:mac      // macOS .dmg
npm run build:linux    // Linux .AppImage
npm run build:all      // 全平台
```

### 13.5 优势

- **一键启动**: 自动配代理 + 启动 mitmproxy + 加载游戏
- **零系统配置**: 不影响 Windows 系统代理 (仅 webview session)
- **内置棋盘**: Canvas 渲染，支持红方/黑方翻转
- **引擎集成**: 皮卡鱼 UCCI 协议，实时分析 + 自动走子
- **断连恢复**: 走子回放，不丢失对局记录
- **数据管理**: 自动清理超过 100MB 的旧数据
- **跨平台打包**: Windows/macOS/Linux 三平台

---

## 14. 对局状态追踪与阵营检测

### 14.1 阵营检测机制

检测玩家执红还是执黑是棋盘正确渲染的前提。阵营检测有三条路径，优先级递减：

**路径 1: Proxy [CAMP] 日志（最权威）**
```python
# xq_ws_proxy.py: 首步走子的方向决定阵营
if self.my_camp is None and self.move_n == 1:
    self.my_camp = 'red' if direction == 'SEND' else 'black'
    ctx.log.info(f"[CAMP] first move is {direction} → {self.my_camp}")
```
- 原理: 中国象棋红方先走，服务端 86005 转发的是走子方信息
- 如果第一步是客户端 SEND → 玩家执红
- 如果第一步是服务端 RECV → 玩家执黑

**路径 2: Renderer 首步 SEND piece color（次权威）**
```javascript
// renderer.js: 首步 SEND 走子的棋子颜色决定阵营
if (_userSide === null && mv.sent) {
    _userSide = result.isRed ? "w" : "b";
}
```

**路径 3: 会话文件恢复中的 camp 字段**
```javascript
// restoreMovesFromSession: 从保存的 camp 字段恢复
if (m.direction === "SEND" && m.camp) {
    _userSide = m.camp === "red" ? "w" : "b";
}
```

### 14.2 FEN 坐标与阵营翻转

**核心问题**: Proxy 使用玩家相对坐标（row 5-9 = 玩家棋子），FEN 使用绝对坐标（row 0 = 黑方底线）。

```
红方玩家 (userSide="w"): proxy 坐标 == FEN 坐标
黑方玩家 (userSide="b"): proxy 坐标需要 9-row 翻转
  例: proxy row 0 → FEN row 9, proxy row 9 → FEN row 0
```

```javascript
// renderer.js: proxy 坐标 → FEN 坐标
function proxyToFenUci(uci) {
    if (_userSide !== "b") return uci;
    const fr = parseInt(uci[1]), tr = parseInt(uci[3]);
    return uci[0] + (9 - fr) + uci[2] + (9 - tr);
}
```

### 14.3 中局加入 (eventID=63)

当玩家在中局加入观战或重连已进行的对局时，服务端发送 eventID=63 消息，包含当前完整 FEN：
```python
# xq_ws_proxy.py
if ev['nEventID'] == 63 and ev['vecMsgBody']:
    fen = extract_fen(ev['vecMsgBody'])
    if fen:
        ctx.log.info(f"[MIDGAME] fen={fen}")
```

Renderer 收到后直接以该 FEN 重置棋盘，清空走子历史，从当前位置继续。

### 14.4 阵营检测的已知陷阱

| 陷阱 | 说明 | 解决方案 |
|------|------|---------|
| Proxy 坐标 ≠ FEN 坐标 | proxy 使用玩家视角相对坐标 | `proxyToFenUci()` 根据 `_userSide` 翻转 |
| 观战模式 | 没有 SEND 消息，无法检测阵营 | 仅通过 [CAMP] 日志或 [MIDGAME] FEN 获取 |
| 引擎分析需要完整历史 | 引擎需要 moveList 知道轮到谁走 | 发送完整的 `parsedMoves` 给引擎 |
| 多局累积 camp 混淆 | 新一局可能复用上局的 camp | 新局强制重置 `_userSide = null` |

---

## 15. 棋盘渲染与 AI 引擎集成

### 15.1 Canvas 棋盘渲染

```
棋盘规格: 300×330 px, 边距 ML=24 MR=12 MT=12 MB=12
列间距: DX = BW/8 ≈ 33px, 行间距: DY = BH/9 ≈ 34px
棋子半径: RR = 13px
```

**渲染层次** (由底到顶):
1. 棋盘底色 (`#e8d5b0`)
2. 网格线 (9 竖 × 10 横，楚河汉界断线)
3. 楚河汉界文字 ("楚  河" / "漢  界")
4. 九宫对角线
5. 列标注 (红方视角九~一，黑方 1~9)
6. 棋子 (圆形 + 双线边框 + 中文)
7. 上一步走子指示 (绿色光晕 + 箭头)
8. 引擎推荐走法 (琥珀色方块 + 箭头)

### 15.2 中文记谱转换

```javascript
// UCI → 中文象棋记谱
_toChinese(uci, piece, fc, fr, tc, tr) {
    // 红方列名: 九八七六五四三二一
    // 黑方列名: 1 2 3 4 5 6 7 8 9
    // 直线棋子 (车炮将兵): 进退用距离数字
    // 斜线棋子 (马象士): 进退用目标列名
}
// 例: "h2e2" 红炮 → "炮八平五"
//     "b0c2" 红马 → "馬八進七"
```

### 15.3 皮卡鱼引擎集成

**UCCI 协议** (Universal Chinese Chess Interface):
```
→ ucci
← ucciok
→ position fen {fen} moves {move_list}
→ go depth 18
← info depth 10 score cp 42 pv h2e2 b7e7 ...
← bestmove h2e2
```

**分析流程**:
1. 每步走子后 300ms 防抖触发 `scheduleAnalysis(fen, isOpponentMove)`
2. 发送完整 moveList → 引擎知道当前局面和轮到谁走
3. 引擎返回 `{bestMove, score, depth, pv}`
4. UI 更新: bestmove (中英文) + score + depth + pv 变着
5. 自动走子模式: opponent moves → analysis → `autoPlayMove(bestmove)`

**自动走子注入**:
```javascript
// main.js: executeJavaScript 注入到 webview
// 计算棋盘 canvas 坐标 → dispatchEvent(PointerEvent)
// 模拟 pointerdown → pointerup (起手) → 180ms delay → pointerdown → pointerup (落子)
```

### 15.4 回声过滤

```
场景: 玩家走子 → SEND 86004 → 服务端转发 RECV 86005 (回声)
问题: 回声的 UCI 和玩家刚走的完全相同，会重复记录
解决: 2 秒时间窗口 + UCI 匹配过滤
  if (!mv.sent && mv.uci === _lastSentUci && Date.now() - _lastSentTime < 2000) {
      return; // skip echo
  }
```

---

## 16. 重连恢复与对局边界检测

### 16.1 对局生命周期

```
对局开始 ←→ 对局进行中 ←→ 对局结束
   │           │              │
  86001     86004/86005    85075/86006×2
  (新局)   (走子)         (结算)
```

**Proxy 侧检测**:
```python
# 新局: 86001 + tableID 变化
if table_changed:
    if self._game_active: self._end_game('new_table')
    self._on_game_begin(self.total)

# 重连: 86001 + 同 tableID + game_active
# → 不触发任何状态变化，保持现有走子记录

# 终局: 86006 RECV × 2 或 85075 RECV (body < 200B)
# → _end_game() 标记所有走子 game_idx，清空 game_active
```

**Renderer 侧检测**:
```javascript
// 新局: [GAME] 开始 → reset + _gameActive = true
// 重连: [86001] + _gameActive == true → restoreMovesFromSession()
//       [86001] + _gameActive == false → SKIP (新局不加旧数据)
// 终局: [GAME] 结束 → reset + _gameActive = false
```

### 16.2 断连恢复机制

**问题**: 断连后重连，棋盘状态丢失怎么办？

**解决方案 — 会话文件回放**:
1. Proxy 每 3 秒保存一次走子到 `qqchess_moves_{ts}.json`
2. 断连时 `websocket_end` 触发 `_save(force=True)` 强制保存
3. 重连时 86001 到达 → `restoreMovesFromSession()`
4. 加载最新 `_moves_` 文件 → 过滤到当前局 (no `game_idx`) → 重置棋盘 → 逐步回放
5. 后续走子直接衔接

**关键设计决策**:
- 断连**不清除** `_gameActive`，走子记录保留
- 重连**不回放**已结束对局的走子（`game_idx` 过滤）
- 新局**不加载**旧数据（`_gameActive` 守卫）

### 16.3 多局累积处理

Proxy 在一次运行中可能经历多局对局:
```
Game 0: moves[m1..m10] → _end_game() 标记 game_idx=0
Game 1: moves[m11..m25] → _end_game() 标记 game_idx=1
Game 2: moves[m26..m30] → 未结束, 无 game_idx
```

`_save()` 保存全部 `self.moves`（含所有局）。Renderer 恢复时通过 `!game_idx` 过滤只回放当前局。

### 16.4 数据文件自动清理

```
触发: 每 30 秒统计刷新 || 每次新文件写入 (5s 防抖)
阈值: 100MB
策略: 按文件名排序（即时间排序）→ 从最旧开始删除 → 直到 < 100MB
文件: 只删除 .json 文件（会话数据），不删其他
```

---

## 17. 已知问题与未来方向

### 17.1 已实现

- [x] WebSocket 帧格式完全破解
- [x] JCE 序列化格式完全破解 (完整的解析器，支持全部类型)
- [x] TEA-CBC 加密算法完全还原（大端标准 TEA，匹配 JS）
- [x] TEA-CBC 加密实现 (Aad) — 可用于构造/重放消息
- [x] 会话密钥派生流程完全还原
- [x] 走子坐标提取（含评分机制、双路径 SEND/RECV）
- [x] HAR 文件离线分析
- [x] 代理会话保存与回放
- [x] mitmproxy 实时抓包
- [x] 棋盘状态 FEN 解析与可视化
- [x] Canvas 中国象棋棋盘渲染 (含中文记谱)
- [x] 阵营检测 (3 条路径，优先级递减)
- [x] 对局边界检测 (新局/终局/重连)
- [x] 断连恢复机制 (会话文件回放)
- [x] 多局累积隔离 (game_idx 标记)
- [x] 皮卡鱼引擎集成 (UCCI 协议)
- [x] AI 引擎实时分析 + 自动走子
- [x] 棋盘红方/黑方翻转
- [x] 中局加入 FEN 同步 (eventID=63)
- [x] 走子回声过滤
- [x] Electron 一键启动封装
- [x] 跨平台打包 (Win/Mac/Linux)
- [x] 首次启动设置引导 (Python/mitmproxy 检测)
- [x] 数据目录自定义 + 自动清理 (> 100MB)
- [x] 日志过滤 (资源日志/QQ象棋日志分离)

### 17.2 已知问题

| 问题 | 严重性 | 说明 |
|------|--------|------|
| FEN 检测不可靠 | 中 | 基于正则的扫描在二进制 payload 中命中率低，仅在 MIDGAME (eventID=63) 中可靠提取 |
| 走子坐标误报 | 中 | 协议固定字段会干扰坐标扫描，评分机制已大幅改善但仍有极低概率误报 |
| `tea_decrypt.py` TEA 实现不一致 | 高 | 使用小端 XXTEA 变体，与 JS 的大端标准 TEA 不匹配；**当前工作实现已迁移到 xq_ws_proxy.py** |
| 两套 TEA 实现并存 | 低 | `xq_ws_proxy.py` 和 `tea_decrypt.py` 有独立实现；`tea_decrypt.py` 可视为遗留实验代码 |
| 无测试框架 | 低 | 纯脚本项目，无 pytest/unittest |
| 观战模式阵营检测 | 中 | 无 SEND 消息，仅依赖 [CAMP] 和 [MIDGAME] FEN |
| macOS 打包无签名 | 中 | 交叉编译无法签名，用户需右键打开绕过 Gatekeeper |
| WebSocket 断开后 proxy 重启 | 低 | 重启后的 proxy 状态丢失，需重新登录才能派生密钥 |
| 引擎自动走子精度 | 低 | 基于 canvas Pixel 坐标映射，屏幕缩放可能偏移 |
| GBK 日志解析 | 低 | 中文 Windows 下 mitmdump 可能输出 GBK，已用双重编码处理 |

### 17.3 未来方向

#### 短期

1. **~~统一 TEA 实现~~** ✅ 已完成 — `xq_ws_proxy.py` 包含完整的大端标准 TEA（加密+解密）
2. **~~改进走子检测~~** ✅ 已完成 — 已利用 msgID 上下文 + 偏移量评分 + 标记字节检测
3. **~~完善 FEN 提取~~** ✅ 已完成 — 从 eventID=63 MIDGAME 消息中可靠提取 FEN
4. **添加 `requirements.txt`** — 列出 `mitmproxy`, `requests` 等依赖

#### 中期

5. **~~Electron 应用完善~~** ✅ 大部分已完成
   - ~~实时显示抓包统计~~ ✅
   - ~~走子历史可视化~~ ✅ (红黑双列)
   - ~~内置棋盘显示~~ ✅ (Canvas 渲染)
   - ~~对接皮卡鱼引擎~~ ✅
   - ~~实时局面评估~~ ✅
   - ~~最佳走法推荐~~ ✅ (棋盘琥珀色标记)
   - 棋局分析报告
   - 托盘图标和菜单

6. **会话管理增强**
   - ~~保存/加载历史会话~~ ✅ (基础版已实现)
   - 多会话对比分析
   - 棋谱导出 (PGN 格式)

7. **macOS 签名公证** — 在 Mac 上打包 + Apple Developer 账号

#### 长期

8. **移动端代理** — 通过 WiFi 代理 + 手机抓包
9. **协议模糊测试** — 向服务端发送变异消息
10. **~~自动化对局bot~~** ✅ 基本实现 — 自动走子模式已可用
11. **完整的 Wireshark dissector** — Lua 插件用于 Wireshark 实时解码
12. **棋谱库** — 积累对局数据，训练象棋 AI 或分析人类走法模式

### 17.4 贡献注意事项

- 本项目的所有代码均为**教育和研究目的**
- 请遵守腾讯 QQ 象棋的用户协议
- 不要将本工具用于破坏游戏公平性或商业盈利
- 抓包数据文件 (`data/sessions/*.json`) 不应提交到公开仓库
- 引擎自动走子仅用于测试和演示，实战中请关闭

---

## 附录 A: 关键常量速查

```python
# TEA
DELTA = 0x9E3779B9
ROUNDS = 16
WJB = 2       # 头部填充
DKB = 7       # 尾部填充
QDE = 4       # delta 左移量 (解密初始 total = DELTA << 4)

# 帧格式
SEND_MAGIC = b'\x01\x10\xcf\x10\x01'
RECV_MAGIC = b'\x0c\x10\x01'

# WebSocket
WS_URL = "wss://wxlogin.qqchess.qq.com:443"
GAME_URL = "https://h5login.qqchess.qq.com/"

# 代理
PROXY_PORT = 8888
PROXY_HOST = "127.0.0.1"

# 初始 FEN
START_FEN = "rnbakabnr/9/1c5c1/p1p1p1p1p/9/9/P1P1P1P1P/1C5C1/9/RNBAKABNR w"

# JCE 类型
JCE_TYPES = {
    0: 'INT1', 1: 'INT2', 2: 'INT4', 3: 'INT8',
    4: 'FLOAT', 5: 'DOUBLE', 6: 'STR1', 7: 'STR4',
    8: 'MAP', 9: 'LIST', 10: 'STRUCT_BEGIN', 11: 'STRUCT_END',
    12: 'ZERO', 13: 'BYTES'
}

# 棋盘坐标
COLS = 'abcdefghi'  # 0-8
ROWS = 10           # 0-9
```

## 附录 B: 消息 ID 速查

```
Heartbeat (心跳):
  85000

Login (登录):
  85001, 89055

Room/Lobby (房间/大厅):
  85005  85006  85008  85018  85031  85039  85047  85053
  85060  85067  85075  85077  85078  85083

Battle (对局):
  86001  86003  86004  86005  86006  86028

Match (匹配):
  89151  89152  85077

Social (社交):
  89113  89115  89150

Shop/Activity (商城/活动):
  85301  85211  85217  85218

System (系统):
  89040  89043  89050  89054  89061  89085
  89100  89300  89504  89505  89513  89621  89671
```

## 附录 C: 依赖安装

```bash
# Python 工具
pip install mitmproxy requests

# Electron 应用
cd electron-app
cnpm install

# 可选: 象棋引擎
# 皮卡鱼 (开源中国象棋引擎)
# 从 https://github.com/pikafish/Pikafish 下载
```

---

> 本文档基于对 QQ 象棋 (天天象棋) H5 客户端和网络协议的数周逆向分析编写。
> 所有发现均为技术研究和学习目的。
