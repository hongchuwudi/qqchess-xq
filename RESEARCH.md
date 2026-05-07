# 天天象棋 (QQ Chess XQ) 网络协议逆向工程 — 完整研究报告

> 最后更新: 2026-05-07
> 作者: Claude Code 协助分析

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
14. [已知问题与未来方向](#14-已知问题与未来方向)

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
├── xq_ws_proxy.py          # [核心] mitmproxy 实时抓包 addon
├── har_analyzer.py          # HAR 离线文件分析器
├── xq_analyzer.py           # 棋局实时分析 + AI 引擎对接
├── xq_decode.py             # JCE 二进制手动解码器 (交互式)
├── tea_decrypt.py           # TEA-CBC 独立解密器
├── download_qqchess.py      # 下载 QQ 象棋 H5 客户端
├── _find_key.py             # [工具] 从登录消息提取 sSecKey
├── _fix_session.py          # [工具] 修复/回放已保存的会话
├── _brute_key.py            # [工具] 暴力尝试会话密钥
├── electron-app/            # Electron 封装 (一键启动)
├── data/
│   ├── h5login.qqchess.qq.com.har  # 127 MB HAR 抓包
│   └── sessions/                   # 代理会话输出 (qqchess_*.json)
├── qqchess_src/             # 下载的游戏客户端源码
├── docs/                    # 分析文档
├── engines/                 # 象棋引擎 (皮卡鱼等)
├── CLAUDE.md                # 项目说明书
└── RESEARCH.md              # 本文档
```

### 12.2 xq_ws_proxy.py — mitmproxy 实时抓包插件

**核心模块，200+ 行 TEA 实现 + 300+ 行 JCE 解析器 + mitmproxy 事件钩子**

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
                    ⑤ 检测 86004/86005/86006 → parse_game_event() → find_moves_in_vec()
                    ⑥ 记录 raw + decoded + moves
       ↓
websocket_end    → _save() 写入 5 个 JSON 文件
```

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
python xq_analyzer.py --session data/sessions/qqchess_ws_raw_20260506_174656.json

# 演示模式 (模拟对局)
python xq_analyzer.py --demo
```

核心类：
- **`XQFenParser`**: FEN 解析/生成/可视化
- **`GameStateTracker`**: 完整对局状态追踪 (走子应用、棋谱记录)
- **`ChessEngine`**: AI 引擎接口 (内置简易评估 + 皮卡鱼对接)
- **`analyze_session()`**: 会话回放，详细的 msgID 时间线和分类统计

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

### 12.6 tea_decrypt.py — TEA 解密器

```bash
# 使用已知密钥解密
python tea_decrypt.py --key <32 hex chars> --raw data/sessions/qqchess_ws_raw_*.json

# 从 uin + sSecKey 派生密钥
python tea_decrypt.py --uin 123456789 --sSecKey <sSecKey_hex> --raw data/sessions/qqchess_ws_raw_*.json

# 分析 HAR 文件
python tea_decrypt.py --har data/h5login.qqchess.qq.com.har --uin 123 --sSecKey abc...

# 自测
python tea_decrypt.py --test
```

**注意**: 此文件的 TEA 实现为小端 XXTEA 变体，是早期实验版本。`xq_ws_proxy.py` 中的大端标准 TEA 实现才是与 JS 客户端匹配的正确版本。

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

### 13.1 架构

```
┌───────────────────────────────────────────┐
│           Electron Main Process           │
│                                           │
│  ┌─────────────┐  ┌───────────────────┐   │
│  │ mitmdump     │  │ session.setProxy()│   │
│  │ child_process│  │ → 127.0.0.1:8888 │   │
│  │ -s xq_ws_   │  └───────────────────┘   │
│  │   proxy.py  │                          │
│  └─────────────┘                          │
│                                           │
│  ┌───────────────────────────────────┐    │
│  │ BrowserWindow                     │    │
│  │ → https://h5login.qqchess.qq.com  │    │
│  └───────────────────────────────────┘    │
└───────────────────────────────────────────┘
```

### 13.2 核心代码

```javascript
// main.js 关键部分

// 1. 启动 mitmproxy
function startMitmproxy() {
    mitmProcess = spawn("mitmdump", [
        "--listen-port", "8888",
        "-s", "../xq_ws_proxy.py",
        "--set", "block_global=false",
        "--ssl-insecure",
    ]);
}

// 2. 自动配置代理 (无需手动设 Windows 代理!)
function configureSession() {
    session.defaultSession.setProxy({
        proxyRules: "http://127.0.0.1:8888",
        proxyBypassRules: "<-loopback>",
    });
    
    // 忽略 mitmproxy 的 CA 证书错误
    app.commandLine.appendSwitch("ignore-certificate-errors");
    session.defaultSession.setCertificateVerifyProc((req, cb) => cb(0));
}

// 3. 加载游戏
function createWindow() {
    const win = new BrowserWindow({ width: 430, height: 700 });
    win.loadURL("https://h5login.qqchess.qq.com/");
}
```

### 13.3 优势

- 一键启动，零配置
- 无需手动设置 Windows 系统代理
- 无需安装 mitmproxy CA 证书
- 游戏加载和抓包完全自动化
- 抓包数据自动保存到 `data/sessions/`

### 13.4 启动方式

```bash
cd electron-app
npm start
```

前提条件：
- `mitmdump` 在 PATH 中：`pip install mitmproxy`
- 依赖已安装：`cnpm install`

---

## 14. 已知问题与未来方向

### 14.1 已实现

- [x] WebSocket 帧格式完全破解
- [x] JCE 序列化格式完全破解 (完整的解析器)
- [x] TEA-CBC 加密算法完全还原（大端标准 TEA，匹配 JS）
- [x] 会话密钥派生流程完全还原
- [x] 走子坐标提取（含评分机制）
- [x] HAR 文件离线分析
- [x] 代理会话保存与回放
- [x] mitmproxy 实时抓包
- [x] 棋盘状态 FEN 解析与可视化
- [x] AI 引擎接口框架
- [x] Electron 一键启动封装

### 14.2 已知问题

| 问题 | 严重性 | 说明 |
|------|--------|------|
| FEN 检测不可靠 | 中 | 基于正则的扫描在二进制 payload 中命中率低，大多数消息不包含完整 FEN |
| 走子坐标误报 | 中 | 协议固定字段 (如 iClientVer=0 的 tag=0 type=0 编码) 会干扰坐标扫描 |
| `tea_decrypt.py` TEA 实现不一致 | 高 | 使用小端 XXTEA 变体，与 JS 客户端的大端标准 TEA 不匹配 |
| 两套 TEA 实现并存 | 中 | `xq_ws_proxy.py` 和 `tea_decrypt.py` 有独立的 TEA 实现，需统一 |
| 本地文件加载缺失资源 | 低 | `qqchess_src/index.html` 缺少 Cocos 引擎和部分 JS，无法离线运行 |
| 无测试框架 | 低 | 纯脚本项目，无 pytest/unittest |
| Windows 特定路径 | 低 | 部分硬编码路径针对 Windows |

### 14.3 未来方向

#### 短期

1. **统一 TEA 实现** — 将 `xq_ws_proxy.py` 中的正确 TEA 实现提取为独立模块 `tea_core.py`
2. **改进走子检测** — 利用 msgID 上下文过滤候选，减少误报
3. **完善 FEN 提取** — 从解密后的 plaintext 中提取 FEN，而非从二进制扫描
4. **添加 `requirements.txt`** — 列出 `mitmproxy`, `requests` 等依赖

#### 中期

5. **Electron 应用完善**
   - 添加托盘图标和菜单
   - 实时显示抓包统计
   - 走子历史可视化
   - 内置棋盘显示

6. **AI 引擎深度集成**
   - 对接皮卡鱼引擎
   - 实时局面评估
   - 最佳走法推荐
   - 棋局分析报告

7. **会话管理**
   - 保存/加载历史会话
   - 多会话对比分析
   - 棋谱导出 (PGN 格式)

#### 长期

8. **移动端代理** — 通过 WiFi 代理 + 手机抓包
9. **协议模糊测试** — 向服务端发送变异消息
10. **自动化对局bot** — 解析协议后实现自动走子
11. **完整的 Wireshark dissector** — Lua 插件用于 Wireshark 实时解码

### 14.4 贡献注意事项

- 本项目的所有代码均为**教育和研究目的**
- 请遵守腾讯 QQ 象棋的用户协议
- 不要将本工具用于破坏游戏公平性或商业盈利
- 抓包数据文件 (`data/sessions/*.json`) 不应提交到公开仓库

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
