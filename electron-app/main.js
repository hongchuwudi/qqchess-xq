const { app, BrowserWindow, screen, session, ipcMain, dialog, Menu } = require("electron");
const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");
const net = require("net");
const { PikafishBridge } = require("./pikafish-bridge");

// ── Config ──────────────────────────────────────────────────────────────
const PROXY_HOST = "127.0.0.1";
const PROXY_PORT = 8888;
const PROXY_URL = `http://${PROXY_HOST}:${PROXY_PORT}`;
const GAME_URL = "https://h5login.qqchess.qq.com/";
const SESSIONS_DIR = (() => {
  const p = app.isPackaged
    ? path.join(app.getPath("userData"), "sessions")
    : path.join(__dirname, "..", "data", "sessions");
  fs.mkdirSync(p, { recursive: true });
  return p;
})();
const MAX_LOGS = 500;

// Resolve paths for dev (__dirname) vs packaged (process.resourcesPath)
function _resPath(...parts) {
  const base = app.isPackaged ? process.resourcesPath : path.join(__dirname, "..");
  return path.join(base, ...parts);
}
const PYTHON_DIR = app.isPackaged
  ? path.join(process.resourcesPath, "python")
  : path.join(__dirname, "python");
const PYTHON_EXE = path.join(PYTHON_DIR, "python.exe");
const MITMDUMP_EXE = path.join(PYTHON_DIR, "Scripts", "mitmdump.exe");
const ADDON_PATH = _resPath("xq_ws_proxy.py");
const ENGINE_DIR = _resPath("engines", "pikayu-20260131");

// ── State ───────────────────────────────────────────────────────────────
let mitmProcess = null;
let controlWindow = null;
let gameWebContents = null;
let logs = [];
let moves = [];
let proxyRunning = false;
let sessionStats = { moves: 0 };
let pikafish = null;

// ── Log management ──────────────────────────────────────────────────────
let _statusTimer = null;
let _gbkDecoder = null;

// Decode mitmdump output. On Chinese Windows, mitmdump may emit GBK
// bytes despite PYTHONUTF8=1. Try UTF-8 first; fall back to GBK.
function _decodeMitm(buf) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(buf);
  } catch (_) {
    try {
      if (!_gbkDecoder) _gbkDecoder = new TextDecoder("gbk");
      return _gbkDecoder.decode(buf);
    } catch (_) {
      return buf.toString();
    }
  }
}

// Filter out mitmdump HTTP/WS resource logs — keep only QQ Chess addon output
function _isResourceLog(line) {
  // mitmdump flow request: "IP:PORT: METHOD URL ..."
  if (/^\d+\.\d+\.\d+\.\d+:\d+:\s+(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT|PATCH)\s/i.test(line)) return true;
  // HTTP response: "<< HTTP/2.0 304 ..." or "<< 101 Switching Protocols ..."
  if (/^<<\s+/i.test(line)) return true;
  // WS flow: "IP:PORT -> WebSocket binary message -> HOST"
  if (/\d+\.\d+\.\d+\.\d+:\d+\s*(->|<-)\s*WebSocket/i.test(line)) return true;
  // TCP connection messages
  if (/(?:server|client)\s+(?:connection|disconnect)/i.test(line)) return true;
  return false;
}

function addLog(msg) {
  logs.push({ time: new Date().toISOString(), text: msg });
  if (logs.length > MAX_LOGS) logs = logs.slice(-MAX_LOGS);

  // Incremental stats for move count
  if (msg.includes(">>> [MOVE") || msg.includes(">>> [MOVE SENT")) {
    sessionStats.moves++;
  }

  if (controlWindow && !controlWindow.isDestroyed()) {
    controlWindow.webContents.send("log-line", { time: logs[logs.length - 1].time, text: msg });
  }

  // Throttle status pushes to at most once per 500ms
  if (!_statusTimer) {
    _statusTimer = setTimeout(() => {
      notifyStatus();
      _statusTimer = null;
    }, 500);
  }
}

function notifyStatus() {
  if (controlWindow && !controlWindow.isDestroyed()) {
    controlWindow.webContents.send("proxy-status", {
      running: proxyRunning,
      host: PROXY_HOST,
      port: PROXY_PORT,
      stats: { ...sessionStats },
    });
  }
}

// ── mitmproxy management ────────────────────────────────────────────────
function isMitmdumpAvailable() {
  const result = require("child_process").spawnSync(MITMDUMP_EXE, ["--version"], {
    stdio: "ignore",
    windowsHide: true,
  });
  return result.status === 0;
}

function startMitmproxy() {
  if (mitmProcess) {
    addLog("[main] mitmproxy already running");
    return true;
  }

  if (!fs.existsSync(ADDON_PATH)) {
    addLog("[main] ERROR: xq_ws_proxy.py not found");
    dialog.showErrorBox("启动失败", `找不到代理脚本:\n${ADDON_PATH}`);
    return false;
  }

  // Ensure mitmproxy is installed in portable Python
  if (!isMitmdumpAvailable()) {
    addLog("[main] mitmproxy not installed, installing...");
    const install = require("child_process").spawnSync(PYTHON_EXE, ["-m", "pip", "install", "mitmproxy"], {
      stdio: "pipe",
      windowsHide: true,
      timeout: 120000,
    });
    if (install.status !== 0) {
      addLog("[main] ERROR: mitmproxy install failed");
      return false;
    }
    addLog("[main] mitmproxy installed");
  }

  addLog(`[main] Starting mitmdump on port ${PROXY_PORT}...`);

  mitmProcess = spawn(MITMDUMP_EXE, [
    "--listen-port", String(PROXY_PORT),
    "-s", ADDON_PATH,
    "--set", "block_global=false",
    "--ssl-insecure",
  ], {
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
    env: { ...process.env, PYTHONUTF8: "1", PYTHONUNBUFFERED: "1", PYTHONIOENCODING: "utf-8", QQCHESS_DATA_DIR: SESSIONS_DIR },
  });

  mitmProcess.stdout.on("data", (data) => {
    for (const line of _decodeMitm(data).split("\n")) {
      const trimmed = line.trim();
      if (trimmed && !_isResourceLog(trimmed)) {
        addLog(trimmed);
      }
    }
    notifyStatus();
  });

  mitmProcess.stderr.on("data", (data) => {
    for (const line of _decodeMitm(data).split("\n")) {
      const trimmed = line.trim();
      if (trimmed) {
        addLog("[stderr] " + trimmed);
      }
    }
  });

  mitmProcess.on("error", (err) => {
    addLog(`[main] mitmproxy error: ${err.message}`);
    proxyRunning = false;
    mitmProcess = null;
    notifyStatus();
  });

  mitmProcess.on("exit", (code) => {
    addLog(`[main] mitmproxy exited (code=${code})`);
    proxyRunning = false;
    mitmProcess = null;
    notifyStatus();
  });

  return true;
}

function stopMitmproxy() {
  if (!mitmProcess) return;
  addLog("[main] Stopping mitmproxy...");
  try {
    mitmProcess.kill("SIGTERM");
  } catch (e) {
    // process may already be dead
  }
  mitmProcess = null;
  proxyRunning = false;
  notifyStatus();
}

async function waitForProxy(timeoutMs = 8000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      await new Promise((resolve, reject) => {
        const sock = new net.Socket();
        sock.setTimeout(300, () => {
          sock.destroy();
          reject(new Error("timeout"));
        });
        sock.connect(PROXY_PORT, PROXY_HOST, () => {
          sock.destroy();
          resolve();
        });
        sock.on("error", (err) => {
          sock.destroy();
          reject(err);
        });
      });
      proxyRunning = true;
      notifyStatus();
      addLog("[main] Proxy health check OK");
      return true;
    } catch (e) {
      await new Promise((r) => setTimeout(r, 300));
    }
  }
  addLog("[main] WARNING: Proxy health check timed out (port not open)");
  // Still mark as running since mitmdump may need more time
  proxyRunning = true;
  notifyStatus();
  return false;
}

// ── Session configuration ───────────────────────────────────────────────
function configureSession() {
  const ses = session.defaultSession;

  // Original config that worked: proxy all, bypass only OAuth
  ses.setProxy({
    proxyRules: PROXY_URL,
    proxyBypassRules: "<-loopback>,graph.qq.com",
  }).then(() => {
    addLog("[main] Proxy configured -> " + PROXY_URL);
  }).catch((err) => {
    addLog("[main] Proxy config failed: " + err.message);
  });

  app.commandLine.appendSwitch("ignore-certificate-errors");
}

// ── Windows ─────────────────────────────────────────────────────────────
function getWindowBounds() {
  const { width, height } = screen.getPrimaryDisplay().workAreaSize;
  return { width, height };
}

function createControlWindow() {
  const { width, height } = getWindowBounds();

  controlWindow = new BrowserWindow({
    x: 0,
    y: 0,
    width: width,
    height: height,
    minWidth: 960,
    minHeight: 600,
    resizable: true,
    title: "QQ Chess Proxy",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      webviewTag: true,
    },
  });

  controlWindow.loadFile(path.join(__dirname, "index.html"));

  // Proxy for game webview
  controlWindow.webContents.on("did-attach-webview", (_event, wc) => {
    gameWebContents = wc;
    wc.session.setProxy({
      proxyRules: PROXY_URL,
      proxyBypassRules: "<-loopback>,graph.qq.com",
    }).catch(() => {});
    wc.on("destroyed", () => { gameWebContents = null; });
  });

  controlWindow.on("closed", () => {
    controlWindow = null;
    stopMitmproxy();
  });

  if (process.argv.includes("--dev")) {
    controlWindow.webContents.openDevTools({ mode: "detach" });
  }

  controlWindow.webContents.on("did-finish-load", () => {
    notifyStatus();
  });
}

function getGameWebContents() {
  return gameWebContents;
}

// ── Session file watcher ────────────────────────────────────────────────
let sessionWatcher = null;

function watchSessionFiles() {
  try {
    fs.mkdirSync(SESSIONS_DIR, { recursive: true });
  } catch (e) {
    // directory exists
  }

  try {
    sessionWatcher = fs.watch(SESSIONS_DIR, (eventType, filename) => {
      if (!filename || !filename.endsWith(".json")) return;
      if (controlWindow && !controlWindow.isDestroyed()) {
        controlWindow.webContents.send("session-file-changed", filename);
      }
    });
  } catch (e) {
    addLog(`[main] Cannot watch sessions dir: ${e.message}`);
  }
}

// ── App menu ────────────────────────────────────────────────────────────
function buildMenu() {
  const template = [
    {
      label: "文件",
      submenu: [
        {
          label: "打开游戏窗口",
          accelerator: "CmdOrCtrl+G",
          click: () => {
            if (controlWindow && !controlWindow.isDestroyed()) {
              controlWindow.webContents.send("launch-game", GAME_URL);
            }
          },
        },
        {
          label: "打开会话目录",
          click: () => {
            const { shell } = require("electron");
            shell.openPath(SESSIONS_DIR);
          },
        },
        { type: "separator" },
        {
          label: "退出",
          accelerator: "CmdOrCtrl+Q",
          click: () => app.quit(),
        },
      ],
    },
    {
      label: "代理",
      submenu: [
        {
          label: "启动代理",
          click: () => {
            if (!proxyRunning) {
              startMitmproxy();
              waitForProxy();
            }
          },
        },
        {
          label: "停止代理",
          click: () => stopMitmproxy(),
        },
        { type: "separator" },
        {
          label: "重新启动代理",
          click: () => {
            stopMitmproxy();
            setTimeout(() => {
              startMitmproxy();
              waitForProxy();
            }, 500);
          },
        },
      ],
    },
    {
      label: "视图",
      submenu: [
        { role: "reload" },
        { role: "forceReload" },
        { role: "toggleDevTools" },
        { type: "separator" },
        { role: "resetZoom" },
        { role: "zoomIn" },
        { role: "zoomOut" },
      ],
    },
  ];

  const menu = Menu.buildFromTemplate(template);
  Menu.setApplicationMenu(menu);
}

// ── IPC handlers ────────────────────────────────────────────────────────
function setupIPC() {
  ipcMain.handle("get-proxy-status", () => ({
    running: proxyRunning,
    host: PROXY_HOST,
    port: PROXY_PORT,
    stats: { ...sessionStats },
    mitmPid: mitmProcess ? mitmProcess.pid : null,
  }));

  ipcMain.handle("get-logs", () => logs.slice(-200));

  ipcMain.handle("get-moves", () => moves);

  ipcMain.handle("clear-logs", () => {
    logs = [];
    sessionStats = { moves: 0 };
    moves = [];
    notifyStatus();
    return true;
  });

  ipcMain.handle("launch-game", () => {
    addLog("[main] launch-game clicked");
    // Renderer sets webview src directly
    return { url: GAME_URL };
  });

  ipcMain.handle("stop-proxy", () => {
    stopMitmproxy();
    return true;
  });

  ipcMain.handle("start-proxy", () => {
    if (proxyRunning) {
      addLog("[main] Proxy already running");
      return true;
    }
    if (startMitmproxy()) {
      waitForProxy();
    }
    return true;
  });

  ipcMain.handle("restart-proxy", () => {
    stopMitmproxy();
    setTimeout(() => {
      if (startMitmproxy()) waitForProxy();
    }, 500);
    return true;
  });

  ipcMain.handle("get-session-files", () => {
    try {
      if (!fs.existsSync(SESSIONS_DIR)) return [];
      return fs.readdirSync(SESSIONS_DIR)
        .filter((f) => f.endsWith(".json"))
        .sort()
        .reverse()
        .slice(0, 200)
        .map((f) => ({
          name: f,
          path: path.join(SESSIONS_DIR, f),
          size: fs.statSync(path.join(SESSIONS_DIR, f)).size,
          mtime: fs.statSync(path.join(SESSIONS_DIR, f)).mtime.toISOString(),
        }));
    } catch (e) {
      return [];
    }
  });

  ipcMain.handle("read-session-file", (_event, filename) => {
    try {
      const filepath = path.join(SESSIONS_DIR, path.basename(filename));
      if (!fs.existsSync(filepath)) return null;
      return JSON.parse(fs.readFileSync(filepath, "utf-8"));
    } catch (e) {
      return null;
    }
  });

  ipcMain.handle("open-sessions-dir", () => {
    const { shell } = require("electron");
    shell.openPath(SESSIONS_DIR);
    return true;
  });

  ipcMain.handle("analyze-position", async (_event, fen, moveList) => {
    if (!pikafish || !pikafish.isReady) {
      return { error: "Engine not ready" };
    }
    try {
      const result = await pikafish.analyze(fen, moveList);
      return result;
    } catch (e) {
      return { error: e.message };
    }
  });

  ipcMain.handle("get-engine-status", () => {
    return {
      available: pikafish !== null,
      ready: pikafish ? pikafish.isReady : false,
      path: pikafish ? pikafish.enginePath : null,
    };
  });

  ipcMain.handle("autoplay-move", async (_event, uci) => {
    if (!gameWebContents || gameWebContents.isDestroyed()) {
      addLog("[autoplay] Game webview not available");
      return false;
    }
    if (!uci || uci.length < 4) {
      addLog("[autoplay] Invalid UCI: " + uci);
      return false;
    }
    addLog("[autoplay] Injecting move: " + uci);

    try {
      await gameWebContents.executeJavaScript(`
        (function(uci) {
          const cols = 'abcdefghi';
          const fc = cols.indexOf(uci[0]);
          const fr = parseInt(uci[1]);
          const tc = cols.indexOf(uci[2]);
          const tr = parseInt(uci[3]);
          if (fc < 0 || tc < 0 || isNaN(fr) || isNaN(tr)) return 'bad uci';

          // Find the game canvas (Cocos Creator renders on a canvas)
          const canvas = document.querySelector('canvas');
          if (!canvas) return 'no canvas';

          const rect = canvas.getBoundingClientRect();
          // Board area: ~5% margin on each side
          const ml = rect.width * 0.05;
          const mt = rect.height * 0.05;
          const bw = rect.width * 0.9;
          const bh = rect.height * 0.9;
          const cellW = bw / 8;   // 9 columns → 8 gaps
          const cellH = bh / 9;   // 10 rows → 9 gaps

          const fromX = rect.left + ml + fc * cellW;
          const fromY = rect.top + mt + fr * cellH;
          const toX = rect.left + ml + tc * cellW;
          const toY = rect.top + mt + tr * cellH;

          function firePointer(x, y, type) {
            canvas.dispatchEvent(new PointerEvent(type, {
              bubbles: true, cancelable: true,
              clientX: x, clientY: y,
              pointerId: 1, pointerType: 'mouse',
              isPrimary: true, pressure: 0.5,
            }));
          }

          // Click source square
          firePointer(fromX, fromY, 'pointerdown');
          firePointer(fromX, fromY, 'pointerup');

          // Brief delay then click target
          return new Promise((resolve) => {
            setTimeout(() => {
              firePointer(toX, toY, 'pointerdown');
              firePointer(toX, toY, 'pointerup');
              resolve('ok:' + uci);
            }, 180);
          });
        })('${uci}')
      `);
      return true;
    } catch (e) {
      addLog("[autoplay] Injection failed: " + e.message);
      return false;
    }
  });
}

// ── App lifecycle ───────────────────────────────────────────────────────
app.whenReady().then(async () => {
  const startupMsg = `[main] QQ Chess Proxy starting -- ${new Date().toLocaleString()}  port: ${PROXY_PORT}`;
  console.log(startupMsg);
  addLog("[main] ========================================");
  addLog(`[main] QQ Chess Proxy starting -- ${new Date().toLocaleString()}`);
  addLog(`[main] port: ${PROXY_PORT}  |  game: ${GAME_URL}`);
  addLog(`[main] 数据目录: ${SESSIONS_DIR}`);
  addLog("[main] ========================================");

  buildMenu();
  setupIPC();
  configureSession();
  watchSessionFiles();

  // Create control window FIRST so engine/proxy logs are visible in real time
  createControlWindow();

  // Wait for renderer to be ready before starting engine (so IPC pushes land)
  await new Promise((r) => controlWindow.webContents.on("did-finish-load", r));

  // Start Pikafish engine
  pikafish = new PikafishBridge(ENGINE_DIR);
  pikafish._onLog = (msg) => addLog(msg);
  pikafish._onReady = (name) => {
    addLog(`[main] Pikafish engine ready: ${name}`);
    if (controlWindow && !controlWindow.isDestroyed()) {
      controlWindow.webContents.send("engine-status", { ready: true, name });
    }
  };
  pikafish._onExit = () => {
    addLog("[main] Pikafish engine exited or failed to start");
    if (controlWindow && !controlWindow.isDestroyed()) {
      controlWindow.webContents.send("engine-status", { ready: false, name: null });
    }
  };
  const engineOk = pikafish.start();
  if (engineOk) {
    const msg = "[main] Pikafish engine starting (waiting for UCCI handshake)...";
    console.log(msg);
    addLog(msg);
  } else {
    const msg = "[main] Pikafish engine not available — analysis disabled";
    console.log(msg);
    addLog(msg);
    if (controlWindow && !controlWindow.isDestroyed()) {
      controlWindow.webContents.send("engine-status", { ready: false, name: null });
    }
  }

  const started = startMitmproxy();
  if (started) {
    console.log(`[main] mitmproxy started on port ${PROXY_PORT}, waiting for health check...`);
    await waitForProxy();
  }

  // Game is loaded in webview via "启动游戏" button
});

app.on("window-all-closed", () => {
  stopMitmproxy();
  if (pikafish) { pikafish.stop(); pikafish = null; }
  if (sessionWatcher) {
    sessionWatcher.close();
    sessionWatcher = null;
  }
  app.quit();
});

app.on("before-quit", () => {
  stopMitmproxy();
  if (pikafish) { pikafish.stop(); pikafish = null; }
  if (sessionWatcher) {
    sessionWatcher.close();
    sessionWatcher = null;
  }
});

app.on("activate", () => {
  // macOS: re-create control window when dock icon clicked
  if (BrowserWindow.getAllWindows().length === 0) {
    createControlWindow();
  }
});
