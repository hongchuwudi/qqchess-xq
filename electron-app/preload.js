const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("qqchess", {
  // ── Request/response (invoke) ──
  getProxyStatus: () => ipcRenderer.invoke("get-proxy-status"),
  getLogs: () => ipcRenderer.invoke("get-logs"),
  getMoves: () => ipcRenderer.invoke("get-moves"),
  clearLogs: () => ipcRenderer.invoke("clear-logs"),
  launchGame: () => ipcRenderer.invoke("launch-game"),
  stopProxy: () => ipcRenderer.invoke("stop-proxy"),
  startProxy: () => ipcRenderer.invoke("start-proxy"),
  restartProxy: () => ipcRenderer.invoke("restart-proxy"),
  getSessionFiles: () => ipcRenderer.invoke("get-session-files"),
  readSessionFile: (filename) => ipcRenderer.invoke("read-session-file", filename),
  openSessionsDir: () => ipcRenderer.invoke("open-sessions-dir"),
  getDataStats: () => ipcRenderer.invoke("get-data-stats"),
  getDataDir: () => ipcRenderer.invoke("get-data-dir"),
  chooseDataDir: () => ipcRenderer.invoke("choose-data-dir"),
  cleanupOldData: () => ipcRenderer.invoke("cleanup-old-data"),
  detectPython: () => ipcRenderer.invoke("detect-python"),

  // ── Engine (Pikafish) ──
  analyzePosition: (fen, moveList) => ipcRenderer.invoke("analyze-position", fen, moveList),
  getEngineStatus: () => ipcRenderer.invoke("get-engine-status"),

  // ── Auto-play ──
  autoPlayMove: (uci) => ipcRenderer.invoke("autoplay-move", uci),

  // ── Event listeners (main → renderer push) ──
  onLogLine: (callback) => {
    const handler = (_event, data) => callback(data);
    ipcRenderer.on("log-line", handler);
    return () => ipcRenderer.removeListener("log-line", handler);
  },
  onShowSetup: (callback) => {
    const handler = () => callback();
    ipcRenderer.on("show-setup", handler);
    return () => ipcRenderer.removeListener("show-setup", handler);
  },
  onProxyStatus: (callback) => {
    const handler = (_event, data) => callback(data);
    ipcRenderer.on("proxy-status", handler);
    return () => ipcRenderer.removeListener("proxy-status", handler);
  },
  onLaunchGame: (callback) => {
    const handler = (_event, url) => callback(url);
    ipcRenderer.on("launch-game", handler);
    return () => ipcRenderer.removeListener("launch-game", handler);
  },
  onGameClosed: (callback) => {
    const handler = () => callback();
    ipcRenderer.on("game-closed", handler);
    return () => ipcRenderer.removeListener("game-closed", handler);
  },
  onSessionFileChanged: (callback) => {
    const handler = (_event, filename) => callback(filename);
    ipcRenderer.on("session-file-changed", handler);
    return () => ipcRenderer.removeListener("session-file-changed", handler);
  },
  onEngineStatus: (callback) => {
    const handler = (_event, data) => callback(data);
    ipcRenderer.on("engine-status", handler);
    return () => ipcRenderer.removeListener("engine-status", handler);
  },
});
