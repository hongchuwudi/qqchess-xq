// ── DOM refs ────────────────────────────────────────────────────────────
const $ = (sel) => document.querySelector(sel);

const dom = {
  // Status
  mySide: $("#my-side"),
  statusDot: $("#status-dot"),
  statusText: $("#status-text"),
  statMoves: $("#stat-moves"),
  statDataSize: $("#stat-data-size"),
  statDataLabel: $("#stat-data-label"),
  statDataCard: $("#stat-data-card"),
  // Log
  logView: $("#log-view"),
  logCount: $("#log-count"),
  moveListRed: $("#move-list-red"),
  moveListBlack: $("#move-list-black"),
  moveCount: $("#move-count"),
  movesSection: $("#moves-section"),
  // Buttons
  btnGame: $("#btn-game"),
  btnProxy: $("#btn-proxy"),
  btnRestart: $("#btn-restart"),
  btnAnalyze: $("#btn-analyze"),
  btnAutoplay: $("#btn-autoplay"),
  btnFlip: $("#btn-flip"),
  btnClear: $("#btn-clear"),
  btnSessions: $("#btn-sessions"),
  // Filters
  filterMoves: $("#filter-moves"),
  filterMsgs: $("#filter-msgs"),
  // Engine
  enginePanel: $("#engine-panel"),
  engineDot: $("#engine-dot"),
  engineStatusText: $("#engine-status-text"),
  engineDepth: $("#engine-depth"),
  engineBody: $("#engine-body"),
  engineBestmove: $("#engine-bestmove"),
  engineBestmoveCn: $("#engine-bestmove-cn"),
  engineScore: $("#engine-score"),
  enginePv: $("#engine-pv"),
  engineFen: $("#engine-fen"),
  boardCanvas: $("#board-canvas"),
  btnCopyLog: $("#btn-copy-log"),
};

// ── GameStateTracker — Chinese chess board state ────────────────────────
const INITIAL_FEN = "rnbakabnr/9/1c5c1/p1p1p1p1p/9/9/P1P1P1P1P/1C5C1/9/RNBAKABNR w";

const GameStateTracker = {
  board: null,    // 2D array 10x9
  side: "w",      // "w" = red to move, "b" = black to move
  fen: INITIAL_FEN,
  moveCount: 0,
  lastUci: null,

  reset() {
    this.fen = INITIAL_FEN;
    this.board = this.parseFen(INITIAL_FEN);
    this.side = "w";
    this.moveCount = 0;
    this.lastUci = null;
  },

  // Parse FEN string → { grid: 10x9, side: "w"|"b" }
  parseFen(fenStr) {
    const parts = fenStr.trim().split(/\s+/);
    const rows = parts[0].split("/");
    if (rows.length !== 10) return null;

    const grid = [];
    for (const rowStr of rows) {
      const row = [];
      for (const ch of rowStr) {
        if (ch >= "1" && ch <= "9") {
          for (let i = 0; i < parseInt(ch); i++) row.push(".");
        } else {
          row.push(ch);
        }
      }
      if (row.length !== 9) return null;
      grid.push(row);
    }

    return {
      grid,
      side: parts[1] || "w",
    };
  },

  // Convert board state → FEN string
  toFen(grid, side) {
    const rows = [];
    for (const row of grid) {
      let empty = 0;
      let s = "";
      for (const cell of row) {
        if (cell === ".") {
          empty++;
        } else {
          if (empty > 0) { s += String(empty); empty = 0; }
          s += cell;
        }
      }
      if (empty > 0) s += String(empty);
      rows.push(s);
    }
    return rows.join("/") + " " + (side || "w");
  },

  // Apply a UCI move string. sent=true means user's own move; sent=false means opponent.
  // skipValidation=true skips the piece-color check (used for mid-game join without FEN).
  applyMove(uci, sent, skipValidation) {
    if (!uci || uci.length < 4) return null;
    if (uci === this.lastUci) return null;

    const cols = "abcdefghi";
    const fc = cols.indexOf(uci[0]);
    const fr = parseInt(uci[1]);
    const tc = cols.indexOf(uci[2]);
    const tr = parseInt(uci[3]);

    if (fc < 0 || tc < 0 || isNaN(fr) || isNaN(tr)) return null;
    if (fr < 0 || fr > 9 || tr < 0 || tr > 9) return null;
    if (fc === tc && fr === tr) return null;

    const grid = this.board ? this.board.grid.map((r) => [...r]) : this.parseFen(INITIAL_FEN).grid;
    const piece = grid[fr][fc];
    if (!piece || piece === ".") return null;

    // Piece-color validation skipped: proxy camp detection is authoritative,
    // and proxy<->FEN coordinate mapping has not been verified.

    // Build Chinese notation BEFORE mutating the board
    const chinese = this._toChinese(uci, piece, fc, fr, tc, tr);

    grid[fr][fc] = ".";
    grid[tr][tc] = piece;

    this.side = this.side === "w" ? "b" : "w";
    this.fen = this.toFen(grid, this.side);
    this.board = this.parseFen(this.fen);
    this.moveCount++;
    this.lastUci = uci;
    this.lastChinese = chinese;

    return { fen: this.fen, chinese, isRed: piece === piece.toUpperCase() };
  },

  // UCI → Chinese chess notation (e.g. "h2e2" → "炮8平5")
  _toChinese(uci, piece, fc, fr, tc, tr) {
    const isRed = piece === piece.toUpperCase();
    const redCols = "九八七六五四三二一";
    const blackCols = "123456789";
    const pieceNames = {
      K: "帥", A: "仕", B: "相", N: "馬", R: "車", C: "砲", P: "兵",
      k: "将", a: "士", b: "象", n: "马", r: "车", c: "炮", p: "卒",
    };
    const straightPieces = new Set(["R", "C", "K", "P", "r", "c", "k", "p"]);

    const name = pieceNames[piece] || piece;
    const isStraight = straightPieces.has(piece);

    let fromCol, toCol, action, number;

    if (isRed) {
      fromCol = redCols[fc];       // col 0(a)→九, col 8(i)→一
      toCol = redCols[tc];
      if (fr === tr) {
        action = "平";
        number = toCol;
      } else if (tr < fr) {
        action = "进";
        number = isStraight ? String(fr - tr) : toCol;
      } else {
        action = "退";
        number = isStraight ? String(tr - fr) : toCol;
      }
    } else {
      fromCol = blackCols[fc];     // col 0→1, col 8→9
      toCol = blackCols[tc];
      if (fr === tr) {
        action = "平";
        number = toCol;
      } else if (tr > fr) {
        action = "进";
        number = isStraight ? String(tr - fr) : toCol;
      } else {
        action = "退";
        number = isStraight ? String(fr - tr) : toCol;
      }
    }

    return `${name}${fromCol}${action}${number}`;
  },

  // Public: get Chinese notation for a UCI from current board (read-only)
  uciToChinese(uci) {
    const cols = "abcdefghi";
    const fc = cols.indexOf(uci[0]);
    const fr = parseInt(uci[1]);
    const tc = cols.indexOf(uci[2]);
    const tr = parseInt(uci[3]);
    if (fc < 0 || tc < 0 || isNaN(fr) || isNaN(tr)) return uci;
    if (!this.board) return uci;
    const piece = this.board.grid[fr] && this.board.grid[fr][fc];
    if (!piece || piece === ".") return uci;
    return this._toChinese(uci, piece, fc, fr, tc, tr);
  },
};

// Init tracker
GameStateTracker.reset();

// ── Board drawing ───────────────────────────────────────────────────────
const BOARD_COLS = "abcdefghi";
const BOARD_W = 300, BOARD_H = 330;
const ML = 24, MR = 12, MT = 12, MB = 12; // margins
const BW = BOARD_W - ML - MR; // 264
const BH = BOARD_H - MT - MB; // 306
const DX = BW / 8;  // ~33px between vertical lines
const DY = BH / 9;  // ~34px between horizontal lines
const RR = 13;       // piece circle radius

const PIECE_GLYPHS = {
  K: "帥", A: "仕", B: "相", N: "馬", R: "車", C: "砲", P: "兵",
  k: "將", a: "士", b: "象", n: "馬", r: "車", c: "炮", p: "卒",
};

let _userSide = null;  // "w" = user is Red, "b" = user is Black (detected from first move)
let _lastSentTime = 0; // timestamp of last SENT move, for filtering echo false-positives
let _lastSentUci = null; // UCI of last SENT move, for echo filtering
let _lastFrom = null, _lastTo = null;
let _bestFrom = null, _bestTo = null;

// Proxy uses player-relative coords (row 5-9 = player pieces).
// Red user: proxy == FEN (red bottom). Black user: need 9-row flip.
function proxyToFenUci(uci) {
  if (!uci || uci.length < 4) return uci;
  if (_userSide !== "b") return uci;
  const fr = parseInt(uci[1]), tr = parseInt(uci[3]);
  if (isNaN(fr) || isNaN(tr)) return uci;
  return uci[0] + (9 - fr) + uci[2] + (9 - tr) + uci.substring(4);
}

function setLastMove(uci) {
  const fc = BOARD_COLS.indexOf(uci[0]), fr = parseInt(uci[1]);
  const tc = BOARD_COLS.indexOf(uci[2]), tr = parseInt(uci[3]);
  if (fc >= 0 && tc >= 0) {
    _lastFrom = { c: fc, r: fr };
    _lastTo = { c: tc, r: tr };
  }
}

function setBestMove(uci) {
  const fc = BOARD_COLS.indexOf(uci[0]), fr = parseInt(uci[1]);
  const tc = BOARD_COLS.indexOf(uci[2]), tr = parseInt(uci[3]);
  if (fc >= 0 && tc >= 0) {
    _bestFrom = { c: fc, r: fr };
    _bestTo = { c: tc, r: tr };
  } else {
    _bestFrom = _bestTo = null;
  }
}

// Coordinate helpers — FEN col 0=a is always player's right side
function bx(c) { return ML + (8 - c) * DX; }
function by(r) { return _userSide === "b" ? MT + (9 - r) * DY : MT + r * DY; }

function redrawBoard() {
  const canvas = dom.boardCanvas;
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const W = canvas.width, H = canvas.height;
  ctx.clearRect(0, 0, W, H);

  ctx.fillStyle = "#e8d5b0";
  ctx.fillRect(0, 0, W, H);

  // Grid
  ctx.strokeStyle = "#4a3728";
  ctx.lineWidth = 1;
  for (let i = 0; i < 9; i++) {
    const x = bx(i);
    ctx.beginPath(); ctx.moveTo(x, by(0)); ctx.lineTo(x, by(9)); ctx.stroke();
  }
  for (let i = 4; i <= 5; i++) {
    // River gap: only draw border halves
    const y = by(i);
    ctx.beginPath(); ctx.moveTo(bx(0), y); ctx.lineTo(bx(8), y); ctx.stroke();
  }
  for (const i of [0, 1, 2, 3, 6, 7, 8, 9]) {
    const y = by(i);
    ctx.beginPath(); ctx.moveTo(bx(0), y); ctx.lineTo(bx(8), y); ctx.stroke();
  }

  // River text
  ctx.fillStyle = "#4a3728";
  ctx.font = "11px serif";
  ctx.textAlign = "center";
  ctx.fillText("楚  河", bx(2), by(4.5) + 4);
  ctx.fillText("漢  界", bx(6), by(4.5) + 4);

  // Palace diagonals
  ctx.strokeStyle = "#4a3728";
  ctx.lineWidth = 0.5;
  ctx.beginPath();
  ctx.moveTo(bx(3), by(0)); ctx.lineTo(bx(5), by(2));
  ctx.moveTo(bx(5), by(0)); ctx.lineTo(bx(3), by(2));
  ctx.moveTo(bx(3), by(7)); ctx.lineTo(bx(5), by(9));
  ctx.moveTo(bx(5), by(7)); ctx.lineTo(bx(3), by(9));
  ctx.stroke();

  // Column labels
  ctx.fillStyle = "#4a3728";
  ctx.font = "9px sans-serif";
  ctx.textAlign = "center";
  const redLabels = "九八七六五四三二一";
  const blackLabels = "1 2 3 4 5 6 7 8 9".split(" ");
  for (let i = 0; i < 9; i++) {
    const topLabel = _userSide === "b" ? redLabels[8 - i] : blackLabels[8 - i];
    const botLabel = _userSide === "b" ? blackLabels[i] : redLabels[i];
    ctx.fillText(topLabel, bx(i), by(0) - 5);
    ctx.fillText(botLabel, bx(i), by(9) + 14);
  }

  // Pieces
  const grid = GameStateTracker.board ? GameStateTracker.board.grid : null;
  if (!grid) return;

  for (let r = 0; r < 10; r++) {
    for (let c = 0; c < 9; c++) {
      const piece = grid[r][c];
      if (piece === ".") continue;

      const cx = bx(c), cy = by(r);
      const isRed = piece === piece.toUpperCase();

      ctx.beginPath();
      ctx.arc(cx, cy, RR, 0, Math.PI * 2);
      ctx.fillStyle = "#f5e6d3";
      ctx.fill();
      ctx.strokeStyle = isRed ? "#c62828" : "#1a1a1a";
      ctx.lineWidth = 2;
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(cx, cy, RR - 3, 0, Math.PI * 2);
      ctx.strokeStyle = isRed ? "#c62828" : "#1a1a1a";
      ctx.lineWidth = 0.5;
      ctx.stroke();

      const glyph = PIECE_GLYPHS[piece] || piece;
      ctx.fillStyle = isRed ? "#c62828" : "#1a1a1a";
      ctx.font = "bold 15px 'Microsoft YaHei', 'SimHei', sans-serif";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText(glyph, cx, cy + 1);
    }
  }

  // Last move: green glow + arrow
  if (_lastFrom && _lastTo) {
    for (const pt of [_lastFrom, _lastTo]) {
      ctx.beginPath();
      ctx.arc(bx(pt.c), by(pt.r), RR + 2, 0, Math.PI * 2);
      ctx.fillStyle = "rgba(102, 187, 106, 0.35)";
      ctx.fill();
    }
    const fx = bx(_lastFrom.c), fy = by(_lastFrom.r);
    const tx = bx(_lastTo.c), ty = by(_lastTo.r);
    const ang = Math.atan2(ty - fy, tx - fx);
    const gap = RR + 4;
    const sx = fx + gap * Math.cos(ang), sy = fy + gap * Math.sin(ang);
    const ex = tx - gap * Math.cos(ang), ey = ty - gap * Math.sin(ang);

    ctx.beginPath();
    ctx.moveTo(sx, sy); ctx.lineTo(ex, ey);
    ctx.strokeStyle = "#2e7d32";
    ctx.lineWidth = 2.5;
    ctx.stroke();

    const ah = 10, aw = 6;
    const hx = ex - ah * Math.cos(ang);
    const hy = ey - ah * Math.sin(ang);
    ctx.beginPath();
    ctx.moveTo(ex, ey);
    ctx.lineTo(hx - aw * Math.sin(ang), hy + aw * Math.cos(ang));
    ctx.lineTo(hx + aw * Math.sin(ang), hy - aw * Math.cos(ang));
    ctx.closePath();
    ctx.fillStyle = "#2e7d32";
    ctx.fill();
  }

  // Best move: blue dashed
  if (_bestFrom && _bestTo) {
    for (const pt of [_bestFrom, _bestTo]) {
      ctx.beginPath();
      ctx.arc(bx(pt.c), by(pt.r), RR + 1, 0, Math.PI * 2);
      ctx.setLineDash([3, 3]);
      ctx.strokeStyle = "#1565c0";
      ctx.lineWidth = 2;
      ctx.stroke();
      ctx.setLineDash([]);
    }
  }
}

// ── State ───────────────────────────────────────────────────────────────
let proxyOnline = false;
let logLines = [];
let parsedMoves = [];
let engineReady = false;
let _analysisVersion = 0;       // increments each time a new analysis is requested
let _currentFen = INITIAL_FEN;
let _analysisTimer = null;
let _lastAnalyzedFen = null;
let _autoPlay = false;
let _pendingAutoPlay = false;  // set before analysis, checked when result arrives

// ── Log classification ──────────────────────────────────────────────────
function classifyLine(text) {
  if (text.includes(">>> [MOVE") || text.includes(">>> [MOVE SENT")) return "move";
  if (text.includes("[LOGIN]")) return "login";
  if (text.includes("[KEY]") || text.includes("session_key")) return "key";
  if (text.includes("ERROR") || text.includes("[err]") || text.includes("失败") || text.includes("FAILED")) return "error";
  if (text.startsWith("[main]")) return "system";
  if (text.includes("[SAVE]") || text.includes("[QQ象棋] 断开")) return "gamedone";
  if (text.match(/\[[↑↓→←]\]/)) return "msg";
  return "";
}

function parseMove(line) {
  const m = line.match(/>>> \[MOVE(?: SENT)? #(\d+)\] (\S+)/);
  if (!m) return null;
  return { num: parseInt(m[1]), uci: m[2], sent: line.includes("MOVE SENT") };
}

// ── Render ──────────────────────────────────────────────────────────────
function renderLogLine(entry) {
  const div = document.createElement("div");
  div.className = "log-line";
  const cls = classifyLine(entry.text);
  if (cls) div.classList.add(cls);
  div.textContent = entry.text;
  return div;
}

function getVisibleLogs() {
  const showMoves = dom.filterMoves.checked;
  const showMsgs = dom.filterMsgs.checked;
  if (showMoves && showMsgs) return logLines;
  return logLines.filter((entry) => {
    const cls = classifyLine(entry.text);
    if (cls === "move" && !showMoves) return false;
    if (cls === "msg" && !showMsgs) return false;
    return true;
  });
}

function refreshLogView() {
  const visible = getVisibleLogs();
  const wasAtBottom = dom.logView.scrollHeight - dom.logView.scrollTop - dom.logView.clientHeight < 40;

  dom.logView.innerHTML = "";
  if (visible.length === 0) {
    dom.logView.innerHTML = '<div class="log-empty">暂无匹配日志</div>';
  } else {
    const fragment = document.createDocumentFragment();
    const show = visible.length > 300 ? visible.slice(-300) : visible;
    for (const entry of show) {
      fragment.appendChild(renderLogLine(entry));
    }
    dom.logView.appendChild(fragment);
  }
  dom.logCount.textContent = `${logLines.length} 条`;

  if (wasAtBottom) dom.logView.scrollTop = dom.logView.scrollHeight;
}

function refreshMoveList() {
  if (parsedMoves.length === 0) {
    dom.movesSection.style.display = "none";
    return;
  }
  dom.movesSection.style.display = "flex";

  const redM = [], blkM = [];
  for (const mv of parsedMoves) {
    const cn = mv.chinese || mv.uci;
    // Column assignment: proxy camp (SEND/RECV) is authoritative
    let isRed;
    if (_userSide && mv.sent !== undefined) {
      isRed = mv.sent ? (_userSide === "w") : (_userSide === "b");
    } else if (mv.chinese) {
      isRed = /^[砲馬車兵仕相帥]/.test(mv.chinese);
    } else {
      isRed = /^[砲馬車兵仕相帥]/.test(cn);
    }
    (isRed ? redM : blkM).push({ ...mv, cn });
  }

  dom.moveListRed.innerHTML = redM.map((mv, i) =>
    `<div class="move-col-item${mv.sent ? ' mine' : ' opp'}"><span class="mv-num">${i + 1}.</span>${mv.cn}</div>`
  ).join("");
  dom.moveListBlack.innerHTML = blkM.map((mv, i) =>
    `<div class="move-col-item${mv.sent ? ' mine' : ' opp'}"><span class="mv-num">${i + 1}.</span>${mv.cn}</div>`
  ).join("");
  dom.moveCount.textContent = `${parsedMoves.length}`;
  dom.statMoves.textContent = parsedMoves.length;
}

async function refreshDataStats() {
  try {
    const stats = await window.qqchess.getDataStats();
    dom.statDataSize.textContent = stats.sizeMB + " MB";
    dom.statDataLabel.textContent = stats.fileCount + " 文件";
    if (parseFloat(stats.sizeMB) > 500) {
      dom.statDataCard.style.background = "rgba(255,112,67,0.15)";
      dom.statDataLabel.textContent = stats.fileCount + " 文件 ⚠";
    } else {
      dom.statDataCard.style.background = "";
    }
  } catch (_) { /* ignore */ }
}

async function refreshDataDir() {
  try {
    const dir = await window.qqchess.getDataDir();
    dom.statDataCard.title = dir + " (点击更改)";
  } catch (_) { /* ignore */ }
}

dom.statDataCard.addEventListener("click", async () => {
  const dir = await window.qqchess.getDataDir();
  const ok = confirm("数据目录: " + dir + "\n\n是否更换数据保存位置？\n(对局数据为临时文件，可随时清理)");
  if (!ok) return;
  const newDir = await window.qqchess.chooseDataDir();
  if (newDir) refreshDataDir();
});

function updateMySide() {
  if (!_userSide) { dom.mySide.textContent = "--"; dom.mySide.className = "my-side"; return; }
  dom.mySide.textContent = _userSide === "w" ? "🔴 红方" : "⚫ 黑方";
  dom.mySide.className = "my-side " + _userSide;
}

function updateStatus(status) {
  proxyOnline = status.running;
  dom.statusDot.className = "dot " + (proxyOnline ? "dot-online" : "dot-offline");
  dom.statusText.textContent = proxyOnline ? "代理运行中" : "代理未启动";

  dom.btnProxy.textContent = proxyOnline ? "停止代理" : "启动代理";
  dom.btnProxy.classList.toggle("btn-warn", proxyOnline);
}

// ── Engine panel ────────────────────────────────────────────────────────
function updateEngineUI(result) {
  if (!result || result.error) {
    dom.engineBestmove.textContent = result ? result.error : "--";
    dom.engineBestmoveCn.textContent = "";
    dom.engineScore.textContent = "--";
    dom.engineDepth.textContent = "";
    dom.enginePv.textContent = "";
    return;
  }

  dom.engineBestmove.textContent = result.bestMove || "--";
  // Convert engine UCI best move to Chinese notation
  const cn = GameStateTracker.uciToChinese(result.bestMove);
  dom.engineBestmoveCn.textContent = cn ? `（${cn}）` : "";

  // Auto-play: if engine analyzed after opponent's move, fire the best move
  if (_pendingAutoPlay && result.bestMove && result.bestMove !== "0000") {
    _pendingAutoPlay = false;
    window.qqchess.autoPlayMove(result.bestMove);
  }

  const score = result.score || 0;
  dom.engineScore.textContent = (score >= 0 ? "+" : "") + score;
  dom.engineScore.className = "engine-score" + (score > 0 ? " positive" : score < 0 ? " negative" : "");

  dom.engineDepth.textContent = result.depth ? `深度 ${result.depth}` : "";

  if (result.pv && result.pv.length > 0) {
    dom.enginePv.textContent = result.pv.slice(0, 8).join(" ");
  } else {
    dom.enginePv.textContent = "";
  }

  dom.engineFen.textContent = _currentFen;
}

function setEngineStatus(ready, text) {
  engineReady = ready;
  dom.engineDot.className = "dot " + (ready ? "dot-online" : "dot-offline");
  dom.engineStatusText.textContent = text || (ready ? "就绪" : "未就绪");
  if (ready) {
    dom.engineBody.style.display = "flex";
  }
}

// ── Engine analysis trigger ─────────────────────────────────────────────
async function triggerAnalysis(fen) {
  if (!engineReady) return;
  if (fen === _lastAnalyzedFen) return;

  _analysisVersion++;
  const version = _analysisVersion;

  try {
    // Send ALL validated moves — the engine needs full history to know whose turn
    const moveList = [];
    let lastUci = null;
    for (const mv of parsedMoves) {
      if (mv.uci !== lastUci) { moveList.push(mv.uci); lastUci = mv.uci; }
    }
    const result = await window.qqchess.analyzePosition(fen, moveList);
    if (version !== _analysisVersion) return;
    if (result && !result.error) {
      _lastAnalyzedFen = fen;
      updateEngineUI(result);
      setBestMove(result.bestMove);
      redrawBoard();
    }
  } catch (e) {
    if (version === _analysisVersion) {
      dom.engineBestmove.textContent = "分析失败";
    }
  }
}

function scheduleAnalysis(fen, isOpponentMove) {
  _currentFen = fen;
  // If auto-play is on and opponent just moved, flag for auto-fire after analysis
  if (isOpponentMove && _autoPlay) {
    _pendingAutoPlay = true;
  }
  // Debounce: wait 300ms after last move before starting analysis
  if (_analysisTimer) clearTimeout(_analysisTimer);
  _analysisTimer = setTimeout(() => {
    triggerAnalysis(fen);
    _analysisTimer = null;
  }, 300);
}

// Force analysis of current position (for manual button)
async function forceAnalyze() {
  if (!engineReady) {
    dom.engineBestmove.textContent = "引擎未就绪";
    return;
  }
  _analysisVersion++;
  const version = _analysisVersion;
  dom.engineBestmove.textContent = "思考中...";
  dom.engineScore.textContent = "...";

  try {
    // Send ALL validated moves so engine knows whose turn it is
    const moveList = [];
    let lastUci = null;
    for (const mv of parsedMoves) {
      if (mv.uci !== lastUci) { moveList.push(mv.uci); lastUci = mv.uci; }
    }
    const result = await window.qqchess.analyzePosition(_currentFen, moveList);
    if (version !== _analysisVersion) return;
    if (result && !result.error) {
      _lastAnalyzedFen = _currentFen;
      updateEngineUI(result);
      setBestMove(result.bestMove);
      redrawBoard();
    }
  } catch (e) {
    if (version === _analysisVersion) {
      dom.engineBestmove.textContent = "分析失败";
    }
  }
}

// ── Event handlers ──────────────────────────────────────────────────────
dom.filterMoves.addEventListener("change", refreshLogView);
dom.filterMsgs.addEventListener("change", refreshLogView);

dom.btnGame.addEventListener("click", () => {
  const wv = document.getElementById("game-webview");
  if (wv) wv.src = "https://h5login.qqchess.qq.com/";
});

dom.btnProxy.addEventListener("click", () => {
  if (proxyOnline) {
    window.qqchess.stopProxy();
  } else {
    window.qqchess.startProxy();
  }
});

dom.btnRestart.addEventListener("click", () => window.qqchess.restartProxy());

dom.btnAnalyze.addEventListener("click", () => forceAnalyze());

dom.btnAutoplay.addEventListener("click", () => {
  _autoPlay = !_autoPlay;
  _pendingAutoPlay = false;
  dom.btnAutoplay.textContent = _autoPlay ? "⏸ 停止自动" : "⚡ 自动走子";
  dom.btnAutoplay.classList.toggle("btn-accent", _autoPlay);
});

dom.btnFlip.addEventListener("click", () => {
  _userSide = _userSide === "b" ? "w" : "b";
  updateMySide();
  redrawBoard();
});

dom.btnClear.addEventListener("click", async () => {
  await window.qqchess.clearLogs();
  logLines = [];
  parsedMoves = [];
  GameStateTracker.reset();
  _currentFen = INITIAL_FEN;
  _lastAnalyzedFen = null;
  _lastFrom = _lastTo = _bestFrom = _bestTo = null;
  _userSide = null;
  _autoPlay = false;
  _pendingAutoPlay = false;
  dom.btnAutoplay.textContent = "⚡ 自动走子";
  dom.btnAutoplay.classList.remove("btn-accent");
  updateMySide();
  _analysisVersion++;
  refreshLogView();
  refreshMoveList();
  redrawBoard();
  updateEngineUI(null);
  dom.engineFen.textContent = INITIAL_FEN;
  dom.statMoves.textContent = "0";
});

dom.btnSessions.addEventListener("click", () => window.qqchess.openSessionsDir());

dom.btnCopyLog.addEventListener("click", () => {
  const visible = getVisibleLogs();
  const text = visible.map((e) => e.text).join("\n");
  navigator.clipboard.writeText(text).then(() => {
    dom.btnCopyLog.textContent = "已复制!";
    setTimeout(() => { dom.btnCopyLog.textContent = "复制日志"; }, 1500);
  }).catch(() => {
    dom.btnCopyLog.textContent = "失败";
    setTimeout(() => { dom.btnCopyLog.textContent = "复制日志"; }, 1500);
  });
});

// ── Session file count + move restore ───────────────────────────────────
let _lastLoadedMovesFile = null;

async function restoreMovesFromSession() {
  try {
    const files = await window.qqchess.getSessionFiles();
    const movesFiles = files.filter((f) => f.name.includes("_moves_")).sort((a, b) => b.name.localeCompare(a.name));
    if (movesFiles.length === 0) { console.log('[restore] no moves files'); return; }
    const latest = movesFiles[0];
    if (latest.name === _lastLoadedMovesFile && parsedMoves.length > 0) { console.log('[restore] already loaded'); return; }
    console.log('[restore] loading', latest.name, 'moves:', parsedMoves.length);
    _lastLoadedMovesFile = latest.name;

    const data = await window.qqchess.readSessionFile(latest.name);
    if (!data || !Array.isArray(data) || data.length === 0) return;

    // Reset board and replay ALL moves from session file
    GameStateTracker.reset();
    parsedMoves = [];
    _userSide = null;
    _currentFen = INITIAL_FEN;
    _lastFrom = _lastTo = _bestFrom = _bestTo = null;

    // Determine _userSide from first SEND move's camp BEFORE replaying
    for (const m of data) {
      if (m.direction === "SEND" && m.camp) {
        _userSide = m.camp === "red" ? "w" : "b";
        updateMySide();
        break;
      }
    }

    // Now replay with correct _userSide for proxyToFenUci
    for (const m of data) {
      const uci = m.uci;
      if (!uci) continue;
      const fenUci = proxyToFenUci(uci);
      const sent = m.direction === "SEND";
      const result = GameStateTracker.applyMove(fenUci, sent);
      if (result) {
        parsedMoves.push({ num: m.num, uci: fenUci, sent, chinese: result.chinese });
        setLastMove(fenUci);
      }
    }
    _currentFen = GameStateTracker.fen;
    refreshMoveList();
    redrawBoard();
    dom.engineFen.textContent = _currentFen;
    dom.statMoves.textContent = parsedMoves.length;
    console.log('[restore] done, moves:', parsedMoves.length);
    if (_currentFen !== INITIAL_FEN) scheduleAnalysis(_currentFen);
  } catch (e) { console.log('[restore] error:', e.message); }
}

async function refreshSessionCount() {
  try {
    const files = await window.qqchess.getSessionFiles();
  } catch (e) { /* ignore */ }
}

// ── IPC listeners ───────────────────────────────────────────────────────
window.qqchess.onLogLine((data) => {
  logLines.push(data);
  if (logLines.length > 1000) logLines = logLines.slice(-1000);

  // Camp detection from proxy [CAMP] log — authoritative side assignment
  if (data.text.includes("[CAMP]")) {
    const campMatch = data.text.match(/\[CAMP\].*→\s*(red|black)/);
    if (campMatch) {
      const newSide = campMatch[1] === "red" ? "w" : "b";
      if (_userSide !== newSide) {
        _userSide = newSide;
        updateMySide();
        redrawBoard();
        refreshMoveList();
      }
    }
  }

  // Mid-game FEN from server state sync (eventID=63) — reset board to current position
  if (data.text.includes("[MIDGAME]")) {
    const m = data.text.match(/\[MIDGAME\]\s+fen=(\S+)/);
    if (m) {
      const fen = m[1];
      const board = GameStateTracker.parseFen(fen);
      if (board) {
        GameStateTracker.reset();
        GameStateTracker.board = board;
        GameStateTracker.fen = fen;
        GameStateTracker.side = board.side;
        _currentFen = fen;
        parsedMoves = [];
        _lastFrom = _lastTo = _bestFrom = _bestTo = null;
        redrawBoard();
        refreshMoveList();
        dom.engineFen.textContent = fen;
        // Trigger analysis of the mid-game position
        scheduleAnalysis(fen);
      }
    }
  }

  // Detect and process moves
  if (data.text.includes(">>> [MOVE") || data.text.includes(">>> [MOVE SENT")) {
    const mv = parseMove(data.text);
    if (mv && !parsedMoves.find((m) => m.num === mv.num)) {
      // Echo filter: if this RECV matches last SENT UCI within 2s, skip
      if (!mv.sent && mv.uci === _lastSentUci && Date.now() - _lastSentTime < 2000) {
        return;
      }
      if (mv.sent) {
        _lastSentUci = mv.uci;
        _lastSentTime = Date.now();
      }
      const fenUci = proxyToFenUci(mv.uci);
      let result = GameStateTracker.applyMove(fenUci, mv.sent);
      // Mid-game without FEN: first move may fail color check on stale board — retry
      if (!result && parsedMoves.length === 0) {
        result = GameStateTracker.applyMove(fenUci, mv.sent, true);
      }
      if (!result) { refreshMoveList(); return; }
      // Detect user side from first SENT move: piece color is authoritative
      if (_userSide === null && mv.sent) {
        _userSide = result.isRed ? "w" : "b";
        updateMySide();
      }
      mv.chinese = result.chinese;
      mv.uci = fenUci;
      parsedMoves.push(mv);
      _currentFen = result.fen;
      setLastMove(mv.uci);
      _bestFrom = _bestTo = null;
      redrawBoard();
      refreshMoveList();
      // Auto-analyze after every move (both user and opponent)
      if (parsedMoves.length >= 2) scheduleAnalysis(result.fen, !mv.sent);
    }
  }

  // New game detected — reset game state
  if (data.text.includes("[GAME] ====== 对局") && data.text.includes("开始")) {
    parsedMoves = [];
    GameStateTracker.reset();
    _currentFen = INITIAL_FEN;
    _lastAnalyzedFen = null;
    _userSide = null;
    _lastSentUci = null;
    _lastSentTime = 0;
    _lastFrom = _lastTo = _bestFrom = _bestTo = null;
    refreshMoveList();
    redrawBoard();
    updateEngineUI(null);
    dom.engineFen.textContent = INITIAL_FEN;
  }

  // 86001 arrives — try to restore from saved session immediately
  if (data.text.includes("[86001] tableID=")) {
    _lastLoadedMovesFile = null;
    restoreMovesFromSession();
  }

  // Clear engine + moves only on genuine game end (not disconnect)
  if (data.text.includes("[GAME] ====== 对局") && data.text.includes("结束")) {
    parsedMoves = [];
    GameStateTracker.reset();
    _currentFen = INITIAL_FEN;
    _lastAnalyzedFen = null;
    _lastFrom = _lastTo = _bestFrom = _bestTo = null;
    refreshMoveList();
    redrawBoard();
    updateEngineUI(null);
    dom.engineFen.textContent = INITIAL_FEN;
  }

  // Throttle log refresh
  if (!refreshLogView._timer) {
    refreshLogView._timer = requestAnimationFrame(() => {
      refreshLogView();
      refreshLogView._timer = null;
    });
  }
});

window.qqchess.onProxyStatus((status) => updateStatus(status));

window.qqchess.onGameClosed(() => { /* noop */ });

window.qqchess.onLaunchGame((url) => {
  const wv = document.getElementById("game-webview");
  if (wv) wv.src = url;
});

window.qqchess.onSessionFileChanged(() => {
  refreshSessionCount();
  // Don't reset moves — live moves are the source of truth
});

window.qqchess.onEngineStatus((data) => {
  if (data.ready) {
    setEngineStatus(true, `就绪 — ${data.name || "Pikafish"}`);
    // If we have moves from a game, analyze current position
    if (_currentFen !== INITIAL_FEN && _currentFen !== _lastAnalyzedFen) {
      scheduleAnalysis(_currentFen);
    }
  } else {
    // Engine stopped or failed — check if it was ever started
    setEngineStatus(false, "未启动 — 查看日志了解详情");
    _lastAnalyzedFen = null;
  }
});

// ── Init ────────────────────────────────────────────────────────────────
async function init() {
  // Proxy status
  try {
    const status = await window.qqchess.getProxyStatus();
    updateStatus(status);
  } catch (e) { /* preload not ready */ }

  // Engine status — initial query, then rely on push events
  try {
    const engStatus = await window.qqchess.getEngineStatus();
    if (engStatus && engStatus.ready) {
      setEngineStatus(true, "就绪");
    } else if (engStatus && engStatus.available) {
      setEngineStatus(false, "启动中...");
    } else {
      setEngineStatus(false, "不可用");
    }
  } catch (e) {
    setEngineStatus(false, "错误");
  }

  // Restore existing logs (clear first to avoid duplicating onLogLine events)
  try {
    const existingLogs = await window.qqchess.getLogs();
    if (existingLogs && existingLogs.length > 0) {
      logLines = [];
      parsedMoves = [];
      _userSide = null;
      GameStateTracker.reset();
      for (const entry of existingLogs) {
        logLines.push(entry);
        // Camp detection from proxy [CAMP] log
        if (entry.text.includes("[CAMP]")) {
          const campMatch = entry.text.match(/\[CAMP\].*→\s*(red|black)/);
          if (campMatch) {
            _userSide = campMatch[1] === "red" ? "w" : "b";
          }
        }
        // Mid-game FEN from server state sync (eventID=63)
        if (entry.text.includes("[MIDGAME]")) {
          const m = entry.text.match(/\[MIDGAME\]\s+fen=(\S+)/);
          if (m) {
            const fen = m[1];
            const board = GameStateTracker.parseFen(fen);
            if (board) {
              GameStateTracker.reset();
              GameStateTracker.board = board;
              GameStateTracker.fen = fen;
              GameStateTracker.side = board.side;
              _currentFen = fen;
              parsedMoves = [];
              _lastFrom = _lastTo = _bestFrom = _bestTo = null;
            }
          }
        }
        if (entry.text.includes(">>> [MOVE") || entry.text.includes(">>> [MOVE SENT")) {
          const mv = parseMove(entry.text);
          if (mv && !parsedMoves.find((m) => m.num === mv.num)) {
            const fenUci = proxyToFenUci(mv.uci);
            let result = GameStateTracker.applyMove(fenUci, mv.sent);
            // Mid-game without FEN: first move may fail color check on stale board — retry
            if (!result && parsedMoves.length === 0) {
              result = GameStateTracker.applyMove(fenUci, mv.sent, true);
            }
            if (result) {
              // Detect user side from first SENT move: piece color is authoritative
              if (_userSide === null && mv.sent) {
                _userSide = result.isRed ? "w" : "b";
                updateMySide();
              }
              mv.chinese = result.chinese;
              mv.uci = fenUci;
              setLastMove(fenUci);
              parsedMoves.push(mv);
            }
          }
        }
      }
      _currentFen = GameStateTracker.fen;
      redrawBoard();
      refreshLogView();
      refreshMoveList();
    }
  } catch (e) { /* ignore */ }

  refreshSessionCount();
  if (parsedMoves.length === 0) await restoreMovesFromSession();

  refreshDataDir();
  refreshDataStats();
  setInterval(refreshDataStats, 30000);  // update every 30s

  // Show initial FEN and board
  dom.engineFen.textContent = _currentFen;
  redrawBoard();
}

init();
