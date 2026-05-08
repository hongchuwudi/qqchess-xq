const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

const DEF_ENGINE_DIR = path.join(__dirname, "..", "engines", "pikayu-20260131");

// sse41-popcnt first — widest CPU compatibility
const PREF_ORDER = ["sse41-popcnt", "bmi2", "avx2", "avxvnni", "avx512", "avx512icl", "vnni512"];

class PikafishBridge {
  constructor(engineDir) {
    this._engineDir = engineDir || DEF_ENGINE_DIR;
    this.proc = null;
    this.ready = false;
    this.enginePath = null;
    this.engineName = "Pikafish";
    this._buffer = "";
    this._pending = null;
    this._infoLines = [];
    this._uciok = false;
    this._onReady = null;
    this._onExit = null;
    this._onLog = null;
    this._startupTimer = null;
    this._initOutput = [];
    this._binaries = [];
    this._tryIdx = 0;
  }

  _listEngines() {
    if (!fs.existsSync(this._engineDir)) return [];
    try {
      const exes = fs.readdirSync(this._engineDir).filter((f) => f.endsWith(".exe"));
      const ordered = [];
      for (const pref of PREF_ORDER) {
        const match = exes.find((e) => e.includes(pref));
        if (match && !ordered.includes(match)) ordered.push(match);
      }
      for (const e of exes) {
        if (!ordered.includes(e)) ordered.push(e);
      }
      return ordered.map((e) => path.join(this._engineDir, e));
    } catch (e) {
      return [];
    }
  }

  start() {
    this._binaries = this._listEngines();
    if (this._binaries.length === 0) {
      this._log("[pikafish] No engine .exe found in: " + this._engineDir);
      return false;
    }
    this._log("[pikafish] Found " + this._binaries.length + " binary(s), trying in compatibility order");
    this._tryIdx = 0;
    this._tryNext();
    return true;
  }

  _tryNext() {
    if (this._tryIdx >= this._binaries.length) {
      this._log("[pikafish] All " + this._binaries.length + " binaries failed");
      if (this._onExit) this._onExit();
      return;
    }

    const exePath = this._binaries[this._tryIdx];
    const exeName = path.basename(exePath);
    this._log("[pikafish] Trying (" + (this._tryIdx + 1) + "/" + this._binaries.length + "): " + exeName);

    this.enginePath = exePath;
    this._uciok = false;
    this._initOutput = [];
    this._buffer = "";

    try {
      this.proc = spawn(exePath, [], {
        cwd: this._engineDir,
        stdio: ["pipe", "pipe", "pipe"],
        windowsHide: true,
      });
    } catch (e) {
      this._log("[pikafish] Spawn failed: " + e.message);
      this._tryIdx++;
      this._tryNext();
      return;
    }

    this.proc.stdout.on("data", (d) => this._onData(d.toString()));
    this.proc.stderr.on("data", (d) => {
      const m = d.toString().trim();
      if (m) this._log("[pikafish:err] " + m);
    });

    this.proc.on("error", (err) => {
      this._log("[pikafish] Error: " + err.message);
      this._cleanup();
      this._tryIdx++;
      this._tryNext();
    });

    this.proc.on("exit", (code, signal) => {
      if (!this._uciok) {
        this._log("[pikafish] Exited (code=" + code + ") before handshake — trying next");
        this._cleanup();
        this._tryIdx++;
        this._tryNext();
      } else {
        this._log("[pikafish] Engine exited unexpectedly (code=" + code + ")");
        this._cleanup();
        if (this._onExit) this._onExit();
      }
    });

    this._send("ucci");
    this._startupTimer = setTimeout(() => {
      if (!this._uciok) {
        this._log("[pikafish] Timeout (8s) — no ucciok from " + exeName);
        this._log("[pikafish] Output: " + (this._initOutput.join(" | ") || "(none)"));
        this._cleanup();
        this._tryIdx++;
        this._tryNext();
      }
    }, 8000);

    this.ready = true;
  }

  _cleanup() {
    clearTimeout(this._startupTimer);
    this._startupTimer = null;
    if (this.proc) {
      try { this.proc.kill(); } catch (e) { /* ignore */ }
      this.proc = null;
    }
  }

  stop() {
    this._cleanup();
    this.ready = false;
  }

  get isReady() {
    return this.ready && this.proc !== null && this._uciok;
  }

  async analyze(fen, moveList) {
    const depth = 18;
    const movetime = 3000;

    if (!this.isReady) return { error: "Engine not ready" };

    this._infoLines = [];
    this._pending = null;

    const INITIAL_FEN = "rnbakabnr/9/1c5c1/p1p1p1p1p/9/9/P1P1P1P1P/1C5C1/9/RNBAKABNR w";
    const engMoves = (moveList || []).map((m) => this._convRow(m));
    const moves = engMoves.join(" ");

    if (fen && fen !== INITIAL_FEN) {
      this._log("[pikafish] position fen " + fen + " moves " + moves);
      this._send("position fen " + fen + " moves " + moves);
    } else if (engMoves.length === 0) {
      this._log("[pikafish] position startpos");
      this._send("position startpos");
    } else {
      this._log("[pikafish] position startpos moves " + moves);
      this._send("position startpos moves " + moves);
    }
    this._send("go depth " + depth + " movetime " + movetime);

    return new Promise((resolve) => {
      const timeout = setTimeout(() => {
        this._pending = null;
        this._send("stop");
        resolve(this._buildResult("0000", "timeout"));
      }, movetime + 3000);

      this._pending = { resolve, timeout };
    });
  }

  _log(msg) {
    if (this._onLog) this._onLog(msg);
  }

  _send(cmd) {
    if (this.proc && this.proc.stdin && this.proc.stdin.writable) {
      try { this.proc.stdin.write(cmd + "\n"); } catch (e) { /* ignore */ }
    }
  }

  _onData(chunk) {
    this._buffer += chunk;
    const lines = this._buffer.split(/\r?\n/);
    this._buffer = lines.pop();

    for (const line of lines) {
      const t = line.trim();
      if (!t) continue;

      if (!this._uciok) {
        this._initOutput.push(t);
        if (this._initOutput.length > 20) this._initOutput.shift();
      }

      if (t === "ucciok" || t === "uciok") {
        this._uciok = true;
        clearTimeout(this._startupTimer);
        this._startupTimer = null;
        this._log("[pikafish] Handshake OK — " + this.engineName);
        this._send("setoption name Threads value 2");
        if (this._onReady) this._onReady(this.engineName);
        continue;
      }

      if (t.toLowerCase().includes("unknown command") && t.toLowerCase().includes("ucci")) {
        this._log("[pikafish] UCCI not supported, switching to UCI protocol");
        this._send("uci");
        continue;
      }

      if (t.startsWith("id name")) {
        this.engineName = t.substring(8).trim();
        this._log("[pikafish] Engine: " + this.engineName);
        continue;
      }

      if (t.startsWith("id author") || t.startsWith("option name")) continue;

      if (t.startsWith("info")) {
        this._infoLines.push(t);
        continue;
      }

      if (t.startsWith("bestmove")) {
        const parts = t.split(/\s+/);
        const bestMove = parts[1] || "0000";
        const ponder = parts[3] || null;
        if (this._pending) {
          clearTimeout(this._pending.timeout);
          this._pending.resolve(this._buildResult(bestMove, "ok", ponder));
          this._pending = null;
        }
        continue;
      }

      if (!this._uciok) this._log("[pikafish] " + t);
    }
  }

  _convRow(uci) {
    if (!uci || uci.length < 4) return uci;
    const fr = parseInt(uci[1]), tr = parseInt(uci[3]);
    if (isNaN(fr) || isNaN(tr)) return uci;
    return uci[0] + (9 - fr) + uci[2] + (9 - tr) + uci.substring(4);
  }

  _buildResult(bestMove, status, ponder) {
    let score = 0, depth = 0, pv = [];
    for (let i = this._infoLines.length - 1; i >= 0; i--) {
      const line = this._infoLines[i];
      const sm = line.match(/score cp (-?\d+)/);
      const dm = line.match(/depth (\d+)/);
      const pm = line.match(/pv (.+)/);
      if (sm && !score) score = parseInt(sm[1]);
      if (dm && !depth) depth = parseInt(dm[1]);
      if (pm && !pv.length) pv = pm[1].split(/\s+/).filter(Boolean).map((m) => this._convRow(m));
      if (score && depth && pv.length) break;
    }
    const fenMove = this._convRow(bestMove);
    this._log("[pikafish] bestmove=" + fenMove + " score=" + score + " depth=" + depth);
    return {
      bestMove: fenMove, score, depth,
      pv: pv.length > 0 ? pv : [fenMove],
      status,
      ponder: ponder ? this._convRow(ponder) : (pv.length > 1 ? pv[1] : null),
    };
  }
}

module.exports = { PikafishBridge };
