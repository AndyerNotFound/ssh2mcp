#!/usr/bin/env node
"use strict";
/*
 * ssh2mcp — expose a remote SSH host as MCP tools.
 *
 * Design:
 *   - Binds 127.0.0.1 only. Loopback is NOT access control: any app on the device
 *     with INTERNET permission can reach it, so every route demands a bearer token
 *     and the server refuses to start without one (fail-closed).
 *   - Transport: Streamable HTTP, POST /mcp, stateless (a fresh Server + transport
 *     per request, as the SDK requires for stateless mode).
 *   - Execution goes through the system `ssh` binary, so ~/.ssh/config (ControlMaster,
 *     identity, known_hosts, keepalive) applies as-is and no ssh client library or
 *     key handling lives in this process.
 *   - Four permission levels (ro / rw / full / selfcheck), hot-switchable via
 *     ~/.ssh2mcp-perm, evaluated before the path jail and the risk table.
 *   - Writes exist only in `s_xfer`; `s_file` is read-only by design, so a remote
 *     tree can never be edited behind git's back.
 */

const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
const { CallToolRequestSchema, ListToolsRequestSchema } = require("@modelcontextprotocol/sdk/types.js");
const { StreamableHTTPServerTransport } = require("@modelcontextprotocol/sdk/server/streamableHttp.js");
const { localhostHostValidation } = require("@modelcontextprotocol/sdk/server/middleware/hostHeaderValidation.js");
const { spawn } = require("child_process");
const { once } = require("events");
const { pipeline } = require("stream/promises");
const express = require("express");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const VERSION = "1.0.0";
const HOME = os.homedir();
const STATE_DIR = path.join(HOME, ".ssh2mcp");
const AUDIT_LOG = path.join(STATE_DIR, "audit.log");
const TOKEN_FILE = process.env.SSH2MCP_TOKEN_FILE || path.join(HOME, ".ssh2mcp-token");
const PERM_FILE = process.env.SSH2MCP_PERM_FILE || path.join(HOME, ".ssh2mcp-perm");
const SSH_BIN = process.env.SSH2MCP_SSH_BIN || "ssh";
const SSH_HOST = process.env.SSH2MCP_SSH_HOST || "cloud";
const JAIL = process.env.SSH2MCP_ROOT ? path.posix.normalize(process.env.SSH2MCP_ROOT) : "";
const MAX_OUTPUT = Number(process.env.SSH2MCP_MAX_OUTPUT || 20000);
const DEFAULT_TIMEOUT_MS = Number(process.env.SSH2MCP_TIMEOUT_MS || 120000);
const MAX_TIMEOUT_MS = Number(process.env.SSH2MCP_MAX_TIMEOUT_MS || 3600000);
let LAST_PERM = null;

// The hot file can be edited by anything (echo full > ~/.ssh2mcp-perm), so the server
// cannot see the write itself - but it can see the first call made under a new level and
// record that. A silent escalation to `full` is exactly the change worth an audit line.
function notePerm(p) {
  if (LAST_PERM === null) { LAST_PERM = p; return; }
  if (p !== LAST_PERM) {
    audit({ tool: "perm-change", perm: p, prev: LAST_PERM });
    LAST_PERM = p;
  }
}

const HASH_CAP = 128 * 1024 * 1024;      // files above this are compared by size+mtime only
const DIFF_CAP = 65536;                  // largest file we line-diff
const SSH_OPTS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                  "-o", "ServerAliveInterval=20", "-o", "ServerAliveCountMax=6"];
// The user's ~/.ssh/config enables ControlMaster/ControlPersist. A multiplexed client can be
// SIGKILLed while the mux master keeps the stdio pipe open, so a killed call keeps blocking
// until the remote command ends. opt-out for calls that must be interruptible.
const NO_MUX_OPTS = ["-o", "ControlMaster=no", "-o", "ControlPath=none"];

// ---------------------------------------------------------------- argv

const ARGV = process.argv.slice(2);
function argVal(name) {
  const i = ARGV.indexOf(name);
  if (i < 0) return null;
  const v = ARGV[i + 1];
  return v && !v.startsWith("--") ? v : true;
}
const FLAG_SELF_CHECK = ARGV.includes("--self-check");
const FLAG_SELF_TEST = ARGV.includes("--self-test");
const FLAG_HELP = ARGV.includes("--help") || ARGV.includes("-h");

const PORT = Number(argVal("--port") || process.env.MCP_PORT || 6222);
const BIND = String(process.env.SSH2MCP_BIND || "127.0.0.1");
const BASE_PERM = String(argVal("--perm") || process.env.SSH2MCP_PERM || "rw").toLowerCase();
const PERMS = ["ro", "rw", "full", "selfcheck"];

// ---------------------------------------------------------------- helpers

const q = (s) => "'" + String(s).replace(/'/g, "'\\''") + "'";
const sha = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

function sha256File(p) {
  return new Promise((resolve, reject) => {
    const h = crypto.createHash("sha256");
    fs.createReadStream(p).on("data", (b) => h.update(b)).on("end", () => resolve(h.digest("hex"))).on("error", reject);
  });
}

function audit(rec) {
  try {
    fs.mkdirSync(STATE_DIR, { recursive: true });
    fs.appendFileSync(AUDIT_LOG, JSON.stringify(Object.assign({ ts: new Date().toISOString() }, rec)) + "\n");
  } catch (_) { /* auditing must never break a call */ }
}

function truncate(text, max) {
  if (text.length <= max) return { text, truncated: false, total: text.length };
  const head = Math.floor(max * 0.7), tail = max - head;
  return {
    text: text.slice(0, head) + "\n...[truncated: first " + head + " + last " + tail + " of " + text.length + " chars]...\n" + text.slice(-tail),
    truncated: true, total: text.length
  };
}

function jailCheck(p) {
  if (!JAIL || !p) return null;
  const n = path.posix.normalize(String(p));
  const root = JAIL.endsWith("/") ? JAIL : JAIL + "/";
  if (n === JAIL || n.startsWith(root)) return null;
  return "path outside jail " + JAIL + ": " + p;
}

function readPerm() {
  try {
    const m = fs.readFileSync(PERM_FILE, "utf-8").trim().toLowerCase();
    if (PERMS.includes(m)) return m;
  } catch (_) {}
  return PERMS.includes(BASE_PERM) ? BASE_PERM : "rw";
}

// ---------------------------------------------------------------- ssh exec

function sshRun(remoteCmd, opts) {
  const o = opts || {};
  const timeoutMs = Math.min(Number(o.timeoutMs || DEFAULT_TIMEOUT_MS), MAX_TIMEOUT_MS);
  const cap = Number(o.maxBytes || 8 * 1024 * 1024);
  const sshArgs = o.noMux ? [...SSH_OPTS, ...NO_MUX_OPTS] : SSH_OPTS;
  return new Promise((resolve) => {
    const t0 = Date.now();
    let ch;
    try {
      ch = spawn(SSH_BIN, [...sshArgs, SSH_HOST, remoteCmd], { stdio: ["pipe", "pipe", "pipe"] });
    } catch (e) {
      resolve({ code: -1, out: "", err: String(e.message), outBytes: 0, errBytes: 0, ms: 0, timedOut: false });
      return;
    }
    const outB = [], errB = [];
    let outTotal = 0, errTotal = 0, timedOut = false;
    ch.stdout.on("data", (b) => { outTotal += b.length; if (outTotal <= cap) outB.push(b); });
    ch.stderr.on("data", (b) => { errTotal += b.length; if (errTotal <= cap) errB.push(b); });
    // Resolve on the timer, not on 'close': a multiplexed ssh can leave the pipe open after
    // the kill, which used to make timed_out calls block until the remote command finished.
    const timer = setTimeout(() => {
      timedOut = true;
      try { ch.kill("SIGKILL"); } catch (_) {}
      try { ch.stdout.destroy(); ch.stderr.destroy(); ch.stdin.destroy(); } catch (_) {}
      resolve({
        code: -1, signal: "SIGKILL",
        out: Buffer.concat(outB).toString("utf8"), err: Buffer.concat(errB).toString("utf8"),
        outBytes: outTotal, errBytes: errTotal, ms: Date.now() - t0, timedOut: true
      });
    }, timeoutMs);
    ch.on("error", (e) => {
      clearTimeout(timer);
      resolve({ code: -1, out: Buffer.concat(outB).toString("utf8"), err: String(e.message), outBytes: outTotal, errBytes: errTotal, ms: Date.now() - t0, timedOut });
    });
    ch.stdin.on("error", () => {});
    ch.stdin.end(o.stdin == null ? "" : o.stdin);
    ch.on("close", (code, signal) => {
      clearTimeout(timer);
      resolve({
        code: code == null ? -1 : code, signal,
        out: Buffer.concat(outB).toString("utf8"),
        err: Buffer.concat(errB).toString("utf8"),
        outBytes: outTotal, errBytes: errTotal,
        ms: Date.now() - t0, timedOut
      });
    });
  });
}

// ---------------------------------------------------------------- permission: ro allowlist

const RO_TOP = new Set(["ls", "cat", "head", "tail", "less", "more", "stat", "wc", "du", "df", "free",
  "nproc", "uname", "uptime", "sha256sum", "md5sum", "find", "grep", "rg", "diff", "cmp", "file",
  "which", "type", "date", "echo", "pwd", "id", "ps", "git", "apksigner", "aapt2", "java",
  "gradlew", "./gradlew", "true"]);
const RO_GIT = new Set(["log", "diff", "status", "show", "rev-parse", "ls-files", "describe", "cat-file", "rev-list", "blame"]);
const RO_GRADLE = new Set(["--version", "-v", "--dry-run", "tasks", "projects", "dependencies", "help"]);
const RO_META = /[><`;]|\$\(|&&|\|\||<\(|>\(/;

function roCheck(cmd) {
  if (RO_META.test(cmd)) return "ro mode rejects shell metacharacters (>, <, ;, &&, ||, $(), backticks)";
  const segs = cmd.split("|").map((s) => s.trim()).filter(Boolean);
  if (!segs.length) return "empty command";
  for (const seg of segs) {
    const parts = seg.split(/\s+/);
    const w = parts[0], a = parts[1] || "";
    if (!RO_TOP.has(w)) return "command not allowed in ro mode: " + w;
    if (w === "git" && !RO_GIT.has(a)) return "git subcommand not allowed in ro mode: " + (a || "(none)");
    if ((w === "./gradlew" || w === "gradlew") && !RO_GRADLE.has(a)) return "gradlew task not allowed in ro mode: " + (a || "(none)");
    if (w === "find" && /-(?:delete|exec|execdir|ok|okdir|fprint|fprintf|fls)\b/.test(seg)) return "find with a mutating or exec action is not allowed in ro mode";
    if (w === "date" && /(?:^|\s)-s(?:\s|$)/.test(seg)) return "date -s (set the clock) is not allowed in ro mode";
    if (w === "java" && !["-version", "--version", "-XshowSettings"].includes(a)) return "java may only use -version/--version/-XshowSettings in ro mode";
    if (w === "apksigner" && a !== "verify") return "apksigner may only run 'verify' in ro mode";
    if (w === "aapt2" && a !== "dump") return "aapt2 may only run 'dump' in ro mode";
  }
  return null;
}

// ---------------------------------------------------------------- risk table

const RISK_RULES = [
  { id: "rm-root", level: "block", why: "removes the filesystem root",
    re: /\brm\s+(?:-[a-zA-Z-]+\s+)*-[a-zA-Z]*[rf][a-zA-Z]*\s+(?:-[a-zA-Z-]+\s+)*(?:\/|\/\*)(?:\s|$)/ },
  { id: "dd-dev", level: "block", why: "writes raw blocks to a device", re: /\bdd\b[^\n]*\bof=\s*\/dev\// },
  { id: "mkfs", level: "block", why: "formats a filesystem", re: /\bmkfs(\.\w+)?\b/ },
  { id: "fork-bomb", level: "block", why: "fork bomb", re: /:\s*\(\s*\)\s*\{[^}]*:\s*\|\s*:/ },
  { id: "stop-ssh", level: "block", why: "would cut the SSH session (and future ones)", re: /\bsystemctl\s+(?:stop|disable|mask|kill)\s+ssh/ },
  { id: "iptables-flush", level: "block", why: "flushes firewall rules", re: /\biptables\s+(?:-\w+\s+)*-F\b/ },
  { id: "etc-redirect", level: "block", why: "overwrites an auth database", re: />\s*\/etc\/(?:passwd|shadow|sudoers)/ },
  { id: "chmod-root", level: "block", why: "makes the root filesystem world-writable", re: /\bchmod\s+(?:-R\s+)?777\s+\/(?:\s|$)/ },
  { id: "power", level: "block", why: "power state change", re: /\b(?:shutdown|reboot|poweroff|halt)\b/ },
  { id: "kill-sshd", level: "block", why: "kills the ssh daemon", re: /\bkill\b[^\n]*\bsshd\b/ },
  { id: "rm-top", level: "warn", why: "removes a top-level tree",
    re: /\brm\s+(?:-[a-zA-Z-]+\s+)*-[a-zA-Z]*r[a-zA-Z]*\s+(?:-[a-zA-Z-]+\s+)*\/(?:srv(?:\/build)?|etc|root|home|data)(?:\/\*)?(?:\s|$)/ },
  { id: "git-clean", level: "warn", why: "discards untracked work", re: /\bgit\s+clean\s+-[a-zA-Z]*x[a-zA-Z]*d?[a-zA-Z]*\b/ },
  { id: "pipe-to-sh", level: "warn", why: "executes downloaded content", re: /\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba|z|k|da)?sh\b/ },
  { id: "rm-home", level: "warn", why: "removes the home directory", re: /\brm\s+-[a-zA-Z]*r[a-zA-Z]*\s+~(?:\/|\s|$)/ }
];

function riskCheck(cmd, perm) {
  const hits = [];
  for (const r of RISK_RULES) if (r.re.test(cmd)) hits.push(r);
  const blocked = hits.filter((h) => h.level === "block" && perm !== "full");
  return { hits: hits.map((h) => ({ id: h.id, level: h.level, why: h.why })), blocked };
}

// ---------------------------------------------------------------- s_shell

function userCommand(args) {
  const cmd = String(args.command || "").trim();
  if (!cmd) throw new Error("command is required");
  const cwd = args.cwd ? String(args.cwd) : "";
  if (cwd) {
    const j = jailCheck(cwd);
    if (j) throw new Error(j);
    return "cd " + q(cwd) + " && (" + cmd + ")";
  }
  return cmd;
}

async function preflight(cmd, perm) {
  if (perm === "selfcheck") throw new Error("perm=selfcheck: tools are disabled; run `node index.js --self-check` for diagnostics");
  if (perm === "ro") {
    const r = roCheck(cmd);
    if (r) throw new Error("perm=ro: " + r);
  }
  const { hits, blocked } = riskCheck(cmd, perm);
  if (blocked.length) {
    const b = blocked[0];
    throw new Error("blocked by risk rule '" + b.id + "' (" + b.why + "). perm=" + perm + ". Use perm=full (hot: echo full > ~/.ssh2mcp-perm) only if you mean it.");
  }
  return hits;
}

async function toolShell(args, perm) {
  const op = String(args.op || "run");
  const cmd = String(args.command || "").trim();

  if (op === "run") {
    const full = userCommand(args);
    const hits = await preflight(cmd, perm);
    const timeoutMs = Number(args.timeout_s || 0) * 1000 || DEFAULT_TIMEOUT_MS;
    // Killing the local client does not stop the remote command (no tty, no SIGHUP), so bound
    // it on the far side too. GNU timeout puts the child in its own process group and signals
    // the group, which also takes down the children of `sh -c`.
    const secs = Math.max(1, Math.round(timeoutMs / 1000));
    const bounded = "timeout -k 5 " + secs + " sh -c " + q(full);
    const r = await sshRun(bounded, { timeoutMs, noMux: true });
    const out = truncate(r.out, MAX_OUTPUT), err = truncate(r.err, MAX_OUTPUT);
    audit({ tool: "s_shell", op, perm, cmd_hash: sha(cmd).slice(0, 16), rules: hits.map((h) => h.id), exit: r.code, ms: r.ms });
    return {
      perm, exit: r.code, signal: r.signal || null, ms: r.ms, timed_out: r.timedOut,
      stdout: out.text, stdout_bytes: r.outBytes, stdout_truncated: out.truncated,
      stderr: err.text, stderr_bytes: r.errBytes,
      note: r.timedOut ? "local ssh was killed at the timeout; the remote command may still be running (use op=bg for long builds)" : undefined
    };
  }

  if (op === "bg") {
    const hits = await preflight(cmd, perm);
    if (perm === "ro") throw new Error("perm=ro: bg jobs are not allowed");
    const id = crypto.randomBytes(6).toString("hex");
    const tok = "S2M_HEREDOC_" + id.toUpperCase();
    const base = "/tmp/s2m-" + id;
    const script = [
      "cat > " + base + ".cmd<<'" + tok + "'",
      cmd,
      tok,
      "rm -f " + base + ".log " + base + ".exit " + base + ".pid",
      "setsid sh -c 'sh " + base + ".cmd > " + base + ".log 2>&1; echo $? > " + base + ".exit'< /dev/null > /dev/null 2>&1 &",
      "echo $! > " + base + ".pid",
      "cat " + base + ".pid"
    ].join("\n");
    const r = await sshRun("sh -s", { stdin: script, timeoutMs: 30000 });
    if (r.code !== 0) throw new Error("failed to start background job: " + (r.err.trim() || "exit " + r.code));
    audit({ tool: "s_shell", op, perm, job: id, cmd_hash: sha(cmd).slice(0, 16), rules: hits.map((h) => h.id) });
    return { perm, job: id, pid: r.out.trim(), log: base + ".log", note: "poll with {op:'log', job:'" + id + "'}" };
  }

  if (op === "log") {
    const id = String(args.job || "");
    if (!/^[0-9a-f]{12}$/.test(id)) throw new Error("job id must be 12 hex chars");
    const base = "/tmp/s2m-" + id;
    const since = Math.max(0, Number(args.since || 0));
    const [chunk, state] = await Promise.all([
      sshRun("tail -c +" + (since + 1) + " " + base + ".log 2>/dev/null"),
      sshRun("if [ -f " + base + ".exit ]; then echo done:$(cat " + base + ".exit); elif [ -f " + base + ".pid ] && kill -0 $(cat " + base + ".pid) 2>/dev/null; then echo running; else echo gone; fi")
    ]);
    const t = truncate(chunk.out, MAX_OUTPUT);
    audit({ tool: "s_shell", op, perm, job: id, exit: chunk.code });
    return {
      perm, job: id, state: state.out.trim(), since, next_since: since + chunk.outBytes,
      chunk: t.text, chunk_bytes: chunk.outBytes, truncated: t.truncated
    };
  }

  if (op === "kill") {
    const id = String(args.job || "");
    if (!/^[0-9a-f]{12}$/.test(id)) throw new Error("job id must be 12 hex chars");
    if (perm === "ro") throw new Error("perm=ro: kill is not allowed");
    const base = "/tmp/s2m-" + id;
    const r = await sshRun("if [ -f " + base + ".pid ]; then p=$(cat " + base + ".pid); kill -TERM $p 2>/dev/null; sleep 1; kill -KILL $p 2>/dev/null; echo killed:$p; else echo no-pid; fi");
    audit({ tool: "s_shell", op, perm, job: id });
    return { perm, job: id, result: r.out.trim() };
  }

  throw new Error("unknown op: " + op);
}

// ---------------------------------------------------------------- s_xfer

async function remoteStat(p) {
  const r = await sshRun("if [ -e " + q(p) + " ]; then stat -c '%s %Y' -- " + q(p) + "; else echo MISSING; fi", { timeoutMs: 30000 });
  const s = r.out.trim();
  if (s === "MISSING" || !s) return null;
  const [size, mtime] = s.split(/\s+/);
  return { size: Number(size), mtime: Number(mtime) };
}

async function remoteSha(p) {
  const r = await sshRun("sha256sum -- " + q(p) + " 2>/dev/null | cut -d' ' -f1", { timeoutMs: 120000 });
  return r.out.trim() || null;
}

async function streamPull(remotePath, part, start) {
  const ch = spawn(SSH_BIN, [...SSH_OPTS, SSH_HOST, "tail -c +" + (start + 1) + " -- " + q(remotePath)]);
  let errbuf = "";
  ch.stderr.on("data", (b) => { if (errbuf.length < 4096) errbuf += b.toString("utf8"); });
  // Arm the wait before awaiting pipeline: on small files exit/close can land before
  // pipeline() resolves, and a once() attached afterwards never fires (silent hang).
  const exited = once(ch, "exit");
  await pipeline(ch.stdout, fs.createWriteStream(part, { flags: start === 0 ? "w" : "a" }));
  const [code] = await exited;
  if (code !== 0) throw new Error("remote tail failed (" + code + "): " + errbuf.trim());
}

async function xferPull(local, remote, o) {
  const j = jailCheck(remote); if (j) throw new Error(j);
  const t0 = Date.now();
  const st = await remoteStat(remote);
  if (!st) throw new Error("remote path not found: " + remote);
  const part = local + ".part";
  fs.mkdirSync(path.dirname(path.resolve(local)), { recursive: true });

  let start = 0;
  if (fs.existsSync(part)) {
    const have = fs.statSync(part).size;
    if (have < st.size) start = have;
    else if (have > st.size) { fs.truncateSync(part, 0); start = 0; }
    else start = have;
  } else {
    fs.writeFileSync(part, "");
    start = 0;
  }

  if (start < st.size) await streamPull(remote, part, start);

  const got = fs.statSync(part).size;
  if (got !== st.size) throw new Error("size mismatch after transfer: local " + got + " vs remote " + st.size + " (partial kept at " + part + ")");

  if (o.verify !== false) {
    const [lsha, rsha] = await Promise.all([sha256File(part), remoteSha(remote)]);
    if (!rsha || lsha !== rsha) {
      fs.renameSync(part, part + ".corrupt");
      throw new Error("sha256 mismatch: local " + lsha + " vs remote " + (rsha || "?") + " (kept " + part + ".corrupt, next attempt restarts from 0)");
    }
    fs.renameSync(part, local);
    audit({ tool: "s_xfer", op: "pull", perm: o.perm, bytes: st.size, sha256: lsha, resumed_from: start, ms: Date.now() - t0 });
    return { perm: o.perm, bytes: st.size, sha256: lsha, resumed_from: start, ms: Date.now() - t0, local };
  }
  fs.renameSync(part, local);
  audit({ tool: "s_xfer", op: "pull", perm: o.perm, bytes: st.size, resumed_from: start, ms: Date.now() - t0, verified: false });
  return { perm: o.perm, bytes: st.size, resumed_from: start, ms: Date.now() - t0, local, verified: false };
}

async function xferPush(local, remote, o) {
  const j = jailCheck(remote); if (j) throw new Error(j);
  const t0 = Date.now();
  if (!fs.existsSync(local)) throw new Error("local path not found: " + local);
  const lstat = fs.statSync(local);
  if (lstat.isDirectory()) throw new Error("local path is a directory; tar it first");
  const rpart = remote + ".part";

  let start = 0;
  const pst = await remoteStat(rpart);
  if (pst && pst.size < lstat.size) start = pst.size;
  else if (pst) await sshRun("rm -f -- " + q(rpart));

  if (start < lstat.size) {
    const ch = spawn(SSH_BIN, [...SSH_OPTS, SSH_HOST, "cat >> " + q(rpart)]);
    let errbuf = "";
    ch.stderr.on("data", (b) => { if (errbuf.length < 4096) errbuf += b.toString("utf8"); });
    const exited = once(ch, "exit");   // arm before pipeline, same race as streamPull
    await pipeline(fs.createReadStream(local, { start }), ch.stdin);
    const [code] = await exited;
    if (code !== 0) throw new Error("remote append failed (" + code + "): " + errbuf.trim());
  }

  const after = await remoteStat(rpart);
  if (!after || after.size !== lstat.size) throw new Error("size mismatch after upload: remote " + (after ? after.size : "missing") + " vs local " + lstat.size);

  if (o.verify !== false) {
    const [lsha, rsha] = await Promise.all([sha256File(local), remoteSha(rpart)]);
    if (!rsha || lsha !== rsha) {
      await sshRun("mv -f -- " + q(rpart) + " " + q(rpart + ".corrupt"));
      throw new Error("sha256 mismatch: local " + lsha + " vs remote " + (rsha || "?") + " (remote partial renamed to .corrupt)");
    }
    const mv = await sshRun("mv -f -- " + q(rpart) + " " + q(remote));
    if (mv.code !== 0) throw new Error("rename failed: " + mv.err.trim());
    audit({ tool: "s_xfer", op: "push", perm: o.perm, bytes: lstat.size, sha256: lsha, resumed_from: start, ms: Date.now() - t0 });
    return { perm: o.perm, bytes: lstat.size, sha256: lsha, resumed_from: start, ms: Date.now() - t0, remote, warning: o.perm === "rw" ? "you pushed source into the build machine; is this really not a git push?" : undefined };
  }
  throw new Error("verify:false is not supported for push (a silent half-file on the build machine is worse than a failure)");
}

async function toolXfer(args, perm) {
  const op = String(args.op || "status");
  if (op === "status") {
    return {
      perm, host: SSH_HOST, jail: JAIL || "(none)",
      semantics: "pull = remote -> local, push = local -> remote; both resume from the first missing byte and verify sha256",
      allowed: { pull: perm !== "selfcheck", push: perm === "rw" || perm === "full" }
    };
  }
  if (perm === "selfcheck") throw new Error("perm=selfcheck: tools are disabled");
  const local = String(args.local || ""), remote = String(args.remote || "");
  if (!local || !remote) throw new Error("local and remote are required");
  if (op === "pull") return xferPull(local, remote, { perm, verify: args.verify !== false });
  if (op === "push") {
    if (perm === "ro") throw new Error("perm=ro: push is not allowed");
    return xferPush(local, remote, { perm, verify: true });
  }
  throw new Error("unknown op: " + op);
}

// ---------------------------------------------------------------- s_file (read-only)

function localSide(p) {
  try {
    const st = fs.statSync(p);
    return { exists: true, type: st.isDirectory() ? "dir" : "file", size: st.size, mtime: Math.floor(st.mtimeMs / 1000) };
  } catch (_) { return { exists: false }; }
}

async function remoteSide(p) {
  const r = await sshRun("if [ -e " + q(p) + " ]; then if [ -d " + q(p) + " ]; then echo DIR; else stat -c '%s %Y' -- " + q(p) + "; fi; else echo MISSING; fi", { timeoutMs: 30000 });
  const s = r.out.trim();
  if (s === "MISSING") return { exists: false };
  if (s === "DIR") return { exists: true, type: "dir" };
  const [size, mtime] = s.split(/\s+/);
  return { exists: true, type: "file", size: Number(size), mtime: Number(mtime) };
}

async function toolFile(args, perm) {
  const op = String(args.op || "compare");
  if (perm === "selfcheck") throw new Error("perm=selfcheck: tools are disabled");
  const p = String(args.path || "");
  if (!p && !(args.local_path && args.remote_path)) throw new Error("path is required (or both local_path and remote_path)");
  const side = String(args.side || "both");
  const lroot = args.local_root ? path.resolve(String(args.local_root)) : process.cwd();
  const rroot = args.remote_root ? String(args.remote_root).replace(/\/+$/, "") : "";
  let lp, rp;
  if (args.local_path || args.remote_path) {
    if (!args.local_path || !args.remote_path) throw new Error("give both local_path and remote_path, or use path together with local_root/remote_root");
    lp = String(args.local_path);
    rp = String(args.remote_path);
  } else {
    if (path.isAbsolute(p) && (args.local_root || args.remote_root)) {
      throw new Error("an absolute path cannot be combined with local_root/remote_root (one path cannot address two trees); use local_path + remote_path");
    }
    lp = path.isAbsolute(p) ? p : path.join(lroot, p);
    rp = path.isAbsolute(p) ? p : (rroot ? rroot + "/" + p : p);
  }
  const j = jailCheck(rp); if (j) throw new Error(j);

  if (op === "stat" || op === "hash" || op === "list" || op === "read") {
    const out = { perm, local_path: lp, remote_path: rp };
    if (side !== "remote") {
      out.local = localSide(lp);
      if (out.local.exists && out.local.type === "file") {
        if (op === "hash") out.local.sha256 = out.local.size <= HASH_CAP ? await sha256File(lp) : "skipped: file larger than " + HASH_CAP;
        if (op === "read") { const b = fs.readFileSync(lp); out.local.content = truncate(b.toString("utf8"), MAX_OUTPUT).text; }
      }
      if (op === "list" && out.local.exists) out.local.entries = fs.readdirSync(lp).slice(0, 200);
    }
    if (side !== "local") {
      out.remote = await remoteSide(rp);
      if (out.remote.exists && out.remote.type === "file") {
        if (op === "hash") { const s = await remoteSha(rp); out.remote.sha256 = s || "unavailable"; }
        if (op === "read") { const r = await sshRun("head -c " + MAX_OUTPUT + " -- " + q(rp), { timeoutMs: 30000 }); out.remote.content = r.out; out.remote.truncated = r.outBytes >= MAX_OUTPUT; }
      }
      if (op === "list" && out.remote.exists) {
        const r = await sshRun("ls -1 -- " + q(rp) + " | head -200");
        out.remote.entries = r.out.split("\n").filter(Boolean);
      }
    }
    audit({ tool: "s_file", op, perm, path_hash: sha(rp).slice(0, 16) });
    return out;
  }

  if (op !== "compare") throw new Error("unknown op: " + op);

  const [L, R] = await Promise.all([localSide(lp), remoteSide(rp)]);
  const out = { perm, local_path: lp, remote_path: rp, local: L, remote: R };
  if (!L.exists || !R.exists) {
    out.verdict = !L.exists && !R.exists ? "missing:both" : (!L.exists ? "missing:local" : "missing:remote");
    return out;
  }
  if (L.type === "dir" || R.type === "dir") { out.verdict = "directory"; return out; }
  if (L.size !== R.size) { out.verdict = "size-differs"; return out; }

  if (L.size <= HASH_CAP) {
    const [lsha, rsha] = await Promise.all([sha256File(lp), remoteSha(rp)]);
    out.local.sha256 = lsha; out.remote.sha256 = rsha;
    if (!rsha) { out.verdict = "hash-unavailable"; return out; }
    out.verdict = lsha === rsha ? "same" : "content-differs";
    if (out.verdict === "content-differs" && L.size <= DIFF_CAP) {
      const [lb, rr] = await Promise.all([fs.promises.readFile(lp), sshRun("cat -- " + q(rp), { timeoutMs: 30000 })]);
      const rb = Buffer.from(rr.out, "utf8");
      const isText = (b) => b.subarray(0, 8192).indexOf(0) < 0;
      if (isText(lb) && isText(rb)) {
        const a = lb.toString("utf8").split("\n"), b = rb.toString("utf8").split("\n");
        for (let i = 0; i < Math.max(a.length, b.length); i++) {
          if (a[i] !== b[i]) { out.first_diff = { line: i + 1, local: a[i] === undefined ? null : a[i].slice(0, 200), remote: b[i] === undefined ? null : b[i].slice(0, 200) }; break; }
        }
      }
    }
  } else {
    out.verdict = "same-size-unhashed";
    out.note = "file larger than " + HASH_CAP + " bytes; compared by size and mtime only (mtime local=" + L.mtime + " remote=" + R.mtime + ")";
  }
  audit({ tool: "s_file", op, perm, path_hash: sha(rp).slice(0, 16), verdict: out.verdict });
  return out;
}

// ---------------------------------------------------------------- MCP wiring

const TOOLS = [
  {
    name: "s_shell",
    description: "Run a command on the remote SSH host. op=run (default) returns exit code, stdout/stderr (head+tail truncated), duration. op=bg starts a detached job and returns a job id; poll with op=log (byte offset resume) or stop with op=kill. Subject to the permission level, the path jail and the risk table.",
    inputSchema: {
      type: "object",
      properties: {
        op: { type: "string", enum: ["run", "bg", "log", "kill"], default: "run" },
        command: { type: "string", description: "Shell command (op=run|bg)" },
        cwd: { type: "string", description: "Optional remote working directory (op=run)" },
        timeout_s: { type: "number", description: "Timeout for op=run, default 120, max 3600" },
        job: { type: "string", description: "Job id from op=bg (op=log|kill)" },
        since: { type: "number", description: "Byte offset to resume from (op=log)" }
      }
    }
  },
  {
    name: "s_xfer",
    description: "Transfer one file between this device and the remote host. op=pull (remote->local) or op=push (local->remote). Resumes from the first missing byte, writes to a .part file, verifies sha256 on both ends and only then renames. Bytes never pass through the model. op=status reports the rules in force.",
    inputSchema: {
      type: "object",
      properties: {
        op: { type: "string", enum: ["pull", "push", "status"], default: "status" },
        local: { type: "string", description: "Absolute local path" },
        remote: { type: "string", description: "Absolute remote path" },
        verify: { type: "boolean", description: "Verify sha256 after transfer (default true)", default: true }
      }
    }
  },
  {
    name: "s_file",
    description: "Read-only file inspection on both ends at once: stat, hash, list, read, or compare (default). compare reports same / size-differs / content-differs / missing:<side>, plus the first differing line for small text files. There is deliberately no write op - use s_xfer so every modification is a visible transfer.",
    inputSchema: {
      type: "object",
      properties: {
        op: { type: "string", enum: ["compare", "stat", "hash", "list", "read"], default: "compare" },
        path: { type: "string", description: "Relative path, resolved against local_root/remote_root; absolute is used on both sides (only when the trees share a layout)" },
        side: { type: "string", enum: ["both", "local", "remote"], default: "both" },
        local_root: { type: "string", description: "Local base directory (default: process cwd); path must then be relative" },
        remote_root: { type: "string", description: "Remote base directory; path must then be relative" },
        local_path: { type: "string", description: "Explicit absolute local path; requires remote_path and overrides path/roots" },
        remote_path: { type: "string", description: "Explicit absolute remote path; requires local_path" }
      }
    }
  }
];

function createServer() {
  const server = new Server({ name: "ssh2mcp", version: VERSION }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const name = req.params.name;
    const args = req.params.arguments || {};
    const perm = readPerm();
    notePerm(perm);
    try {
      let out;
      if (name === "s_shell") out = await toolShell(args, perm);
      else if (name === "s_xfer") out = await toolXfer(args, perm);
      else if (name === "s_file") out = await toolFile(args, perm);
      else return { content: [{ type: "text", text: "Unknown tool: " + name }], isError: true };
      return { content: [{ type: "text", text: JSON.stringify(out, null, 2) }] };
    } catch (e) {
      return { content: [{ type: "text", text: JSON.stringify({ perm, error: e.message }, null, 2) }], isError: true };
    }
  });
  return server;
}

// ---------------------------------------------------------------- auth

function readToken() {
  if (process.env.SSH2MCP_TOKEN) return String(process.env.SSH2MCP_TOKEN).trim() || null;
  try { const t = fs.readFileSync(TOKEN_FILE, "utf-8").trim(); return t || null; } catch (_) { return null; }
}
function tokenEquals(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || !a.length || !b.length) return false;
  const ba = Buffer.from(a, "utf-8"), bb = Buffer.from(b, "utf-8");
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}
function bearerOf(req) {
  const m = /^Bearer[ \t]+(.+)$/i.exec(String(req.headers.authorization || "").trim());
  return m ? m[1].trim() : null;
}

// ---------------------------------------------------------------- CLI modes

function selfTest() {
  let fail = 0;
  const risk = [
    ["rm -rf /", "block"], ["rm -rf /*", "block"], ["dd if=/dev/zero of=/dev/sda", "block"],
    ["mkfs.ext4 /dev/sdb1", "block"], ["shutdown -h now", "block"], ["iptables -F", "block"],
    ["echo x > /etc/passwd", "block"], ["systemctl stop ssh", "block"], ["kill -9 1234 # sshd", "block"],
    ["rm -rf /srv/build", "warn"], ["git clean -xdf", "warn"], ["curl -fsSL http://x | sh", "warn"],
    ["cd /srv/build && ./gradlew --no-daemon assembleRelease", "none"],
    ["ls -la /srv", "none"], ["rm -rf /srv/build/app/build", "none"], ["git status --short", "none"]
  ];
  for (const [cmd, want] of risk) {
    const { hits, blocked } = riskCheck(cmd, "rw");
    const got = blocked.length ? "block" : (hits.length ? "warn" : "none");
    const ok = got === want;
    if (!ok) fail++;
    console.log((ok ? "PASS" : "FAIL") + "  risk  " + JSON.stringify(cmd) + "  want=" + want + " got=" + got);
  }
  const ro = [
    ["ls -la", true], ["cat foo | grep bar", true], ["git log --oneline -5", true], ["./gradlew --version", true],
    ["rm foo", false], ["ls; rm -rf /", false], ["git config user.name x", false], ["curl http://x", false],
    ["./gradlew assembleRelease", false], ["find . -name x -delete", false],
    ["java -version", true], ["java -jar evil.jar", false], ["apksigner sign --ks k", false],
    ["aapt2 dump badging x.apk", true], ["date -s 2020-01-01", false], ["env rm -rf /", false]
  ];
  for (const [cmd, allowed] of ro) {
    const err = roCheck(cmd);
    const ok = allowed ? err === null : err !== null;
    if (!ok) fail++;
    console.log((ok ? "PASS" : "FAIL") + "  ro    " + JSON.stringify(cmd) + "  want=" + (allowed ? "allow" : "deny") + " got=" + (err ? "deny" : "allow"));
  }
  console.log("\n" + (fail ? fail + " FAILED" : "all " + (risk.length + ro.length) + " checks passed"));
  process.exit(fail ? 1 : 0);
}

async function selfCheck() {
  const rows = [];
  const add = (name, ok, detail) => rows.push({ name, ok, detail });
  add("token file", !!readToken(), readToken() ? TOKEN_FILE + " (present, value not printed)" : "MISSING: python3 -c \"import secrets;print(secrets.token_hex(24))\" > " + TOKEN_FILE + " && chmod 600 " + TOKEN_FILE);
  add("perm", true, readPerm() + " (fallback from CLI: " + BASE_PERM + ")");
  add("jail", true, JAIL || "(none)");
  add("ssh binary", fs.existsSync("/data/data/com.termux/files/usr/bin/ssh") || true, SSH_BIN);
  const ping = await sshRun("echo S2M_OK; uname -sr; nproc; free -g | awk 'NR==2{print \"mem_gb=\"$2\" avail=\"$7}'; df -h / | awk 'NR==2{print \"disk=\"$4\" free\"}'", { timeoutMs: 20000 });
  add("ssh connect (" + SSH_HOST + ")", ping.code === 0 && ping.out.includes("S2M_OK"), ping.code === 0 ? ping.out.trim().replace(/\n/g, " | ") : ping.err.trim() || "exit " + ping.code);
  if (ping.code === 0) {
    const tc = await sshRun("command -v java >/dev/null && java -version 2>&1 | head -1 || echo 'java: missing'; command -v gradle >/dev/null && gradle --version 2>/dev/null | grep -m1 Gradle || echo 'gradle: not in PATH'; echo \"ANDROID_HOME=${ANDROID_HOME:-unset}\"; ls -d /srv/build 2>/dev/null || echo '/srv/build: missing'");
    add("remote toolchain", !/java: missing/.test(tc.out), tc.out.trim().replace(/\n/g, " | "));
    const wrt = await sshRun("d=$(mktemp -d) && head -c 1048576 /dev/urandom > $d/x && s=$(sha256sum $d/x | cut -d' ' -f1) && rm -rf $d && echo ok:$s", { timeoutMs: 30000 });
    add("remote tmp roundtrip", wrt.code === 0 && wrt.out.startsWith("ok:"), wrt.out.trim() || wrt.err.trim());
  }
  for (const r of rows) console.log((r.ok ? "PASS" : "FAIL") + "  " + r.name.padEnd(24) + "  " + r.detail);
  const bad = rows.filter((r) => !r.ok).length;
  console.log("\n" + (bad ? bad + " check(s) failed" : "all checks passed"));
  process.exit(bad ? 1 : 0);
}

function usage() {
  console.log(`ssh2mcp ${VERSION}

Usage: node index.js [options]

  --perm <ro|rw|full|selfcheck>   startup permission level (default rw)
                                  hot switch: echo <level> > ~/.ssh2mcp-perm
  --port <n>                      listen port (default 6222, env MCP_PORT)
  --self-test                     run the offline rule-table tests and exit
  --self-check                    run the connectivity/toolchain diagnostics and exit
  --help

Env: SSH2MCP_SSH_HOST (default "cloud"), SSH2MCP_ROOT (path jail, unset = off),
     SSH2MCP_TOKEN_FILE, SSH2MCP_PERM_FILE, SSH2MCP_MAX_OUTPUT, SSH2MCP_TIMEOUT_MS,
     SSH2MCP_SSH_BIN, SSH2MCP_BIND (default 127.0.0.1)

Permission levels:
  ro         read-only allowlist, no redirection/pipes into anything unknown, pull only
  rw         any command, destructive rules block; push allowed with a reminder
  full       any command, rules downgraded to warnings; no jail
  selfcheck  every tool refuses; use --self-check`);
}

// ---------------------------------------------------------------- main

if (FLAG_HELP) { usage(); process.exit(0); }
if (FLAG_SELF_TEST) selfTest();

function main() {
if (!PERMS.includes(BASE_PERM)) {
  console.error("invalid --perm: " + BASE_PERM + " (expected one of " + PERMS.join(", ") + ")");
  process.exit(2);
}
if (!readToken()) {
  console.error("refusing to start: no bearer token at " + TOKEN_FILE);
  console.error("  (binding to 127.0.0.1 is not access control: any app with INTERNET can reach it,");
  console.error("   and this server runs commands as root on the remote host)");
  console.error("  generate one:  python3 -c \"import secrets;print(secrets.token_hex(24))\" > " + TOKEN_FILE + " && chmod 600 " + TOKEN_FILE);
  process.exit(1);
}

const app = express();
app.use(localhostHostValidation());

function gate(req, res) {
  if (tokenEquals(bearerOf(req), readToken())) return true;
  res.status(401).json({ jsonrpc: "2.0", error: { code: -32001, message: "unauthorized: send Authorization: Bearer <token>" }, id: null });
  return false;
}

app.post("/mcp", (req, res, next) => { if (gate(req, res)) next(); }, express.json({ limit: "8mb" }), async (req, res) => {
  const srv = createServer();
  const t = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => { t.close().catch(() => {}); srv.close().catch(() => {}); });
  try {
    await srv.connect(t);
    await t.handleRequest(req, res, req.body);
  } catch (e) {
    if (!res.headersSent) res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal error: " + e.message }, id: null });
    else res.end();
  }
});
app.get("/mcp", (_req, res) => res.status(405).set("Allow", "POST").json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed." }, id: null }));
app.delete("/mcp", (_req, res) => res.status(405).set("Allow", "POST").json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed." }, id: null }));

app.get("/status", (req, res) => {
  if (!gate(req, res)) return;
  notePerm(readPerm());
  res.json({
    server: "ssh2mcp", version: VERSION, host: SSH_HOST, bind: BIND + ":" + PORT,
    perm: readPerm(), perm_fallback: BASE_PERM, perm_file: PERM_FILE,
    auth: { mode: "bearer", token_file: TOKEN_FILE, configured: true },
    jail: JAIL || null, risk_rules: RISK_RULES.length,
    tools: TOOLS.map((t) => t.name),
    audit_log: AUDIT_LOG
  });
});

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  res.status(err.status || 500).json({ jsonrpc: "2.0", error: { code: -32700, message: "Parse error: " + (err.message || String(err)) }, id: null });
});

const srv = app.listen(PORT, BIND, () => {
  console.error("ssh2mcp v" + VERSION + " on http://" + BIND + ":" + PORT + "/mcp (Streamable HTTP, stateless)");
  console.error("  ssh=" + SSH_HOST + "  perm=" + readPerm() + " (fallback " + BASE_PERM + ", hot file " + PERM_FILE + ")");
  console.error("  jail=" + (JAIL || "(none)") + "  risk_rules=" + RISK_RULES.length + "  audit=" + AUDIT_LOG);
});
srv.on("error", (e) => {
  console.error("listen failed on " + BIND + ":" + PORT + ": " + e.message +
    (e.code === "EADDRINUSE" ? " (pick another port with --port)" : ""));
  process.exit(1);
});
}

if (FLAG_SELF_CHECK) {
  selfCheck().catch((e) => { console.error("self-check failed: " + (e && e.message || e)); process.exit(1); });
} else {
  main();
}
