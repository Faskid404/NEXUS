/* ════════════════════════════════════════════════════════════════════
   NEXUSFORGE — Stateful Session Manager  (enhanced)
   ════════════════════════════════════════════════════════════════════ */

import { randomUUID } from "crypto";
import { createLogger } from "./logger.js";

const log = createLogger("sessionManager");

export interface SessionState {
  id:             string;
  targetUrl:      string;
  cwd:            string;
  env:            Record<string, string>;
  history:        string[];
  tags:           string[];
  createdAt:      number;
  lastUsedAt:     number;
  confirmed:      boolean;
  confirmedMode?: string;
  oobToken?:      string;
  commandCount:   number;
  errorCount:     number;
}

const SESSIONS      = new Map<string, SessionState>();
const SESSION_TTL_MS  = 4  * 60 * 60 * 1_000;  // 4 hours
const MAX_HISTORY     = 500;
const MAX_SESSIONS    = Number(process.env["MAX_NEXUS_SESSIONS"] ?? 200);

/* ── LRU eviction when at capacity ────────────────────────────────── */
function evictOldestIfNeeded(): void {
  if (SESSIONS.size < MAX_SESSIONS) return;
  let oldest: SessionState | null = null;
  for (const s of SESSIONS.values()) {
    if (!oldest || s.lastUsedAt < oldest.lastUsedAt) oldest = s;
  }
  if (oldest) {
    SESSIONS.delete(oldest.id);
    log.info({ evictedId: oldest.id, targetUrl: oldest.targetUrl }, "session evicted (LRU)");
  }
}

export function createSession(targetUrl: string, tags: string[] = []): SessionState {
  evictOldestIfNeeded();
  const id = randomUUID();
  const s: SessionState = {
    id, targetUrl, cwd: "/", env: {}, history: [], tags,
    createdAt: Date.now(), lastUsedAt: Date.now(),
    confirmed: false, commandCount: 0, errorCount: 0,
  };
  SESSIONS.set(id, s);
  log.info({ id, targetUrl }, "session created");
  return s;
}

export function getSession(id: string): SessionState | null {
  const s = SESSIONS.get(id) ?? null;
  if (s) s.lastUsedAt = Date.now();
  return s;
}

export function getOrCreateSession(targetUrl: string, tags?: string[]): SessionState {
  for (const s of SESSIONS.values()) {
    if (s.targetUrl === targetUrl && Date.now() - s.lastUsedAt < SESSION_TTL_MS) {
      s.lastUsedAt = Date.now();
      return s;
    }
  }
  return createSession(targetUrl, tags);
}

export function deleteSession(id: string): boolean {
  const existed = SESSIONS.has(id);
  SESSIONS.delete(id);
  if (existed) log.info({ id }, "session deleted");
  return existed;
}

export function listSessions(): SessionState[] {
  return [...SESSIONS.values()].sort((a, b) => b.lastUsedAt - a.lastUsedAt);
}

/** Find all active sessions for a given target URL. */
export function findSessionsByUrl(targetUrl: string): SessionState[] {
  return [...SESSIONS.values()].filter(s => s.targetUrl === targetUrl);
}

export function sessionAddHistory(id: string, cmd: string): void {
  const s = SESSIONS.get(id);
  if (!s) return;
  // Deduplicate consecutive identical commands
  if (s.history[s.history.length - 1] !== cmd) {
    s.history.push(cmd);
    if (s.history.length > MAX_HISTORY) s.history.shift();
  }
  s.commandCount++;
}

export function sessionRecordError(id: string): void {
  const s = SESSIONS.get(id);
  if (s) s.errorCount++;
}

export function sessionSetCwd(id: string, cwd: string): void {
  const s = SESSIONS.get(id);
  if (s) s.cwd = cwd;
}

export function sessionSetEnv(id: string, key: string, val: string): void {
  const s = SESSIONS.get(id);
  if (s) s.env[key] = val;
}

export function sessionUnsetEnv(id: string, key: string): void {
  const s = SESSIONS.get(id);
  if (s) delete s.env[key];
}

export function sessionMarkConfirmed(id: string, mode: string, oobToken?: string): void {
  const s = SESSIONS.get(id);
  if (!s) return;
  s.confirmed = true;
  s.confirmedMode = mode;
  if (oobToken) s.oobToken = oobToken;
}

export function sessionAddTag(id: string, tag: string): void {
  const s = SESSIONS.get(id);
  if (s && !s.tags.includes(tag)) s.tags.push(tag);
}

/** Summary stats about the session pool. */
export function getSessionStats(): {
  total:     number;
  confirmed: number;
  active:    number;
  maxAllowed: number;
} {
  const now    = Date.now();
  let confirmed = 0, active = 0;
  for (const s of SESSIONS.values()) {
    if (s.confirmed) confirmed++;
    if (now - s.lastUsedAt < 30 * 60 * 1_000) active++;
  }
  return { total: SESSIONS.size, confirmed, active, maxAllowed: MAX_SESSIONS };
}

/** Prepend cd+env context so an injected command runs in the right shell context. */
export function enrichCmd(id: string, rawCmd: string): string {
  const s = SESSIONS.get(id);
  if (!s) return rawCmd;
  const envPrefix = Object.entries(s.env)
    .map(([k, v]) => `export ${k}='${v.replace(/'/g, "'\\''")}'`)
    .join("; ");
  const cdPart  = s.cwd !== "/" ? `cd '${s.cwd}'` : "";
  const prefix  = [envPrefix, cdPart].filter(Boolean).join("; ");
  return prefix ? `${prefix}; ${rawCmd}` : rawCmd;
}

/** Parse command output to track CWD changes. */
export function updateCwdFromOutput(id: string, cmd: string, output: string): void {
  const s = SESSIONS.get(id);
  if (!s) return;
  const cdMatch = cmd.trim().match(/^cd\s+([^;|&]+)/);
  if (!cdMatch) return;
  const target = cdMatch[1]!.trim();
  if (target.startsWith("/")) {
    s.cwd = target;
  } else if (target === "..") {
    const parts = s.cwd.split("/").filter(Boolean);
    parts.pop();
    s.cwd = "/" + parts.join("/") || "/";
  } else {
    s.cwd = (s.cwd === "/" ? "" : s.cwd) + "/" + target;
  }
  // Prefer actual pwd output if available
  const pwdLine = output.match(/^\/\S*/m);
  if (pwdLine) s.cwd = pwdLine[0];
}

/* ── Periodic GC ───────────────────────────────────────────────────── */
setInterval(() => {
  const now    = Date.now();
  let   evicted = 0;
  for (const [id, s] of SESSIONS.entries()) {
    if (now - s.lastUsedAt > SESSION_TTL_MS) {
      SESSIONS.delete(id);
      evicted++;
    }
  }
  if (evicted > 0) log.info({ evicted, remaining: SESSIONS.size }, "session GC completed");
}, 15 * 60 * 1_000).unref();
