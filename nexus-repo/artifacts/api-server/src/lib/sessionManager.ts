/* ════════════════════════════════════════════════════════════════════
   NEXUSFORGE — Stateful Session Manager
   Maintains per-target working directory, env vars, and command history
   so subsequent commands run in the correct shell context.
   ════════════════════════════════════════════════════════════════════ */

import { randomUUID } from "crypto";
import { logger } from "./logger.js";

export interface SessionState {
  id:           string;
  targetUrl:    string;
  cwd:          string;
  env:          Record<string, string>;
  history:      string[];
  createdAt:    number;
  lastUsedAt:   number;
  confirmed:    boolean;
  confirmedMode?: string;
  oobToken?:    string;
}

const SESSIONS = new Map<string, SessionState>();
const SESSION_TTL_MS = 4 * 60 * 60 * 1000;

export function createSession(targetUrl: string): SessionState {
  const id = randomUUID();
  const s: SessionState = { id, targetUrl, cwd: "/", env: {}, history: [],
    createdAt: Date.now(), lastUsedAt: Date.now(), confirmed: false };
  SESSIONS.set(id, s);
  logger.info({ id, targetUrl }, "session created");
  return s;
}

export function getSession(id: string): SessionState | null {
  const s = SESSIONS.get(id) ?? null;
  if (s) s.lastUsedAt = Date.now();
  return s;
}

export function getOrCreateSession(targetUrl: string): SessionState {
  for (const s of SESSIONS.values()) {
    if (s.targetUrl === targetUrl && Date.now() - s.lastUsedAt < SESSION_TTL_MS) {
      s.lastUsedAt = Date.now(); return s;
    }
  }
  return createSession(targetUrl);
}

export function deleteSession(id: string): void {
  SESSIONS.delete(id);
  logger.info({ id }, "session deleted");
}

export function listSessions(): SessionState[] {
  return [...SESSIONS.values()].sort((a, b) => b.lastUsedAt - a.lastUsedAt);
}

export function sessionAddHistory(id: string, cmd: string): void {
  const s = SESSIONS.get(id); if (!s) return;
  s.history.push(cmd); if (s.history.length > 500) s.history.shift();
}

export function sessionSetCwd(id: string, cwd: string): void {
  const s = SESSIONS.get(id); if (s) s.cwd = cwd;
}

export function sessionSetEnv(id: string, key: string, val: string): void {
  const s = SESSIONS.get(id); if (s) s.env[key] = val;
}

export function sessionMarkConfirmed(id: string, mode: string, oobToken?: string): void {
  const s = SESSIONS.get(id); if (!s) return;
  s.confirmed = true; s.confirmedMode = mode; if (oobToken) s.oobToken = oobToken;
}

/** Prepend cd+env context so injected command runs in the right directory. */
export function enrichCmd(id: string, rawCmd: string): string {
  const s = SESSIONS.get(id); if (!s) return rawCmd;
  const envPrefix = Object.entries(s.env).map(([k,v]) => `export ${k}='${v.replace(/'/g, "'\\''")}'`).join("; ");
  const cdPart = s.cwd !== "/" ? `cd '${s.cwd}'` : "";
  const prefix = [envPrefix, cdPart].filter(Boolean).join("; ");
  return prefix ? `${prefix}; ${rawCmd}` : rawCmd;
}

/** Parse command output to track CWD changes. */
export function updateCwdFromOutput(id: string, cmd: string, output: string): void {
  const s = SESSIONS.get(id); if (!s) return;
  const cdMatch = cmd.trim().match(/^cd\s+([^;|&]+)/);
  if (!cdMatch) return;
  const target = cdMatch[1]!.trim();
  if (target.startsWith("/")) { s.cwd = target; }
  else if (target === "..") {
    const parts = s.cwd.split("/").filter(Boolean); parts.pop();
    s.cwd = "/" + parts.join("/");
  } else { s.cwd = s.cwd.replace(/\/$/, "") + "/" + target; }
  const pwdLine = output.match(/^\/\S*/m);
  if (pwdLine) s.cwd = pwdLine[0];
}

setInterval(() => {
  const now = Date.now();
  for (const [id, s] of SESSIONS.entries()) {
    if (now - s.lastUsedAt > SESSION_TTL_MS) {
      SESSIONS.delete(id); logger.info({ id }, "session GC — expired");
    }
  }
}, 15 * 60 * 1000);