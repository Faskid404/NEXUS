import { db, injectionLogsTable } from "@workspace/db";
import { desc } from "drizzle-orm";
import { createLogger } from "./logger.js";

const log = createLogger("injectionLogger");

export interface InjectionLogEntry {
  id:           number;
  timestamp:    string;
  command:      string;
  engine:       string;
  mode:         string;
  responseTime: number;
}

export interface LogStats {
  total:        number;
  byMode:       Record<string, number>;
  byEngine:     Record<string, number>;
  avgResponseMs: number;
  minResponseMs: number;
  maxResponseMs: number;
  source:        "database" | "memory";
}

/* ── In-memory fallback ─────────────────────────────────────────────── */
const MAX_MEM_LOGS = 1_000;
const memLogs: InjectionLogEntry[] = [];
let   memNextId = 1;

function memWrite(command: string, engine: string, mode: string, responseTime: number): void {
  memLogs.unshift({
    id:           memNextId++,
    timestamp:    new Date().toISOString(),
    command:      String(command).slice(0, 500),
    engine,
    mode,
    responseTime,
  });
  if (memLogs.length > MAX_MEM_LOGS) memLogs.splice(MAX_MEM_LOGS);
}

/* ── logInjection ────────────────────────────────────────────────────── */
export async function logInjection(
  command:      string,
  engine:       string,
  mode:         string,
  responseTime: number,
): Promise<{ ok: boolean; error?: string }> {
  // Always write to memory (instant) — serves as a hot cache
  memWrite(command, engine, mode, responseTime);

  if (!db) return { ok: true };

  try {
    await db.insert(injectionLogsTable).values({
      command: String(command).slice(0, 500),
      engine,
      mode,
      responseTime,
    });
    return { ok: true };
  } catch (err: unknown) {
    const msg = (err as Error).message ?? String(err);
    log.error({ err, engine, mode }, `DB write failed — ${msg}`);
    return { ok: false, error: msg };
  }
}

/* ── readLogs ────────────────────────────────────────────────────────── */
export async function readLogs(limit = 200, offset = 0): Promise<InjectionLogEntry[]> {
  if (!db) {
    return memLogs.slice(offset, offset + limit);
  }
  try {
    const rows = await db
      .select()
      .from(injectionLogsTable)
      .orderBy(desc(injectionLogsTable.timestamp))
      .limit(limit)
      .offset(offset);
    return rows.map(r => ({
      id:           r.id,
      timestamp:    r.timestamp.toISOString(),
      command:      r.command,
      engine:       r.engine,
      mode:         r.mode,
      responseTime: r.responseTime,
    }));
  } catch (err: unknown) {
    const msg = (err as Error).message ?? String(err);
    log.error({ err }, `DB read failed — ${msg}`);
    // Fallback: serve from memory buffer
    return memLogs.slice(offset, offset + limit);
  }
}

/* ── getLogStats ─────────────────────────────────────────────────────── */
export async function getLogStats(): Promise<LogStats> {
  const logs = await readLogs(10_000, 0);

  const byMode:   Record<string, number> = {};
  const byEngine: Record<string, number> = {};
  let   sum = 0, min = Infinity, max = -Infinity;

  for (const l of logs) {
    byMode[l.mode]     = (byMode[l.mode]     ?? 0) + 1;
    byEngine[l.engine] = (byEngine[l.engine] ?? 0) + 1;
    sum += l.responseTime;
    if (l.responseTime < min) min = l.responseTime;
    if (l.responseTime > max) max = l.responseTime;
  }

  return {
    total:         logs.length,
    byMode,
    byEngine,
    avgResponseMs: logs.length > 0 ? Math.round(sum / logs.length) : 0,
    minResponseMs: logs.length > 0 ? min : 0,
    maxResponseMs: logs.length > 0 ? max : 0,
    source:        db ? "database" : "memory",
  };
}

/* ── clearLogs ───────────────────────────────────────────────────────── */
export async function clearLogs(): Promise<void> {
  memLogs.splice(0);
  if (!db) return;
  try {
    await db.delete(injectionLogsTable);
  } catch (err: unknown) {
    const msg = (err as Error).message ?? String(err);
    log.error({ err }, `DB clear failed — ${msg}`);
    throw new Error(`Log clear failed: ${msg}`);
  }
}
