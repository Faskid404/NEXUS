import { db, injectionLogsTable } from "@workspace/db";
import { desc } from "drizzle-orm";
import { logger } from "./logger.js";

export interface InjectionLogEntry {
  id: number;
  timestamp: string;
  command: string;
  engine: string;
  mode: string;
  responseTime: number;
}

/* ── In-memory fallback (used when DATABASE_URL is not configured) ───── */
const MAX_MEM_LOGS = 500;
const memLogs: InjectionLogEntry[] = [];
let   memNextId = 1;

function memWrite(command: string, engine: string, mode: string, responseTime: number): void {
  memLogs.unshift({
    id:           memNextId++,
    timestamp:    new Date().toISOString(),
    command:      String(command).slice(0, 300),
    engine,
    mode,
    responseTime,
  });
  if (memLogs.length > MAX_MEM_LOGS) memLogs.splice(MAX_MEM_LOGS);
}

export async function logInjection(
  command: string,
  engine: string,
  mode: string,
  responseTime: number
): Promise<{ ok: boolean; error?: string }> {
  if (!db) {
    memWrite(command, engine, mode, responseTime);
    return { ok: true };
  }
  try {
    await db.insert(injectionLogsTable).values({
      command: String(command).slice(0, 300),
      engine,
      mode,
      responseTime,
    });
    return { ok: true };
  } catch (err: unknown) {
    const msg = (err as Error).message ?? String(err);
    logger.error({ err, engine, mode }, `injectionLogger: DB write failed — ${msg}`);
    /* Fallback: keep the entry in memory so it isn't silently lost */
    memWrite(command, engine, mode, responseTime);
    return { ok: false, error: msg };
  }
}

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

    return rows.map((r) => ({
      id:           r.id,
      timestamp:    r.timestamp.toISOString(),
      command:      r.command,
      engine:       r.engine,
      mode:         r.mode,
      responseTime: r.responseTime,
    }));
  } catch (err: unknown) {
    const msg = (err as Error).message ?? String(err);
    logger.error({ err }, `injectionLogger: DB read failed — ${msg}`);
    /* Fallback: return whatever we have in memory */
    return memLogs.slice(offset, offset + limit);
  }
}

export async function clearLogs(): Promise<void> {
  if (!db) {
    memLogs.splice(0);
    return;
  }
  try {
    await db.delete(injectionLogsTable);
    /* Also wipe memory buffer so no stale entries linger */
    memLogs.splice(0);
  } catch (err: unknown) {
    const msg = (err as Error).message ?? String(err);
    logger.error({ err }, `injectionLogger: DB clear failed — ${msg}`);
    throw new Error(`Log clear failed: ${msg}`);
  }
}
