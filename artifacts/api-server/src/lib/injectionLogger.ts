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

  export async function logInjection(
    command: string,
    engine: string,
    mode: string,
    responseTime: number
  ): Promise<{ ok: boolean; error?: string }> {
    if (!db) {
      logger.warn({ engine, mode }, "injectionLogger: DB not available — DATABASE_URL not set");
      return { ok: false, error: "Database not configured" };
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
      return { ok: false, error: msg };
    }
  }

  export async function readLogs(limit = 200, offset = 0): Promise<InjectionLogEntry[]> {
    if (!db) {
      logger.warn("injectionLogger: DB not available — DATABASE_URL not set");
      return [];
    }
    try {
      const rows = await db
        .select()
        .from(injectionLogsTable)
        .orderBy(desc(injectionLogsTable.timestamp))
        .limit(limit)
        .offset(offset);

      return rows.map((r) => ({
        id: r.id,
        timestamp: r.timestamp.toISOString(),
        command: r.command,
        engine: r.engine,
        mode: r.mode,
        responseTime: r.responseTime,
      }));
    } catch (err: unknown) {
      const msg = (err as Error).message ?? String(err);
      logger.error({ err }, `injectionLogger: DB read failed — ${msg}`);
      return [];
    }
  }

  export async function clearLogs(): Promise<void> {
    if (!db) {
      logger.warn("injectionLogger: DB not available — DATABASE_URL not set");
      throw new Error("Database not configured");
    }
    try {
      await db.delete(injectionLogsTable);
    } catch (err: unknown) {
      const msg = (err as Error).message ?? String(err);
      logger.error({ err }, `injectionLogger: DB clear failed — ${msg}`);
      throw new Error(`Log clear failed: ${msg}`);
    }
  }
  