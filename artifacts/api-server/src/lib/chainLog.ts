import { db, chainRunsTable } from "@workspace/db";
import { desc } from "drizzle-orm";
import { logger } from "./logger.js";

export interface ChainRun {
  id:            number;
  timestamp:     string;
  targetUrl:     string;
  injectParam:   string;
  httpMethod:    string;
  cmd:           string;
  confirmed:     boolean;
  confirmedMode: string | null;
  confirmedVia:  string | null;
  exfilData:     string;
  elapsed:       number;
  modesRun:      number;
  totalModes:    number;
  oobToken:      string;
}

export function addChainRun(run: Omit<ChainRun, "id" | "timestamp">): void {
  if (!db) return;
  db.insert(chainRunsTable).values({
    targetUrl:     String(run.targetUrl).slice(0, 500),
    injectParam:   String(run.injectParam).slice(0, 100),
    httpMethod:    String(run.httpMethod).slice(0, 20),
    cmd:           String(run.cmd).slice(0, 500),
    confirmed:     Boolean(run.confirmed),
    confirmedMode: run.confirmedMode ?? null,
    confirmedVia:  run.confirmedVia ?? null,
    exfilData:     String(run.exfilData ?? "").slice(0, 2000),
    elapsed:       Number(run.elapsed),
    modesRun:      Number(run.modesRun),
    totalModes:    Number(run.totalModes),
    oobToken:      String(run.oobToken).slice(0, 64),
  }).catch((err: unknown) => {
    logger.error({ err }, "chainLog: DB write failed");
  });
}

export async function getChainRuns(limit = 500): Promise<ChainRun[]> {
  if (!db) return [];
  try {
    const rows = await db
      .select()
      .from(chainRunsTable)
      .orderBy(desc(chainRunsTable.timestamp))
      .limit(limit);
    return rows.map(r => ({
      id:            r.id,
      timestamp:     r.timestamp.toISOString(),
      targetUrl:     r.targetUrl,
      injectParam:   r.injectParam,
      httpMethod:    r.httpMethod,
      cmd:           r.cmd,
      confirmed:     r.confirmed,
      confirmedMode: r.confirmedMode,
      confirmedVia:  r.confirmedVia,
      exfilData:     r.exfilData,
      elapsed:       r.elapsed,
      modesRun:      r.modesRun,
      totalModes:    r.totalModes,
      oobToken:      r.oobToken,
    }));
  } catch (err: unknown) {
    logger.error({ err }, "chainLog: DB read failed");
    return [];
  }
}

export async function clearChainRuns(): Promise<void> {
  if (!db) throw new Error("No database connection");
  try {
    await db.delete(chainRunsTable);
  } catch (err: unknown) {
    const msg = (err as Error).message ?? String(err);
    logger.error({ err }, "chainLog: DB clear failed");
    throw new Error(`chainLog clear failed: ${msg}`);
  }
}
