import { existsSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";

const LOG_FILE = join(process.cwd(), "injection_logs.json");

if (!existsSync(LOG_FILE)) {
  writeFileSync(LOG_FILE, "[]");
}

export interface InjectionLogEntry {
  id: number;
  timestamp: string;
  command: string;
  engine: string;
  mode: string;
  responseTime: number;
}

export function logInjection(
  command: string,
  engine: string,
  mode: string,
  responseTime: number
): void {
  try {
    const raw = readFileSync(LOG_FILE, "utf8").trim() || "[]";
    const logs: InjectionLogEntry[] = JSON.parse(raw);
    logs.unshift({
      id: Date.now(),
      timestamp: new Date().toISOString(),
      command: String(command).slice(0, 300),
      engine,
      mode,
      responseTime,
    });
    writeFileSync(LOG_FILE, JSON.stringify(logs.slice(0, 1000), null, 2));
  } catch {
    try {
      writeFileSync(LOG_FILE, "[]");
    } catch {
      /* readonly fs */
    }
  }
}

export function readLogs(): InjectionLogEntry[] {
  try {
    if (!existsSync(LOG_FILE)) return [];
    const raw = readFileSync(LOG_FILE, "utf8").trim();
    if (!raw) return [];
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

export function clearLogs(): void {
  writeFileSync(LOG_FILE, "[]");
}
