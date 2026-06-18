import { EventEmitter } from "events";
import { randomBytes } from "crypto";

export interface OobHit {
  id: string; ts: number; type: "http"; method: string; path: string;
  sourceIp: string; userAgent: string; headers: Record<string, string>;
  body: string; query: Record<string, string>; data: string;
  token: string; size: number;
  receivedAt?: string;
  decodedData?: string;
}

const MAX_HITS = 1000;
const hits: OobHit[] = [];
export const oobEvents = new EventEmitter();
oobEvents.setMaxListeners(500);

export function addHit(hit: OobHit): void {
  hits.unshift(hit);
  if (hits.length > MAX_HITS) hits.splice(MAX_HITS);
  oobEvents.emit("hit", hit);
}
export function getHits(limit = 500): OobHit[] { return hits.slice(0, limit); }
export function clearHits(): void { hits.splice(0); oobEvents.emit("cleared"); }
export function generateToken(): string { return randomBytes(8).toString("hex"); }

const ipCounts = new Map<string, { count: number; reset: number }>();
export function isRateLimited(ip: string): boolean {
  const now = Date.now();
  const e = ipCounts.get(ip);
  if (!e || now > e.reset) { ipCounts.set(ip, { count: 1, reset: now + 60_000 }); return false; }
  if (e.count >= 300) return true;
  e.count++;
  return false;
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, e] of ipCounts.entries()) if (now > e.reset) ipCounts.delete(ip);
}, 300_000);
