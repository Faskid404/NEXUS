import { EventEmitter } from "events";

export interface DnsSession {
  key:          string;
  token:        string;
  prefix:       string;
  chunks:       Record<number, string>;
  total:        number;
  received:     number;
  complete:     boolean;
  assembled:    string | null;
  decoded:      string | null;
  byteLen:      number;
  receivedAt:   number;
  lastChunkAt:  number;
  completedAt:  number | null;
}

export const dnsEvents = new EventEmitter();
dnsEvents.setMaxListeners(500);

const MAX_SESSIONS = 200;
const TTL_MS       = 30 * 60 * 1000;
const sessions     = new Map<string, DnsSession>();

export function addChunk(
  token:  string,
  prefix: string,
  idx:    number,
  total:  number,
  chunk:  string,
): DnsSession {
  const key = `${token}:${prefix}`;
  let s = sessions.get(key);

  if (!s) {
    s = {
      key, token, prefix,
      chunks:      {},
      total,
      received:    0,
      complete:    false,
      assembled:   null,
      decoded:     null,
      byteLen:     0,
      receivedAt:  Date.now(),
      lastChunkAt: Date.now(),
      completedAt: null,
    };
    sessions.set(key, s);

    if (sessions.size > MAX_SESSIONS) {
      let oldKey: string | undefined;
      let oldTs = Infinity;
      for (const [k, v] of sessions) {
        if (v.receivedAt < oldTs) { oldTs = v.receivedAt; oldKey = k; }
      }
      if (oldKey) sessions.delete(oldKey);
    }
  }

  if (total > s.total) s.total = total;

  if (!(idx in s.chunks)) {
    s.chunks[idx] = chunk;
    s.received++;
  }
  s.lastChunkAt = Date.now();

  dnsEvents.emit("chunk", { key, token, prefix, idx, received: s.received, total: s.total });

  if (!s.complete && s.received >= s.total) {
    const sorted = Object.entries(s.chunks)
      .sort((a, b) => Number(a[0]) - Number(b[0]))
      .map(([, c]) => c
        .replace(/-/g, "+")
        .replace(/_/g, "/")
        .replace(/~/g, "="),
      );

    const rawB64 = sorted.join("");
    const padding = (4 - (rawB64.length % 4)) % 4;
    const b64 = rawB64 + "=".repeat(padding);

    s.assembled  = b64;
    s.byteLen    = Math.floor(b64.length * 3 / 4);
    s.complete   = true;
    s.completedAt = Date.now();

    try {
      const buf = Buffer.from(b64, "base64");
      const txt = buf.toString("utf8");
      const printable = [...txt].filter(c => {
        const code = c.charCodeAt(0);
        return code === 9 || code === 10 || code === 13 || (code >= 32 && code <= 126);
      }).length;
      s.decoded = printable / Math.max(txt.length, 1) > 0.80 ? txt : null;
    } catch {
      s.decoded = null;
    }

    dnsEvents.emit("complete", s);
  }

  return s;
}

export function getSessions(): DnsSession[] {
  return [...sessions.values()].sort((a, b) => b.lastChunkAt - a.lastChunkAt);
}

export function getSession(key: string): DnsSession | undefined {
  return sessions.get(key);
}

export function clearSessions(): void {
  sessions.clear();
  dnsEvents.emit("cleared");
}

setInterval(() => {
  const cutoff = Date.now() - TTL_MS;
  for (const [key, s] of sessions) {
    if (s.lastChunkAt < cutoff) sessions.delete(key);
  }
}, 5 * 60 * 1000);
