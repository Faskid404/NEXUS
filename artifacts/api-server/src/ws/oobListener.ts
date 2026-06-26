import type { WebSocket } from "ws";
import {
  getHits, clearHits, oobEvents,
  type OobHit,
} from "../oob/oobStore.js";
import {
  getSessions, clearSessions, dnsEvents,
  type DnsSession,
} from "../oob/dnsReassembler.js";
import { createLogger } from "../lib/logger.js";

const log = createLogger("ws:oob");

/* ── Wire protocol (server → client) ───────────────────────────────────── */
type ServerMsg =
  | { type: "snapshot";    hits: OobHit[];      sessions: DnsSession[] }
  | { type: "hit";         hit: OobHit }
  | { type: "dns_session"; session: DnsSession }
  | { type: "dns_chunk";   key: string; token: string; prefix: string;
                           idx: number; received: number; total: number }
  | { type: "dns_complete"; session: DnsSession }
  | { type: "cleared" }
  | { type: "dns_cleared" };

/* ── Wire protocol (client → server) ───────────────────────────────────── */
type ClientCmd =
  | { action: "clear_hits" }
  | { action: "clear_dns" };

function send(ws: WebSocket, msg: ServerMsg): void {
  if (ws.readyState !== 1) return;
  try { ws.send(JSON.stringify(msg)); } catch { /* closing mid-send */ }
}

export function handleOobListener(ws: WebSocket): void {
  log.info("oob listener connected");

  /* ── Snapshot of current state on connect ─────────────────── */
  send(ws, {
    type:     "snapshot",
    hits:     getHits(500),
    sessions: getSessions(),
  });

  /* ── Forward new HTTP hits ────────────────────────────────── */
  const onHit = (hit: OobHit) => send(ws, { type: "hit", hit });

  /* ── Forward DNS events ───────────────────────────────────── */
  const onDnsChunk = (ev: { key: string; token: string; prefix: string; idx: number; received: number; total: number }) => {
    /* First chunk for a session = send full session object so client can initialise */
    if (ev.received === 1) {
      const sessions = getSessions();
      const session  = sessions.find(s => s.key === ev.key);
      if (session) {
        send(ws, { type: "dns_session", session });
        return;
      }
    }
    send(ws, { type: "dns_chunk", ...ev });
  };

  const onDnsComplete = (session: DnsSession) =>
    send(ws, { type: "dns_complete", session });

  const onCleared    = () => send(ws, { type: "cleared" });
  const onDnsCleared = () => send(ws, { type: "dns_cleared" });

  oobEvents.on("hit",     onHit);
  oobEvents.on("cleared", onCleared);
  dnsEvents.on("chunk",   onDnsChunk);
  dnsEvents.on("complete", onDnsComplete);
  dnsEvents.on("cleared", onDnsCleared);

  /* ── Commands from the client ─────────────────────────────── */
  ws.on("message", (raw) => {
    let cmd: ClientCmd;
    try { cmd = JSON.parse(raw.toString()) as ClientCmd; } catch { return; }
    switch (cmd.action) {
      case "clear_hits":
        clearHits();      // emits "cleared" → picked up by onCleared above
        break;
      case "clear_dns":
        clearSessions();  // emits "cleared" → picked up by onDnsCleared above
        break;
    }
  });

  /* ── Cleanup on disconnect ────────────────────────────────── */
  ws.once("close", () => {
    log.info("oob listener disconnected");
    oobEvents.off("hit",     onHit);
    oobEvents.off("cleared", onCleared);
    dnsEvents.off("chunk",   onDnsChunk);
    dnsEvents.off("complete", onDnsComplete);
    dnsEvents.off("cleared", onDnsCleared);
  });
}
