import { createHmac, timingSafeEqual, randomBytes } from "crypto";
import { logger } from "./logger.js";

const raw = (process.env["SESSION_SECRET"] ?? "").trim();
if (!raw) {
  logger.warn("SESSION_SECRET is not set — tokens will invalidate on every server restart");
}
export const SESSION_SECRET = raw || randomBytes(32).toString("hex");
export const TOKEN_TTL_MS   = 24 * 60 * 60 * 1_000;

/* ── Token revocation blacklist ────────────────────────────────────── */
interface RevokedEntry { expiresAt: number; }
const revokedTokens = new Map<string, RevokedEntry>();

// Periodic cleanup of expired revocations (no need to keep them past their TTL)
setInterval(() => {
  const now = Date.now();
  for (const [tok, entry] of revokedTokens) {
    if (now > entry.expiresAt) revokedTokens.delete(tok);
  }
}, 30 * 60 * 1_000).unref();

export function revokeToken(token: string): void {
  try {
    const decoded   = Buffer.from(token, "base64url").toString("utf8");
    const lastColon = decoded.lastIndexOf(":");
    if (lastColon === -1) return;
    const payload   = decoded.slice(0, lastColon);
    const parts     = payload.split(":");
    const expiresAt = Number(parts[2]);
    if (Number.isNaN(expiresAt)) return;
    // Store a fingerprint (first 16 chars of token) to save memory
    revokedTokens.set(token.slice(0, 48), { expiresAt });
    logger.info({ tokenPrefix: token.slice(0, 8) }, "token revoked");
  } catch {
    // Ignore invalid tokens during revocation
  }
}

export function isTokenRevoked(token: string): boolean {
  return revokedTokens.has(token.slice(0, 48));
}

export function makeToken(): string {
  const issuedAt  = Date.now();
  const expiresAt = issuedAt + TOKEN_TTL_MS;
  const nonce     = randomBytes(8).toString("hex"); // anti-replay nonce
  const payload   = `authenticated:${issuedAt}:${expiresAt}:${nonce}`;
  const sig       = createHmac("sha256", SESSION_SECRET).update(payload).digest("hex");
  return Buffer.from(`${payload}:${sig}`).toString("base64url");
}

export function verifyToken(token: string): boolean {
  try {
    // Check revocation list first (fast path)
    if (isTokenRevoked(token)) return false;

    const decoded   = Buffer.from(token, "base64url").toString("utf8");
    const lastColon = decoded.lastIndexOf(":");
    if (lastColon === -1) return false;
    const payload  = decoded.slice(0, lastColon);
    const sig      = decoded.slice(lastColon + 1);
    const expected = createHmac("sha256", SESSION_SECRET).update(payload).digest("hex");
    if (sig.length !== expected.length) return false;
    if (!/^[0-9a-f]+$/i.test(sig)) return false;
    const valid = timingSafeEqual(
      Buffer.from(sig, "hex"),
      Buffer.from(expected, "hex"),
    );
    if (!valid) return false;
    const parts     = payload.split(":");
    // Support both old format (3 parts) and new format (4 parts with nonce)
    const expiresAt = Number(parts[2]);
    if (Number.isNaN(expiresAt) || Date.now() > expiresAt) return false;
    return true;
  } catch {
    return false;
  }
}

/** Token metadata for diagnostics (non-sensitive). */
export function getTokenInfo(token: string): { issuedAt: number; expiresAt: number; valid: boolean } | null {
  try {
    const decoded   = Buffer.from(token, "base64url").toString("utf8");
    const lastColon = decoded.lastIndexOf(":");
    if (lastColon === -1) return null;
    const payload   = decoded.slice(0, lastColon);
    const parts     = payload.split(":");
    return {
      issuedAt:  Number(parts[1]),
      expiresAt: Number(parts[2]),
      valid:     verifyToken(token),
    };
  } catch {
    return null;
  }
}
