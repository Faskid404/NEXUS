import { createHmac, timingSafeEqual, randomBytes } from "crypto";
import { logger } from "./logger.js";

const raw = (process.env["SESSION_SECRET"] ?? "").trim();
if (!raw) {
  logger.warn("SESSION_SECRET is not set — tokens will invalidate on every server restart");
}
export const SESSION_SECRET = raw || randomBytes(32).toString("hex");
export const TOKEN_TTL_MS   = 24 * 60 * 60 * 1_000;

export function makeToken(): string {
  const issuedAt  = Date.now();
  const expiresAt = issuedAt + TOKEN_TTL_MS;
  const payload   = `authenticated:${issuedAt}:${expiresAt}`;
  const sig       = createHmac("sha256", SESSION_SECRET).update(payload).digest("hex");
  return Buffer.from(`${payload}:${sig}`).toString("base64url");
}

export function verifyToken(token: string): boolean {
  try {
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
    const expiresAt = Number(parts[2]);
    if (Number.isNaN(expiresAt) || Date.now() > expiresAt) return false;
    return true;
  } catch {
    return false;
  }
}
