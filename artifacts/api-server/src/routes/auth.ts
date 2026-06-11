import { Router, type Request, type Response } from "express";
import { createHmac, timingSafeEqual, randomBytes } from "crypto";

const router = Router();

/* ── Access key pattern ──────────────────────────────────────────────────── */
const ALLOWED_PREFIX = "omowoli12345@";

function isAllowedKey(key: string): boolean {
  return (
    typeof key === "string" &&
    key.startsWith(ALLOWED_PREFIX) &&
    key.length > ALLOWED_PREFIX.length
  );
}

/* Session secret — random per process start; tokens invalidate on restart. */
const SESSION_SECRET = process.env["SESSION_SECRET"] ?? randomBytes(32).toString("hex");
const TOKEN_TTL_MS   = 24 * 60 * 60 * 1_000;

/* ── Rate limiter ─────────────────────────────────────────────────────────
 * Tracks failed login attempts per source IP.
 * Limit: 5 failures per 15-minute window. Successful logins reset the counter.
 * ──────────────────────────────────────────────────────────────────────── */
const RATE_WINDOW_MS  = 15 * 60 * 1_000;
const MAX_FAILURES    = 5;

interface RateEntry { count: number; windowStart: number; }
const failMap = new Map<string, RateEntry>();

function getClientIp(req: Request): string {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string") return forwarded.split(",")[0]!.trim();
  return req.socket.remoteAddress ?? "unknown";
}

function isRateLimited(ip: string): boolean {
  const now   = Date.now();
  const entry = failMap.get(ip);
  if (!entry || now - entry.windowStart >= RATE_WINDOW_MS) return false;
  return entry.count >= MAX_FAILURES;
}

function recordFailure(ip: string): void {
  const now   = Date.now();
  const entry = failMap.get(ip);
  if (!entry || now - entry.windowStart >= RATE_WINDOW_MS) {
    failMap.set(ip, { count: 1, windowStart: now });
  } else {
    entry.count += 1;
  }
}

function clearFailures(ip: string): void {
  failMap.delete(ip);
}

/* Periodic cleanup — evict stale windows every 30 minutes. */
setInterval(() => {
  const cutoff = Date.now() - RATE_WINDOW_MS;
  for (const [ip, entry] of failMap) {
    if (entry.windowStart < cutoff) failMap.delete(ip);
  }
}, 30 * 60 * 1_000).unref();

/* ── Token helpers ───────────────────────────────────────────────────────── */
function makeToken(): string {
  const issuedAt  = Date.now();
  const expiresAt = issuedAt + TOKEN_TTL_MS;
  const payload   = `authenticated:${issuedAt}:${expiresAt}`;
  const sig       = createHmac("sha256", SESSION_SECRET).update(payload).digest("hex");
  return Buffer.from(`${payload}:${sig}`).toString("base64url");
}

function verifyToken(token: string): boolean {
  try {
    const decoded   = Buffer.from(token, "base64url").toString("utf8");
    const lastColon = decoded.lastIndexOf(":");
    if (lastColon === -1) return false;
    const payload  = decoded.slice(0, lastColon);
    const sig      = decoded.slice(lastColon + 1);
    const expected = createHmac("sha256", SESSION_SECRET).update(payload).digest("hex");
    if (sig.length !== expected.length) return false;
    if (!/^[0-9a-f]+$/i.test(sig)) return false;
    const valid = timingSafeEqual(Buffer.from(sig, "hex"), Buffer.from(expected, "hex"));
    if (!valid) return false;
    const expiresAt = Number(payload.split(":")[2]);
    if (Number.isNaN(expiresAt) || Date.now() > expiresAt) return false;
    return true;
  } catch {
    return false;
  }
}

/* ── Routes ─────────────────────────────────────────────────────────────── */
router.post("/auth/login", (req: Request, res: Response) => {
  const ip = getClientIp(req);

  if (isRateLimited(ip)) {
    res.status(429).json({ error: "Too many failed attempts — try again in 15 minutes" });
    return;
  }

  const { password } = req.body as { password?: string };
  if (!password || !isAllowedKey(password)) {
    recordFailure(ip);
    res.status(401).json({ error: "Access denied — invalid credentials" });
    return;
  }

  clearFailures(ip);
  res.json({ token: makeToken() });
});

router.get("/auth/verify", (req: Request, res: Response) => {
  const auth  = req.headers["authorization"] ?? "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token || !verifyToken(token)) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  res.json({ ok: true });
});

export default router;
