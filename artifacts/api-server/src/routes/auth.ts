import { Router, type Request, type Response } from "express";
import { makeToken, verifyToken, revokeToken, getTokenInfo } from "../lib/authToken.js";
import { logger } from "../lib/logger.js";

const router = Router();

/* ── Password config ───────────────────────────────────────────────── */
const ALLOWED_PREFIX = "omowoli12345@";

function isAllowedKey(key: string): boolean {
  return (
    typeof key === "string" &&
    key.startsWith(ALLOWED_PREFIX) &&
    key.length >= ALLOWED_PREFIX.length
  );
}

/* ── IP allowlist (optional env var, comma-separated) ─────────────── */
const ADMIN_IPS = new Set(
  (process.env["NEXUS_ADMIN_IPS"] ?? "")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean)
);

function getClientIp(req: Request): string {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string") return forwarded.split(",")[0]!.trim();
  return req.socket.remoteAddress ?? "unknown";
}

/* ── Exponential-backoff rate limiter ──────────────────────────────── */
const RATE_WINDOW_MS = 15 * 60 * 1_000;   // 15-minute base window
const BACKOFF_TIERS  = [5, 10, 20] as const; // failures before each tier
const BACKOFF_BANS   = [                   // ban durations per tier
  1  * 60 * 1_000,  // tier 1:  1 min
  5  * 60 * 1_000,  // tier 2:  5 min
  60 * 60 * 1_000,  // tier 3: 60 min
] as const;

interface RateEntry {
  count:       number;
  windowStart: number;
  bannedUntil: number;
}
const failMap = new Map<string, RateEntry>();

function isRateLimited(ip: string): { limited: boolean; retryAfterMs: number } {
  const now   = Date.now();
  const entry = failMap.get(ip);
  if (!entry) return { limited: false, retryAfterMs: 0 };

  // Check active ban
  if (entry.bannedUntil > now) {
    return { limited: true, retryAfterMs: entry.bannedUntil - now };
  }
  // Reset window if expired
  if (now - entry.windowStart >= RATE_WINDOW_MS) return { limited: false, retryAfterMs: 0 };
  // Check failure tier — use highest threshold exceeded
  if (entry.count >= BACKOFF_TIERS[2]) return { limited: true, retryAfterMs: BACKOFF_BANS[2] };
  if (entry.count >= BACKOFF_TIERS[1]) return { limited: true, retryAfterMs: BACKOFF_BANS[1] };
  if (entry.count >= BACKOFF_TIERS[0]) return { limited: true, retryAfterMs: BACKOFF_BANS[0] };
  return { limited: false, retryAfterMs: 0 };
}

function recordFailure(ip: string): void {
  const now   = Date.now();
  const entry = failMap.get(ip);
  if (!entry || now - entry.windowStart >= RATE_WINDOW_MS) {
    failMap.set(ip, { count: 1, windowStart: now, bannedUntil: 0 });
    return;
  }
  entry.count += 1;
  // Apply exponential backoff ban when thresholds are hit
  if (entry.count === BACKOFF_TIERS[2]) entry.bannedUntil = now + BACKOFF_BANS[2];
  else if (entry.count === BACKOFF_TIERS[1]) entry.bannedUntil = now + BACKOFF_BANS[1];
  else if (entry.count === BACKOFF_TIERS[0]) entry.bannedUntil = now + BACKOFF_BANS[0];
}

function clearFailures(ip: string): void {
  failMap.delete(ip);
}

// Periodic cleanup
setInterval(() => {
  const cutoff = Date.now() - RATE_WINDOW_MS;
  for (const [ip, entry] of failMap) {
    if (entry.windowStart < cutoff && entry.bannedUntil < Date.now()) failMap.delete(ip);
  }
}, 30 * 60 * 1_000).unref();

/* ── POST /auth/login ──────────────────────────────────────────────── */
router.post("/auth/login", (req: Request, res: Response) => {
  const ip = getClientIp(req);

  // IP allowlist check (if configured)
  if (ADMIN_IPS.size > 0 && !ADMIN_IPS.has(ip)) {
    logger.warn({ ip }, "auth/login: IP not in allowlist");
    res.status(403).json({ error: "Access denied" });
    return;
  }

  const { limited, retryAfterMs } = isRateLimited(ip);
  if (limited) {
    const retryAfterSec = Math.ceil(retryAfterMs / 1_000);
    res.setHeader("Retry-After", String(retryAfterSec));
    res.status(429).json({
      error: "Too many failed attempts",
      retryAfterSeconds: retryAfterSec,
    });
    return;
  }

  const { password } = req.body as { password?: string };
  if (!password || !isAllowedKey(password)) {
    recordFailure(ip);
    const entry = failMap.get(ip);
    logger.warn({ ip, attempts: entry?.count ?? 1 }, "auth/login: invalid credentials");
    res.status(401).json({ error: "Access denied — invalid credentials" });
    return;
  }

  clearFailures(ip);
  const token = makeToken();
  logger.info({ ip }, "auth/login: success");
  res.json({ token });
});

/* ── GET /auth/verify ──────────────────────────────────────────────── */
router.get("/auth/verify", (req: Request, res: Response) => {
  const auth  = req.headers["authorization"] ?? "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  if (!token || !verifyToken(token)) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  const info = getTokenInfo(token);
  res.json({ ok: true, expiresAt: info?.expiresAt, issuedAt: info?.issuedAt });
});

/* ── POST /auth/logout ─────────────────────────────────────────────── */
router.post("/auth/logout", (req: Request, res: Response) => {
  const auth  = req.headers["authorization"] ?? "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  if (!token) {
    res.status(400).json({ error: "No token provided" });
    return;
  }
  if (!verifyToken(token)) {
    // Token already expired/invalid — treat as success
    res.json({ ok: true, message: "Token was already invalid" });
    return;
  }
  revokeToken(token);
  const ip = getClientIp(req);
  logger.info({ ip }, "auth/logout: token revoked");
  res.json({ ok: true, message: "Logged out — token revoked" });
});

/* ── GET /auth/status ──────────────────────────────────────────────── */
router.get("/auth/status", (_req: Request, res: Response) => {
  res.json({
    rateLimitWindow: `${RATE_WINDOW_MS / 60_000}m`,
    backoffTiers: BACKOFF_TIERS.map((t, i) => ({
      failuresNeeded: t,
      banDuration:    `${BACKOFF_BANS[i]! / 60_000}m`,
    })),
    blockedIps: failMap.size,
  });
});

export default router;
