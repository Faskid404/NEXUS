import { Router, type Request, type Response } from "express";
import { makeToken, verifyToken } from "../lib/authToken.js";

const router = Router();

/**
 * The password is validated as: must start with the prefix and be at least
 * as long as the prefix (i.e., the exact prefix is also a valid password).
 *
 * FIX: was `key.length > ALLOWED_PREFIX.length` which rejected the exact
 * password "omowoli12345@" because 13 > 13 is false.
 */
const ALLOWED_PREFIX = "omowoli12345@";

function isAllowedKey(key: string): boolean {
  return (
    typeof key === "string" &&
    key.startsWith(ALLOWED_PREFIX) &&
    key.length >= ALLOWED_PREFIX.length
  );
}

const RATE_WINDOW_MS = 15 * 60 * 1_000;
const MAX_FAILURES   = 5;

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

setInterval(() => {
  const cutoff = Date.now() - RATE_WINDOW_MS;
  for (const [ip, entry] of failMap) {
    if (entry.windowStart < cutoff) failMap.delete(ip);
  }
}, 30 * 60 * 1_000).unref();

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
  const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  if (!token || !verifyToken(token)) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  res.json({ ok: true });
});

export default router;
