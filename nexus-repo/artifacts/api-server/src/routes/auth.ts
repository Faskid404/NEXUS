import { Router, type Request, type Response } from "express";
import { createHmac, timingSafeEqual, randomBytes } from "crypto";

const router = Router();

/* ── Authentication credential ──────────────────────────────────────────── */
const AUTH_PASS = process.env["AUTH_PASS"] ?? "omowoli12345@*";

/* Session secret — random per process start; tokens invalidate on restart. */
const SESSION_SECRET  = process.env["SESSION_SECRET"] ?? randomBytes(32).toString("hex");
const TOKEN_TTL_MS    = 24 * 60 * 60 * 1_000;

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
  const { password } = req.body as { password?: string };
  if (!password || password !== AUTH_PASS) {
    res.status(401).json({ error: "Invalid credentials" });
    return;
  }
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
