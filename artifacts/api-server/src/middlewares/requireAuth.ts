import { type Request, type Response, type NextFunction } from "express";
import { verifyToken } from "../lib/authToken.js";

/**
 * Express middleware — rejects requests that don't carry a valid Bearer token.
 * The token is issued by POST /api/auth/login and expires after 24 hours.
 */
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const auth  = req.headers["authorization"] ?? "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  if (!token || !verifyToken(token)) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  next();
}

/**
 * Verify a WebSocket upgrade token (passed as ?token= query param).
 */
export function verifyWsToken(rawToken: string): boolean {
  return verifyToken(rawToken.trim());
}
