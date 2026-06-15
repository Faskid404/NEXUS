/* ════════════════════════════════════════════════════════════════════
   tunnelUrl.ts — OOB callback URL management

   Priority order for the callback base URL:
     1. Runtime-set URL (setTunnelUrl() — ngrok, custom, etc.)
     2. RENDER_EXTERNAL_URL   env var  (Render.com deployment)
     3. NEXUS_TUNNEL_URL      env var  (manual override)
     4. REPLIT_DEV_DOMAIN     env var  (Replit dev preview)
     5. null → callers fall back to deriving from req.headers.host
   ════════════════════════════════════════════════════════════════════ */

import { logger } from "./logger.js";

let _tunnelUrl: string | null = null;

export function setTunnelUrl(url: string): void {
  const normalised = url.replace(/\/+$/, ""); // strip trailing slash
  _tunnelUrl = normalised;
  logger.info({ url: normalised }, "tunnelUrl: updated");
}

export function getTunnelUrl(): string | null {
  return _tunnelUrl;
}

/**
 * Called once at server boot — populate _tunnelUrl from well-known
 * environment variables if no runtime URL has been set yet.
 */
export function initTunnelUrl(): void {
  if (_tunnelUrl) return; // already set by caller (e.g. ngrok)

  const candidates = [
    process.env["NEXUS_TUNNEL_URL"],
    process.env["RENDER_EXTERNAL_URL"] && `${process.env["RENDER_EXTERNAL_URL"]}/api/oob/cb`,
    process.env["REPLIT_DEV_DOMAIN"]   && `https://${process.env["REPLIT_DEV_DOMAIN"]}/api/oob/cb`,
  ].filter(Boolean) as string[];

  if (candidates[0]) {
    setTunnelUrl(candidates[0]);
    logger.info({ url: candidates[0] }, "tunnelUrl: initialised from environment");
  } else {
    logger.info("tunnelUrl: no env URL found — will derive from request host");
  }
}

/**
 * Get the best available OOB callback base URL, falling back to
 * request-derived host when no tunnel URL is configured.
 */
export function getOobCbBase(req?: { headers: Record<string, string | string[] | undefined>; protocol?: string }): string {
  if (_tunnelUrl) return _tunnelUrl;

  if (req) {
    const host  = (req.headers["x-forwarded-host"] as string | undefined) || req.headers["host"] || "localhost";
    const proto = ((req.headers["x-forwarded-proto"] as string | undefined) || req.protocol || "https").split(",")[0]!.trim();
    return `${proto}://${host}/api/oob/cb`;
  }

  // Last resort
  const domain = process.env["RENDER_EXTERNAL_URL"] || process.env["REPLIT_DEV_DOMAIN"];
  if (domain) return `${domain.startsWith("http") ? domain : `https://${domain}`}/api/oob/cb`;
  return "http://localhost/api/oob/cb";
}
