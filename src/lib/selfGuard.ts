// SelfGuard — prevents NEXUS from targeting its own deployment instance
// Applied in IronWorm scan, SSH brute, remote injection, and C2 targeting.

export interface SelfGuardResult {
  isSelf:  boolean;
  reason:  string;
}

const LOOPBACK = new Set([
  "localhost", "127.0.0.1", "::1", "0.0.0.0",
  "0:0:0:0:0:0:0:1", "::ffff:127.0.0.1",
]);

const SELF_CLOUD_PATTERNS = [
  /\.replit\.app$/i,
  /\.repl\.co$/i,
  /\.replit\.dev$/i,
  /\.onrender\.com$/i,
  /\.fly\.dev$/i,
  /\.railway\.app$/i,
];

function stripPort(host: string): string {
  return host.replace(/:\d+$/, "");
}

function normalize(raw: string): string {
  return raw
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//i, "")
    .split("/")[0] ?? "";
}

/** Check a single target string — returns {isSelf, reason} */
export function checkSelf(target: string): SelfGuardResult {
  const t = normalize(target);
  if (!t) return { isSelf: false, reason: "" };

  const tHost = stripPort(t);

  // Loopback
  if (LOOPBACK.has(tHost) || /^127\./.test(tHost)) {
    return { isSelf: true, reason: `Loopback address detected: ${tHost}` };
  }

  // Current page hostname
  const ownHost = stripPort(window.location.hostname.toLowerCase());
  if (tHost === ownHost) {
    return { isSelf: true, reason: `Matches deployment host: ${ownHost}` };
  }

  // Cloud platform domains — block same-platform instances
  for (const pat of SELF_CLOUD_PATTERNS) {
    if (pat.test(tHost) && pat.test(ownHost) && tHost === ownHost) {
      return { isSelf: true, reason: `Same cloud deployment: ${tHost}` };
    }
  }

  // Private RFC-1918 ranges that match the browser's own origin (can't reliably
  // detect without WebRTC, so we flag them as a warning but don't hard-block)
  return { isSelf: false, reason: "" };
}

/** Batch-filter a list of targets — returns safe list and blocked list */
export function filterTargets(targets: string[]): {
  safe:    string[];
  blocked: { target: string; reason: string }[];
} {
  const safe:    string[] = [];
  const blocked: { target: string; reason: string }[] = [];

  for (const t of targets) {
    const r = checkSelf(t);
    if (r.isSelf) blocked.push({ target: t, reason: r.reason });
    else safe.push(t);
  }
  return { safe, blocked };
}

/** UI helper — returns a red warning string if self, else null */
export function selfWarning(target: string): string | null {
  const r = checkSelf(target);
  return r.isSelf ? `⚠ SELF-TARGET: ${r.reason}` : null;
}
