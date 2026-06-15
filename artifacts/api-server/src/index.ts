import { createServer } from "http";
import { WebSocketServer } from "ws";
import app from "./app.js";
import { logger } from "./lib/logger.js";
import { setTunnelUrl, initTunnelUrl } from "./lib/tunnelUrl.js";
import { verifyWsToken } from "./middlewares/requireAuth.js";
import { handleStreamExec }      from "./ws/streamExec.js";
import { handleScanTarget }      from "./ws/scanTarget.js";
import { handleExploitChain }    from "./ws/exploitChain.js";
import { handleProbeTarget }     from "./ws/probeTarget.js";
import { handleCveExploit }      from "./ws/cveExploit.js";
import { handleAutoExploit }     from "./ws/autoExploit.js";
import { handlePostExploit }     from "./ws/postExploit.js";
import { handleMutationScanner } from "./ws/mutationScanner.js";
import { handleChainReactor }    from "./ws/chainReactor.js";

const rawPort = process.env["PORT"];
if (!rawPort) throw new Error("PORT environment variable is required but was not provided.");
const port = Number(rawPort);
if (Number.isNaN(port) || port <= 0) throw new Error(`Invalid PORT value: "${rawPort}"`);

/* ── Server bootstrap ──────────────────────────────────────────────── */
const server = createServer(app);
const wss    = new WebSocketServer({ noServer: true });

const PING_INTERVAL_MS  = 15_000; // Faster heartbeat (15s instead of 25s)
const MAX_WS_CONNS      = Number(process.env["MAX_WS_CONNECTIONS"] ?? 100);
let   activeWsConns     = 0;

function attachHeartbeat(ws: import("ws").WebSocket): void {
  let alive = true;

  const interval = setInterval(() => {
    if (!alive) {
      ws.terminate();
      return;
    }
    alive = false;
    try { ws.ping(); } catch { /* ignore if already closing */ }
  }, PING_INTERVAL_MS);

  ws.on("pong",  () => { alive = true; });
  ws.on("close", () => {
    clearInterval(interval);
    activeWsConns = Math.max(0, activeWsConns - 1);
  });
  ws.on("error", (err) => { logger.warn({ err }, "ws client error"); });
}

/* ── WebSocket upgrade handler ─────────────────────────────────────── */
server.on("upgrade", (req, socket, head) => {
  /* — Connection limit ————————————————————————————————————— */
  if (activeWsConns >= MAX_WS_CONNS) {
    socket.write("HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n");
    socket.destroy();
    logger.warn({ activeWsConns, MAX_WS_CONNS }, "ws upgrade rejected — connection limit reached");
    return;
  }

  /* — Auth check: require ?token=<bearer-token> ——————————— */
  let pathname = "/";
  let wsToken  = "";
  try {
    const url = new URL(req.url ?? "/", "http://localhost");
    pathname  = url.pathname;
    wsToken   = url.searchParams.get("token") ?? "";
  } catch {
    pathname = req.url?.split("?")[0] ?? "/";
  }

  if (!verifyWsToken(wsToken)) {
    socket.write("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nWWW-Authenticate: Bearer\r\n\r\n");
    socket.destroy();
    logger.warn({ pathname }, "ws upgrade rejected — invalid/missing token");
    return;
  }

  /* — Route to the appropriate handler ———————————————————— */
  const wrap = (handler: (ws: import("ws").WebSocket) => void) =>
    (ws: import("ws").WebSocket) => {
      activeWsConns++;
      attachHeartbeat(ws);
      handler(ws);
    };

  const routes: Record<string, (ws: import("ws").WebSocket) => void> = {
    "/api/ws/exec":        wrap(handleStreamExec),
    "/api/ws/scan":        wrap(handleScanTarget),
    "/api/ws/chain":       wrap(handleExploitChain),
    "/api/ws/probe":       wrap(handleProbeTarget),
    "/api/ws/autoexploit": wrap(handleAutoExploit),
    "/api/ws/postexploit": wrap(handlePostExploit),
    "/api/ws/cve":         wrap(handleCveExploit),
    "/api/ws/mutation":    wrap(handleMutationScanner),
    "/api/ws/chainreactor":wrap(handleChainReactor),
  };

  const handler = routes[pathname];
  if (handler) {
    wss.handleUpgrade(req, socket as import("stream").Duplex, head, handler);
  } else {
    socket.write("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
    socket.destroy();
  }
});

/* ── Start server ──────────────────────────────────────────────────── */
server.listen(port, () => {
  logger.info({ port, maxWsConns: MAX_WS_CONNS }, "Server listening");

  // Auto-initialise tunnel URL from environment (e.g. RENDER_EXTERNAL_URL)
  initTunnelUrl();

  const ngrokToken = process.env["NGROK_AUTH_TOKEN"];
  if (ngrokToken) {
    import("@ngrok/ngrok").then(({ default: ngrok }) => {
      ngrok.connect({ authtoken: ngrokToken, addr: port, proto: "http" })
        .then(listener => {
          const url = listener.url();
          if (url) {
            setTunnelUrl(`${url}/api/oob/cb`);
            logger.info({ url }, "ngrok tunnel active — OOB callbacks will use this URL");
          }
        })
        .catch(err => logger.warn({ err }, "ngrok tunnel failed — OOB callbacks will use Replit domain"));
    }).catch(err => logger.warn({ err }, "ngrok module not available"));
  }
});

server.on("error", (err) => { logger.error({ err }, "Server error"); process.exit(1); });
wss.on("error",    (err) => { logger.error({ err }, "WSS error"); });

/* ── Graceful shutdown ─────────────────────────────────────────────── */
function gracefulShutdown(signal: string): void {
  logger.info({ signal, activeWsConns }, "Graceful shutdown initiated");

  // Stop accepting new HTTP connections
  server.close((err) => {
    if (err) logger.error({ err }, "Error closing HTTP server");
    else     logger.info("HTTP server closed cleanly");

    // Close all WS connections
    wss.clients.forEach(ws => {
      try { ws.close(1001, "Server shutting down"); } catch { /* ignore */ }
    });
    wss.close(() => logger.info("WSS closed cleanly"));

    process.exit(err ? 1 : 0);
  });

  // Force-kill after 15 seconds if graceful close hangs
  setTimeout(() => {
    logger.error("Graceful shutdown timed out — forcing exit");
    process.exit(1);
  }, 15_000).unref();
}

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT",  () => gracefulShutdown("SIGINT"));

process.on("uncaughtException",  (err) => { logger.error({ err }, "Uncaught exception");  });
process.on("unhandledRejection", (err) => { logger.error({ err }, "Unhandled rejection"); });
