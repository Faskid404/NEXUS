import { createServer } from "http";
import { WebSocketServer } from "ws";
import app from "./app.js";
import { logger } from "./lib/logger.js";
import { setTunnelUrl } from "./lib/tunnelUrl.js";
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

const server = createServer(app);
const wss    = new WebSocketServer({ noServer: true });

const PING_INTERVAL_MS = 25_000;

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
  ws.on("close", () => clearInterval(interval));
  ws.on("error", (err) => { logger.warn({ err }, "ws client error"); });
}

server.on("upgrade", (req, socket, head) => {
  const pathname = (() => {
    try { return new URL(req.url ?? "/", "http://localhost").pathname; }
    catch { return req.url?.split("?")[0] ?? "/"; }
  })();

  const wrap = (handler: (ws: import("ws").WebSocket) => void) =>
    (ws: import("ws").WebSocket) => { attachHeartbeat(ws); handler(ws); };

  if      (pathname === "/api/ws/exec")        wss.handleUpgrade(req, socket as import("stream").Duplex, head, wrap(handleStreamExec));
  else if (pathname === "/api/ws/scan")        wss.handleUpgrade(req, socket as import("stream").Duplex, head, wrap(handleScanTarget));
  else if (pathname === "/api/ws/chain")       wss.handleUpgrade(req, socket as import("stream").Duplex, head, wrap(handleExploitChain));
  else if (pathname === "/api/ws/probe")       wss.handleUpgrade(req, socket as import("stream").Duplex, head, wrap(handleProbeTarget));
  else if (pathname === "/api/ws/autoexploit") wss.handleUpgrade(req, socket as import("stream").Duplex, head, wrap(handleAutoExploit));
  else if (pathname === "/api/ws/postexploit") wss.handleUpgrade(req, socket as import("stream").Duplex, head, wrap(handlePostExploit));
  else if (pathname === "/api/ws/cve")         wss.handleUpgrade(req, socket as import("stream").Duplex, head, wrap(handleCveExploit));
  else if (pathname === "/api/ws/mutation")      wss.handleUpgrade(req, socket as import("stream").Duplex, head, wrap(handleMutationScanner));
  else if (pathname === "/api/ws/chainreactor")  wss.handleUpgrade(req, socket as import("stream").Duplex, head, wrap(handleChainReactor));
  else {
    socket.write("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
    socket.destroy();
  }
});

server.listen(port, () => {
  logger.info({ port }, "Server listening");
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
