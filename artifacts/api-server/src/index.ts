import { createServer } from "http";
import { WebSocketServer } from "ws";
import app from "./app.js";
import { logger } from "./lib/logger.js";
import { setTunnelUrl } from "./lib/tunnelUrl.js";
import { handleStreamExec }   from "./ws/streamExec.js";
import { handleScanTarget }   from "./ws/scanTarget.js";
import { handleExploitChain } from "./ws/exploitChain.js";
import { handleProbeTarget }  from "./ws/probeTarget.js";
import { handleCveExploit } from "./ws/cveExploit.js";
import { handleAutoExploit }  from "./ws/autoExploit.js";
import { handlePostExploit }  from "./ws/postExploit.js";

const rawPort = process.env["PORT"];
if (!rawPort) throw new Error("PORT environment variable is required but was not provided.");
const port = Number(rawPort);
if (Number.isNaN(port) || port <= 0) throw new Error(`Invalid PORT value: "${rawPort}"`);

const server = createServer(app);
const wss    = new WebSocketServer({ noServer: true });

server.on("upgrade", (req, socket, head) => {
  const pathname = (() => {
    try { return new URL(req.url ?? "/", "http://localhost").pathname; }
    catch { return req.url?.split("?")[0] ?? "/"; }
  })();

  if      (pathname === "/api/ws/exec")        wss.handleUpgrade(req, socket as import("stream").Duplex, head, handleStreamExec);
  else if (pathname === "/api/ws/scan")        wss.handleUpgrade(req, socket as import("stream").Duplex, head, handleScanTarget);
  else if (pathname === "/api/ws/chain")       wss.handleUpgrade(req, socket as import("stream").Duplex, head, handleExploitChain);
  else if (pathname === "/api/ws/probe")       wss.handleUpgrade(req, socket as import("stream").Duplex, head, handleProbeTarget);
  else if (pathname === "/api/ws/autoexploit") wss.handleUpgrade(req, socket as import("stream").Duplex, head, handleAutoExploit);
  else if (pathname === "/api/ws/postexploit") wss.handleUpgrade(req, socket as import("stream").Duplex, head, handlePostExploit);
  else if (pathname === "/api/ws/cve")         wss.handleUpgrade(req, socket as import("stream").Duplex, head, handleCveExploit);
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
