import { createServer } from "http";
import { WebSocketServer } from "ws";
import app from "./app.js";
import { logger } from "./lib/logger.js";
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
  if      (req.url === "/api/ws/exec")  wss.handleUpgrade(req, socket as import("stream").Duplex, head, handleStreamExec);
  else if (req.url === "/api/ws/scan")  wss.handleUpgrade(req, socket as import("stream").Duplex, head, handleScanTarget);
  else if (req.url === "/api/ws/chain") wss.handleUpgrade(req, socket as import("stream").Duplex, head, handleExploitChain);
  else if (req.url === "/api/ws/probe")       wss.handleUpgrade(req, socket as import("stream").Duplex, head, handleProbeTarget);
  else if (req.url === "/api/ws/autoexploit")  wss.handleUpgrade(req, socket as import("stream").Duplex, head, handleAutoExploit);
  else if (req.url === "/api/ws/postexploit")  wss.handleUpgrade(req, socket as import("stream").Duplex, head, handlePostExploit);
  else if (req.url === "/api/ws/cve")          wss.handleUpgrade(req, socket as import("stream").Duplex, head, handleCveExploit);
  else socket.destroy();
});

server.listen(port, () => { logger.info({ port }, "Server listening"); });
server.on("error", (err) => { logger.error({ err }, "Server error"); process.exit(1); });
