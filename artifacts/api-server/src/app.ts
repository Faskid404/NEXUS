import express, { type Express, type Request, type Response, type NextFunction } from "express";
import cors from "cors";
import pinoHttp from "pino-http";
import path from "path";
import { existsSync } from "fs";
import { fileURLToPath } from "url";
import { randomBytes } from "crypto";
import router from "./routes/index.js";
import { logger } from "./lib/logger.js";

const app: Express = express();

/* ── Request ID injection ──────────────────────────────────────────── */
app.use((req: Request, res: Response, next: NextFunction) => {
  const id = (req.headers["x-request-id"] as string) || randomBytes(8).toString("hex");
  req.headers["x-request-id"] = id;
  res.setHeader("x-request-id", id);
  next();
});

/* ── Security headers ──────────────────────────────────────────────── */
app.use((_req: Request, res: Response, next: NextFunction) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  res.setHeader("X-Permitted-Cross-Domain-Policies", "none");
  res.removeHeader("X-Powered-By");
  next();
});

/* ── Request timeout (60s default, overrideable per-route) ─────────── */
const REQUEST_TIMEOUT_MS = Number(process.env["REQUEST_TIMEOUT_MS"] ?? 60_000);
app.use((req: Request, res: Response, next: NextFunction) => {
  req.socket.setTimeout(REQUEST_TIMEOUT_MS);
  req.on("timeout", () => {
    if (!res.headersSent) {
      res.status(408).json({ error: "Request timeout" });
    }
  });
  next();
});

/* ── HTTP request logging ──────────────────────────────────────────── */
app.use(
  pinoHttp({
    logger,
    genReqId: (req) => req.headers["x-request-id"] as string,
    serializers: {
      req(req) {
        return { id: req.id, method: req.method, url: req.url?.split("?")[0] };
      },
      res(res) {
        return { statusCode: res.statusCode };
      },
    },
  }),
);

/* ── CORS ──────────────────────────────────────────────────────────── */
const allowedOrigins = (process.env["CORS_ORIGINS"] ?? "*")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

app.use(cors({
  origin: allowedOrigins.includes("*") ? "*" : (origin, cb) => {
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    cb(new Error("Not allowed by CORS"));
  },
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Request-ID"],
  exposedHeaders: ["X-Request-ID"],
  maxAge: 86_400, // preflight cache: 24h
}));

/* ── Body parsing ──────────────────────────────────────────────────── */
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

/* ── API routes ────────────────────────────────────────────────────── */
app.use("/api", router);

/* ── Static frontend ───────────────────────────────────────────────── */
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const frontendDist = path.resolve(__dirname, "../../nexus/dist/public");
if (existsSync(frontendDist)) {
  app.use(express.static(frontendDist, { maxAge: 0 }));
  app.get("/{*splat}", (_req: Request, res: Response) => {
    res.sendFile(path.join(frontendDist, "index.html"));
  });
}

/* ── 404 handler (must be after all routes) ────────────────────────── */
app.use((req: Request, res: Response) => {
  if (!res.headersSent) {
    res.status(404).json({ error: "Not found", path: req.path });
  }
});

/* ── Global error handler ──────────────────────────────────────────── */
// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: Error, req: Request, res: Response, _next: NextFunction) => {
  const reqId = req.headers["x-request-id"] as string;
  logger.error({ err, reqId, method: req.method, url: req.url?.split("?")[0] }, "Unhandled route error");
  if (!res.headersSent) {
    const status = (err as { status?: number }).status ?? 500;
    const msg    = process.env["NODE_ENV"] === "production" ? "Internal server error" : err.message;
    res.status(status).json({ error: msg, requestId: reqId });
  }
});

export default app;
