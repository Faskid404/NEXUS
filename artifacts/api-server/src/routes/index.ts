import { Router, type IRouter } from "express";
import { requireAuth }      from "../middlewares/requireAuth.js";
import healthRouter         from "./health.js";
import hubRouter            from "./hub.js";
import logsRouter           from "./logs.js";
import suggestionsRouter    from "./suggestions.js";
import scannerRouter        from "./scanner.js";
import chainRouter          from "./exploitChain.js";
import authRouter           from "./auth.js";
import oobRouter            from "./oob.js";
import chainLogRouter       from "./chainLog.js";
import cveRouter            from "./cve.js";
import aiRouter             from "./ai.js";
import deliverRouter        from "./deliver.js";
import exfilRouter          from "./exfil.js";

const router: IRouter = Router();

/* ── Public (no auth required) ─────────────────────────────────────── */
router.use(authRouter);    // POST /api/auth/login, GET /api/auth/verify
router.use(healthRouter);  // GET  /api/healthz

/* ── Protected (valid Bearer token required) ────────────────────────── */
router.use(requireAuth);
router.use(hubRouter);
router.use(logsRouter);
router.use(suggestionsRouter);
router.use(scannerRouter);
router.use(chainRouter);
router.use(oobRouter);
router.use(chainLogRouter);
router.use(cveRouter);
router.use(aiRouter);
router.use(deliverRouter);
router.use(exfilRouter);

export default router;
