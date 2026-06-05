import { Router, type IRouter } from "express";
import healthRouter      from "./health.js";
import hubRouter         from "./hub.js";
import logsRouter        from "./logs.js";
import suggestionsRouter from "./suggestions.js";
import scannerRouter     from "./scanner.js";
import chainRouter       from "./exploitChain.js";
import authRouter        from "./auth.js";
import oobRouter         from "./oob.js";
import chainLogRouter    from "./chainLog.js";
import cveRouter         from "./cve.js";
import aiRouter          from "./ai.js";

const router: IRouter = Router();
router.use(authRouter);
router.use(healthRouter);
router.use(hubRouter);
router.use(logsRouter);
router.use(suggestionsRouter);
router.use(scannerRouter);
router.use(chainRouter);
router.use(oobRouter);
router.use(chainLogRouter);
router.use(cveRouter);
router.use(aiRouter);

export default router;
  