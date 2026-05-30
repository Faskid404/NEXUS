import { Router, type IRouter } from "express";
import healthRouter from "./health.js";
import hubRouter from "./hub.js";
import logsRouter from "./logs.js";
import suggestionsRouter from "./suggestions.js";
import scannerRouter from "./scanner.js";
import chainRouter from "./exploitChain.js";

const router: IRouter = Router();

router.use(healthRouter);
router.use(hubRouter);
router.use(logsRouter);
router.use(suggestionsRouter);
router.use(scannerRouter);
router.use(chainRouter);

export default router;
