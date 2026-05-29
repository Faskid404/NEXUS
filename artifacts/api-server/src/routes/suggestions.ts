import { Router, type IRouter, type Request, type Response } from "express";
import { generateSuggestions } from "../lib/payloadAI.js";

const router: IRouter = Router();

router.get("/suggestions", (req: Request, res: Response) => {
  const { mode, cmd } = req.query as { mode?: string; cmd?: string };
  res.json(generateSuggestions(mode, cmd));
});

export default router;
