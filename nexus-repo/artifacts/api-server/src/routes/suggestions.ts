import { Router, type IRouter, type Request, type Response } from "express";
import { generateSuggestions } from "../lib/payloadAI.js";

const router: IRouter = Router();

router.get("/suggestions", (req: Request, res: Response) => {
  const { mode, cmd, attackerIp, attackerPort } = req.query as {
    mode?: string;
    cmd?: string;
    attackerIp?: string;
    attackerPort?: string;
  };
  res.json(generateSuggestions(mode, cmd, attackerIp, attackerPort));
});

export default router;
