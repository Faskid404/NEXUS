import { Router, type IRouter, type Request, type Response } from "express";
import { execSync } from "child_process";
import { applyQuantumBypass } from "../lib/bypassEngine.js";
import { logInjection } from "../lib/injectionLogger.js";
import { buildWafBypass } from "../lib/bypassEngine.js";
import { generateSuggestions } from "../lib/payloadAI.js";
import { runBash } from "../engines/bash.js";
import { runNode } from "../engines/node.js";
import { runPython } from "../engines/python.js";
import { runPhp } from "../engines/php.js";
import { runJava } from "../engines/java.js";
import { runCpp } from "../engines/cpp.js";
import { runPowershell } from "../engines/powershell.js";
import { runRuby } from "../engines/ruby.js";
import { runPerl } from "../engines/perl.js";

const router: IRouter = Router();

function checkBin(cmd: string): boolean {
  try { execSync(cmd, { stdio: "ignore", timeout: 2000 }); return true; } catch { return false; }
}

router.get("/hub/health", (_req: Request, res: Response) => {
  res.json({
    status: "online",
    version: "7.0.0",
    timestamp: new Date().toISOString(),
    engines: ["bash","node","python","php","java","cpp","powershell","ruby","perl"],
    modes: ["classic","blind","oob","quantum","ifs","concat","hex","b64loop","env","heredoc"],
  });
});

router.get("/hub/engines", (_req: Request, res: Response) => {
  res.json({
    bash:       true,
    node:       true,
    python:     checkBin("python3 --version"),
    php:        checkBin("php --version"),
    java:       checkBin("java -version"),
    cpp:        checkBin("gcc --version"),
    powershell: checkBin("pwsh --version") || checkBin("powershell -v"),
    ruby:       checkBin("ruby --version"),
    perl:       checkBin("perl --version"),
  });
});

router.post("/hub/bypass", (req: Request, res: Response) => {
  const { payload = "id" } = req.body as { payload?: string };
  res.json({ variants: buildWafBypass(payload) });
});

router.post("/hub/suggest", (req: Request, res: Response) => {
  const { mode, cmd = "id", attackerIp = "127.0.0.1", attackerPort = "4444" } =
    req.body as { mode?: string; cmd?: string; attackerIp?: string; attackerPort?: string };
  res.json({ suggestions: generateSuggestions(mode, cmd, attackerIp, attackerPort) });
});

router.post("/hub/exec", async (req: Request, res: Response) => {
  const start = Date.now();
  const {
    cmd,
    engine       = "bash/bash",
    mode         = "classic",
    attackerIp   = "127.0.0.1",
    attackerPort = "4444",
  } = req.body as { cmd?: string; engine?: string; mode?: string; attackerIp?: string; attackerPort?: string };

  if (!cmd || typeof cmd !== "string" || !cmd.trim()) {
    res.status(400).json({ error: "cmd is required" });
    return;
  }

  const processed = applyQuantumBypass(cmd, mode, attackerIp, attackerPort);
  const [lang, func = "exec"] = engine.split("/");

  let output = "";
  try {
    if      (lang === "bash")       output = runBash(processed);
    else if (lang === "node")       output = await runNode(processed, func);
    else if (lang === "python")     output = runPython(processed, func);
    else if (lang === "php")        output = runPhp(processed, func);
    else if (lang === "java")       output = runJava(processed, func);
    else if (lang === "cpp")        output = runCpp(processed, func);
    else if (lang === "powershell") output = runPowershell(processed);
    else if (lang === "ruby")       output = runRuby(processed, func);
    else if (lang === "perl")       output = runPerl(processed, func);
    else { res.status(400).json({ error: `Unknown engine: ${lang}` }); return; }
  } catch (e: unknown) {
    output = `[Engine Error] ${(e as Error).message}`;
  }

  const elapsed = Date.now() - start;
  logInjection(cmd, engine, mode, elapsed);
  res.json({ output: String(output), engine, mode, elapsed });
});

export default router;
