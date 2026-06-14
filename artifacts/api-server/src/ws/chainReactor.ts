import type { WebSocket } from "ws";
import { KILL_CHAINS, getKillChain, type ChainStep, type KillChain } from "../lib/chainReactor.js";
import { tcpProbe, dispatchPort } from "../lib/exploitEngine.js";
import { logger } from "../lib/logger.js";

interface ReactorRequest {
  chainId?:   string;
  custom?:    KillChain;
  target?:    string;
  lhost?:     string;
  lport?:     string | number;
  extraVars?: Record<string, string>;
}

interface StepResult {
  stepId:  string;
  name:    string;
  status:  "success" | "failed" | "skipped" | "info";
  output:  string;
  elapsed: number;
}

function send(ws: WebSocket, obj: unknown): void {
  if (ws.readyState === 1) {
    try { ws.send(JSON.stringify(obj)); } catch { /* closed mid-send */ }
  }
}

function interpolate(s: string, vars: Record<string, string>): string {
  return Object.entries(vars).reduce((acc, [k, v]) => acc.replaceAll(k, v), s);
}

async function execStep(
  step: ChainStep,
  vars: Record<string, string>,
  abortRef: { aborted: boolean },
): Promise<StepResult> {
  const t0 = Date.now();
  const name = interpolate(step.name, vars);

  if (abortRef.aborted) {
    return { stepId: step.id, name, status: "skipped", output: "Aborted", elapsed: 0 };
  }

  try {
    if (step.type === "info") {
      const cmd = step.cmd ? interpolate(step.cmd, vars) : "(info step)";
      return { stepId: step.id, name, status: "info", output: cmd, elapsed: Date.now() - t0 };
    }

    if (step.type === "port_exploit") {
      const target  = interpolate(step.target ?? "TARGET", vars);
      const port    = step.port ?? 80;
      const isOpen  = await tcpProbe(target, port, step.timeout ?? 4000);
      if (!isOpen) {
        return { stepId: step.id, name, status: "failed", output: `${target}:${port} — closed/filtered`, elapsed: Date.now() - t0 };
      }
      const res = await dispatchPort(target, port);
      return {
        stepId: step.id, name,
        status: res.status === "success" ? "success" : "failed",
        output: `PORT ${port} open\n${res.action}\n${res.result}`,
        elapsed: Date.now() - t0,
      };
    }

    if (step.type === "http_probe" || step.type === "inject") {
      const rawUrl = interpolate(step.url ?? "http://127.0.0.1/", vars);
      const method = (step.method ?? "GET").toUpperCase();
      const payload = step.payload ? interpolate(step.payload, vars) : undefined;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), step.timeout ?? 8000);
      let status = 0;
      let body   = "";
      try {
        const headers: Record<string, string> = { "User-Agent": "Mozilla/5.0" };
        if (payload) headers["Content-Type"] = "application/json";
        const resp = await fetch(rawUrl, {
          method,
          headers,
          body:   payload,
          signal: controller.signal,
        });
        status = resp.status;
        body   = (await resp.text()).slice(0, 2000);
      } finally {
        clearTimeout(timer);
      }
      const wantCode = step.successIf ? parseInt(step.successIf, 10) : 200;
      const ok = status === wantCode || (step.successIf === "200" && status >= 200 && status < 300);
      return {
        stepId: step.id, name,
        status: ok ? "success" : "failed",
        output: `HTTP ${status} ${rawUrl}\n${body.slice(0, 800)}`,
        elapsed: Date.now() - t0,
      };
    }

    if (step.type === "custom") {
      const cmd = step.cmd ? interpolate(step.cmd, vars) : "(no command)";
      return {
        stepId: step.id, name, status: "info",
        output: `RUN:\n${cmd}`,
        elapsed: Date.now() - t0,
      };
    }

    return { stepId: step.id, name, status: "info", output: "Unknown step type", elapsed: Date.now() - t0 };
  } catch (err) {
    return {
      stepId: step.id, name, status: "failed",
      output: err instanceof Error ? err.message : String(err),
      elapsed: Date.now() - t0,
    };
  }
}

export function handleChainReactor(ws: WebSocket): void {
  ws.once("message", (raw) => {
    let req: ReactorRequest;
    try {
      req = JSON.parse(raw.toString()) as ReactorRequest;
    } catch {
      send(ws, { type: "error", message: "invalid JSON" });
      ws.close();
      return;
    }

    const abortRef = { aborted: false };
    ws.on("close",   () => { abortRef.aborted = true; });
    ws.on("message", (m) => {
      try {
        const msg = JSON.parse(m.toString()) as { type?: string };
        if (msg.type === "abort") abortRef.aborted = true;
      } catch { /* ignore */ }
    });

    let chain: KillChain | undefined;
    if (req.chainId) {
      chain = getKillChain(req.chainId);
    } else if (req.custom) {
      chain = req.custom;
    }

    if (!chain) {
      send(ws, { type: "error", message: `Kill chain '${req.chainId ?? "custom"}' not found` });
      ws.close();
      return;
    }

    const target = (req.target ?? "127.0.0.1").trim().replace(/[^a-zA-Z0-9.\-_:\[\]]/g, "");
    const lhost  = (req.lhost  ?? "127.0.0.1").trim();
    const lport  = String(req.lport ?? "4444").trim();

    const vars: Record<string, string> = {
      TARGET: target,
      LHOST:  lhost,
      LPORT:  lport,
      ...(req.extraVars ?? {}),
    };

    logger.info({ chain: chain.id, target, steps: chain.steps.length }, "ws/chainreactor start");

    const run = async (): Promise<void> => {
      send(ws, {
        type:     "chain_start",
        chainId:  chain!.id,
        name:     chain!.name,
        total:    chain!.steps.length,
        target,
        lhost,
        lport,
      });

      let succeeded = 0;
      let failed    = 0;

      for (const step of chain!.steps) {
        if (abortRef.aborted) {
          send(ws, { type: "step_skip", stepId: step.id, name: step.name, reason: "aborted" });
          continue;
        }

        send(ws, { type: "step_start", stepId: step.id, name: step.name, stepType: step.type });

        const result = await execStep(step, vars, abortRef);

        send(ws, { type: "step_result", ...result });

        if (result.status === "success") succeeded++;
        if (result.status === "failed")  failed++;

        if (result.status === "failed" && step.failAction === "abort") {
          abortRef.aborted = true;
          send(ws, { type: "step_abort", stepId: step.id, reason: "failAction=abort" });
          break;
        }

        if (!abortRef.aborted) await new Promise(r => setTimeout(r, 150));
      }

      send(ws, {
        type:      "chain_end",
        chainId:   chain!.id,
        succeeded,
        failed,
        aborted:   abortRef.aborted,
        total:     chain!.steps.length,
      });
      ws.close();
    };

    void run();
  });

  send(ws, { type: "ready", chains: KILL_CHAINS.map(c => ({ id: c.id, name: c.name, category: c.category, steps: c.steps.length })) });
}
