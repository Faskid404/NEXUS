import type { WebSocket } from "ws";
import { KILL_CHAINS, getKillChain, type ChainStep, type KillChain } from "../lib/chainReactor.js";
import { tcpProbe, dispatchPort } from "../lib/exploitEngine.js";
import { logger } from "../lib/logger.js";
import { ChainReactorRequestSchema, ChainReactorAbortSchema } from "../lib/schemas.js";
import { withRetry } from "../lib/retry.js";

interface StepResult {
  stepId:  string;
  name:    string;
  status:  "success" | "failed" | "skipped" | "info";
  output:  string;
  elapsed: number;
}

function wsend(ws: WebSocket, obj: unknown): void {
  if (ws.readyState === 1) {
    try { ws.send(JSON.stringify(obj)); } catch { }
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
  const t0   = Date.now();
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
      const target = interpolate(step.target ?? "TARGET", vars);
      const port   = step.port ?? 80;

      const isOpen = await withRetry(() => tcpProbe(target, port, step.timeout ?? 4000), {
        attempts: 2,
        baseMs:   500,
      });

      if (!isOpen) {
        return { stepId: step.id, name, status: "failed", output: `${target}:${port} — closed/filtered`, elapsed: Date.now() - t0 };
      }

      const res = await withRetry(() => dispatchPort(target, port), { attempts: 2, baseMs: 1000 });
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

      let status = 0;
      let body   = "";

      await withRetry(async () => {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), step.timeout ?? 8000);
        try {
          const reqHeaders: Record<string, string> = { "User-Agent": "Mozilla/5.0" };
          if (payload) reqHeaders["Content-Type"] = "application/json";
          const resp = await fetch(rawUrl, {
            method,
            headers: reqHeaders,
            body:    payload,
            signal:  controller.signal,
          });
          status = resp.status;
          body   = (await resp.text()).slice(0, 2000);
        } finally {
          clearTimeout(timer);
        }
      }, { attempts: 2, baseMs: 800 });

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
      return { stepId: step.id, name, status: "info", output: `RUN:\n${cmd}`, elapsed: Date.now() - t0 };
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
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw.toString());
    } catch {
      wsend(ws, { type: "error", message: "invalid JSON" });
      ws.close();
      return;
    }

    const result = ChainReactorRequestSchema.safeParse(parsed);
    if (!result.success) {
      wsend(ws, { type: "error", message: "validation failed", issues: result.error.issues });
      ws.close();
      return;
    }

    const req      = result.data;
    const abortRef = { aborted: false };

    ws.on("close", () => { abortRef.aborted = true; });
    ws.on("message", (m) => {
      try {
        const ctrl = JSON.parse(m.toString());
        const abort = ChainReactorAbortSchema.safeParse(ctrl);
        if (abort.success) abortRef.aborted = true;
      } catch { }
    });

    let chain: KillChain | undefined;
    if (req.chainId) {
      chain = getKillChain(req.chainId);
    } else if (req.custom) {
      chain = req.custom as KillChain;
    }

    if (!chain) {
      wsend(ws, { type: "error", message: `Kill chain '${req.chainId ?? "custom"}' not found` });
      ws.close();
      return;
    }

    const target = (req.target ?? "127.0.0.1").trim().replace(/[^a-zA-Z0-9.\-_:[\]]/g, "");
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
      wsend(ws, {
        type:    "chain_start",
        chainId: chain!.id,
        name:    chain!.name,
        total:   chain!.steps.length,
        target,
        lhost,
        lport,
      });

      let succeeded = 0;
      let failed    = 0;

      for (const step of chain!.steps) {
        if (abortRef.aborted) {
          wsend(ws, { type: "step_skip", stepId: step.id, name: step.name, reason: "aborted" });
          continue;
        }

        wsend(ws, { type: "step_start", stepId: step.id, name: step.name, stepType: step.type });

        const res = await execStep(step, vars, abortRef);
        wsend(ws, { type: "step_result", ...res });

        if (res.status === "success") succeeded++;
        if (res.status === "failed")  failed++;

        if (res.status === "failed" && step.failAction === "abort") {
          abortRef.aborted = true;
          wsend(ws, { type: "step_abort", stepId: step.id, reason: "failAction=abort" });
          break;
        }

        if (!abortRef.aborted) {
          const delay = 150 + Math.random() * 100;
          await new Promise(r => setTimeout(r, delay));
        }
      }

      wsend(ws, {
        type:     "chain_end",
        chainId:  chain!.id,
        succeeded,
        failed,
        aborted:  abortRef.aborted,
        total:    chain!.steps.length,
      });
      ws.close();
    };

    void run();
  });

  wsend(ws, {
    type:   "ready",
    chains: KILL_CHAINS.map(c => ({ id: c.id, name: c.name, category: c.category, steps: c.steps.length })),
  });
}
