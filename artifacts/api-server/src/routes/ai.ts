import { Router, type IRouter, type Request, type Response } from "express";
import OpenAI from "openai";
import { generateSuggestions } from "../lib/payloadAI.js";
import { createLogger } from "../lib/logger.js";

const log    = createLogger("ai");
const router: IRouter = Router();

const SYSTEM_PROMPT = `You are an elite red-team command injection specialist. Generate exactly 10 unique, heavily obfuscated, polymorphic shell injection payloads for authorized penetration testing. Output ONLY the raw payloads — one per line, no numbering, no explanations, no markdown.`;

/* ── Supported AI provider chain ──────────────────────────────────── */
interface ProviderConfig {
  name:    string;
  baseURL: string;
  envKey:  string;
  models:  string[];
}

const PROVIDERS: ProviderConfig[] = [
  {
    name:    "groq",
    baseURL: "https://api.groq.com/openai/v1",
    envKey:  "GROQ_API_KEY",
    models:  ["llama-3.3-70b-versatile", "llama-3.1-70b-versatile", "mixtral-8x7b-32768", "gemma2-9b-it"],
  },
  {
    name:    "openrouter",
    baseURL: "https://openrouter.ai/api/v1",
    envKey:  "OPENROUTER_API_KEY",
    models:  ["meta-llama/llama-3.3-70b-instruct", "mistralai/mixtral-8x7b-instruct", "google/gemma-2-9b-it:free"],
  },
  {
    name:    "openai",
    baseURL: "https://api.openai.com/v1",
    envKey:  "OPENAI_API_KEY",
    models:  ["gpt-4o-mini", "gpt-3.5-turbo"],
  },
];

function cleanPayloads(raw: string): string[] {
  const seen = new Set<string>();
  return raw
    .split("\n")
    .map(l => l.replace(/^\d+[\.\)]\s*/, "").trim())
    .filter(l =>
      l.length > 4 &&
      !l.startsWith("#") &&
      !l.startsWith("//") &&
      !l.startsWith("```") &&
      !l.startsWith("-") &&
      !l.toLowerCase().startsWith("note:") &&
      !l.toLowerCase().startsWith("payload")
    )
    .filter(l => {
      if (seen.has(l)) return false;
      seen.add(l);
      return true;
    });
}

async function tryProvider(
  provider: ProviderConfig,
  userPrompt: string,
): Promise<{ payloads: string[]; model: string } | null> {
  const apiKey = (process.env[provider.envKey] ?? "").trim();
  if (!apiKey) return null;

  for (const model of provider.models) {
    try {
      const client = new OpenAI({ apiKey, baseURL: provider.baseURL });
      const completion = await client.chat.completions.create({
        model,
        temperature: 1.1,
        max_tokens:  1024,
        top_p:       0.95,
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          { role: "user",   content: userPrompt },
        ],
      });
      const raw      = completion.choices[0]?.message?.content ?? "";
      const payloads = cleanPayloads(raw);
      if (payloads.length >= 3) {
        log.info({ provider: provider.name, model, count: payloads.length }, "ai: payloads generated");
        return { payloads, model: `${provider.name}/${model}` };
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("401") || msg.includes("Unauthorized") || msg.includes("Invalid API Key")) {
        log.warn({ provider: provider.name, model }, "ai: invalid API key — skipping provider");
        break; // Don't try other models for this provider
      }
      if (msg.includes("404") || msg.includes("not found") || msg.includes("does not exist")) {
        log.warn({ provider: provider.name, model }, "ai: model not available — trying next");
        continue; // Try next model
      }
      if (msg.includes("429") || msg.includes("rate")) {
        log.warn({ provider: provider.name, model }, "ai: rate limited — trying next provider");
        break; // Rate limited — try next provider
      }
      log.warn({ provider: provider.name, model, err: msg }, "ai: request failed — trying next");
      continue;
    }
  }
  return null;
}

/* ── POST /ai/suggest ──────────────────────────────────────────────── */
router.post("/ai/suggest", async (req: Request, res: Response) => {
  const { mode, cmd, attackerIp, attackerPort, context } = req.body as {
    mode?: string; cmd?: string; attackerIp?: string; attackerPort?: string; context?: string;
  };

  const userPrompt = `Mode: ${mode ?? "classic"}
Command: ${cmd ?? "id"}
Attacker: ${attackerIp ?? "ATTACKER_IP"}:${attackerPort ?? "4444"}
${context ? `Context: ${context}` : ""}

Generate 10 novel obfuscated variants that evade WAF/IDS for this exact mode. Every payload must use a different technique: IFS substitution, brace expansion, printf hex, base64 decode loops, process substitution, arithmetic expansion, ANSI-C quoting, wildcard abuse, concatenation splits, null byte injection. One payload per line, no explanations.`;

  // Try each provider in priority order
  for (const provider of PROVIDERS) {
    const result = await tryProvider(provider, userPrompt);
    if (result) {
      res.json({ payloads: result.payloads, model: result.model });
      return;
    }
  }

  // All providers failed or no API keys — fall back to local engine
  const all      = generateSuggestions(mode ?? "classic", cmd ?? "id", attackerIp ?? "ATTACKER_IP", attackerPort ?? "4444");
  const shuffled = [...all].sort(() => Math.random() - 0.5);
  log.info({ mode, count: shuffled.length }, "ai: using local engine (no AI keys configured)");
  res.json({ payloads: shuffled.slice(0, Math.min(14, shuffled.length)), model: "nexusforge-local-engine" });
});

/* ── GET /ai/models — list available AI providers/models ───────────── */
router.get("/ai/models", (_req: Request, res: Response) => {
  const available = PROVIDERS
    .filter(p => (process.env[p.envKey] ?? "").trim().length > 0)
    .map(p => ({ provider: p.name, models: p.models }));

  res.json({
    available,
    fallback: { provider: "nexusforge-local-engine", models: ["all-modes"] },
    totalProviders: PROVIDERS.length,
    configuredProviders: available.length,
  });
});

/* ── GET /ai/modes — list injection modes the AI can generate for ──── */
router.get("/ai/modes", (_req: Request, res: Response) => {
  res.json({
    modes: [
      "classic", "blind", "oob", "quantum", "polymorphic", "ifs", "concat",
      "hex", "b64loop", "env", "heredoc", "unicode", "null", "wildcard",
      "comment", "double_enc", "brace", "process_sub", "arith", "ansi_c",
      "rev", "ssti", "log4shell", "xxe", "polyglot", "rev_shell", "cloud",
      "container", "timing", "stealth", "windows_timing", "windows_rev",
      "windows", "antiforensics",
    ],
  });
});

export default router;
