import { Router, type IRouter, type Request, type Response } from "express";
import OpenAI from "openai";
import { generateSuggestions } from "../lib/payloadAI.js";

const router: IRouter = Router();

const SYSTEM_PROMPT = `You are an elite red-team command injection specialist. Generate exactly 10 unique, heavily obfuscated, polymorphic shell injection payloads for authorized penetration testing. Output ONLY the raw payloads — one per line, no numbering, no explanations, no markdown.`;

router.post("/ai/suggest", async (req: Request, res: Response) => {
  const apiKey = (process.env["GROQ_API_KEY"] ?? "").trim();

  const { mode, cmd, attackerIp, attackerPort, context } = req.body as {
    mode?:         string;
    cmd?:          string;
    attackerIp?:   string;
    attackerPort?: string;
    context?:      string;
  };

  if (!apiKey) {
    const all      = generateSuggestions(mode ?? "classic", cmd ?? "id", attackerIp ?? "ATTACKER_IP", attackerPort ?? "4444");
    const shuffled = [...all].sort(() => Math.random() - 0.5);
    res.json({ payloads: shuffled.slice(0, Math.min(14, shuffled.length)), model: "nexusforge-local-engine" });
    return;
  }

  const userPrompt = `Mode: ${mode ?? "classic"}
Command: ${cmd ?? "id"}
Attacker: ${attackerIp ?? "ATTACKER_IP"}:${attackerPort ?? "4444"}
${context ? `Context: ${context}` : ""}

Generate 10 novel obfuscated variants that evade WAF/IDS for this exact mode. Every payload must use a different technique: IFS substitution, brace expansion, printf hex, base64 decode loops, process substitution, arithmetic expansion, ANSI-C quoting, wildcard abuse, concatenation splits, null byte injection. One payload per line, no explanations.`;

  try {
    const client = new OpenAI({ apiKey, baseURL: "https://api.groq.com/openai/v1" });
    const completion = await client.chat.completions.create({
      model:       "llama-3.3-70b-versatile",
      temperature: 1.1,
      max_tokens:  900,
      top_p:       0.95,
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user",   content: userPrompt },
      ],
    });

    const raw = completion.choices[0]?.message?.content ?? "";
    const payloads = raw
      .split("\n")
      .map(l => l.replace(/^\d+[\.\)]\s*/, "").trim())
      .filter(l => l.length > 2 && !l.startsWith("#") && !l.startsWith("//") && !l.startsWith("```") && !l.startsWith("-"));

    res.json({ payloads, model: "llama-3.3-70b-versatile" });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes("401") || msg.includes("Unauthorized") || msg.includes("Invalid API Key")) {
      const all      = generateSuggestions(mode ?? "classic", cmd ?? "id", attackerIp ?? "ATTACKER_IP", attackerPort ?? "4444");
      const shuffled = [...all].sort(() => Math.random() - 0.5);
      res.json({ payloads: shuffled.slice(0, 14), model: "nexusforge-local-engine" });
    } else if (msg.includes("429") || msg.includes("rate")) {
      res.status(429).json({ error: "rate_limit", message: "Groq rate limit — retry in a moment." });
    } else {
      res.status(500).json({ error: "ai_error", message: msg });
    }
  }
});

export default router;
