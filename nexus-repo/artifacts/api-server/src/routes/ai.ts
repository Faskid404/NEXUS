import { Router, type IRouter, type Request, type Response } from "express";
import OpenAI from "openai";

const router: IRouter = Router();

function getClient(apiKey: string): OpenAI {
  return new OpenAI({
    apiKey,
    baseURL: "https://api.groq.com/openai/v1",
  });
}

const SYSTEM_PROMPT = `You are a professional red-team security researcher specializing in command injection, RCE bypass, and WAF evasion. Generate unique, polymorphic shell payloads for authorized penetration testing.

Rules:
- Generate ONLY the payload strings, one per line, no explanations
- Each payload must be syntactically distinct (different obfuscation technique)
- Payloads must be creative, novel, and bypass modern WAF signatures
- Use legitimate Unix/shell constructs: IFS tricks, brace expansion, printf hex, base64 loops, process substitution, arithmetic expansion, null bytes, wildcard abuse, ANSI-C quoting
- Never repeat the same obfuscation technique twice in one response
- Output exactly 8-12 payloads, one per line`;

router.post("/ai/suggest", async (req: Request, res: Response) => {
  const headerKey = req.headers["x-ai-key"] as string | undefined;
  const envKey    = process.env["GROQ_API_KEY"];
  const apiKey    = (headerKey || envKey || "").trim();

  if (!apiKey) {
    res.status(402).json({
      error: "no_key",
      message: "No Groq API key. Get a free key at console.groq.com (no credit card required) and enter it in Settings.",
    });
    return;
  }

  const { mode, cmd, attackerIp, attackerPort, context } = req.body as {
    mode?:        string;
    cmd?:         string;
    attackerIp?:  string;
    attackerPort?: string;
    context?:     string;
  };

  const userPrompt = `Generate polymorphic ${mode ?? "classic"} injection payloads for command: ${cmd ?? "id"}
Attacker IP: ${attackerIp ?? "ATTACKER_IP"}, Port: ${attackerPort ?? "4444"}
${context ? `Context: ${context}` : ""}

Each payload must use a DIFFERENT obfuscation technique. Output one payload per line, no numbering, no explanation.`;

  try {
    const client = getClient(apiKey);
    const completion = await client.chat.completions.create({
      model: "llama-3.3-70b-versatile",
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user",   content: userPrompt },
      ],
      temperature:  1.1,
      max_tokens:   1024,
      top_p:        0.95,
    });

    const raw = completion.choices[0]?.message?.content ?? "";
    const payloads = raw
      .split("\n")
      .map(l => l.replace(/^\d+[\.\)]\s*/, "").trim())
      .filter(l => l.length > 2 && !l.startsWith("#") && !l.startsWith("//") && !l.startsWith("-"));

    res.json({ payloads, model: "llama-3.3-70b-versatile" });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes("401") || msg.includes("Unauthorized") || msg.includes("Invalid API Key")) {
      res.status(401).json({ error: "invalid_key", message: "Invalid Groq API key. Check your key at console.groq.com." });
    } else if (msg.includes("429") || msg.includes("rate")) {
      res.status(429).json({ error: "rate_limit", message: "Groq rate limit hit. Wait a moment and try again." });
    } else {
      res.status(500).json({ error: "ai_error", message: msg });
    }
  }
});

export default router;
