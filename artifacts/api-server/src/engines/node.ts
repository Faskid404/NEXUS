import { exec, spawn } from "child_process";

export function runNode(cmd: string, func: string): Promise<string> {
  return new Promise((resolve) => {
    const safe = String(cmd);
    if (func === "spawn") {
      const child = spawn("sh", ["-c", safe]);
      let out = "";
      child.stdout.on("data", (d: Buffer) => (out += d));
      child.stderr.on("data", (d: Buffer) => (out += d));
      child.on("close", (code: number) => resolve(out || `[exit ${code}]`));
      child.on("error", (e: Error) => resolve(`[spawn error] ${e.message}`));
      setTimeout(() => {
        child.kill();
        resolve(out || "[timeout]");
      }, 10000);
    } else {
      exec(safe, { timeout: 10000 }, (err, stdout, stderr) => {
        resolve(stdout || stderr || err?.message || "[no output]");
      });
    }
  });
}
