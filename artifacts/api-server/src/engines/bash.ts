import { execSync } from "child_process";

export function runBash(cmd: string): string {
  try {
    return execSync(String(cmd), {
      shell: "/bin/bash",
      encoding: "utf8",
      timeout: 10000,
    });
  } catch (e: unknown) {
    const err = e as { stdout?: string; stderr?: string; message?: string };
    return err.stdout || err.stderr || err.message || "[bash error]";
  }
}
