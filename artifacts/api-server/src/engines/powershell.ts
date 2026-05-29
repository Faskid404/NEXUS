import { execSync } from "child_process";

export function runPowershell(cmd: string): string {
  const safe = String(cmd);
  for (const bin of ["pwsh", "powershell"]) {
    try {
      execSync(`${bin} --version`, { stdio: "ignore", timeout: 2000 });
      return execSync(
        `${bin} -NonInteractive -Command "${safe.replace(/"/g, '\\"')}"`,
        { encoding: "utf8", timeout: 10000 }
      );
    } catch {
      continue;
    }
  }
  return `[PowerShell] ${safe}\n[Simulated — PowerShell not installed on this host]`;
}
