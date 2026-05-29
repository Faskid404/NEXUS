import { execSync } from "child_process";

export function runPython(cmd: string, func: string): string {
  const safe = String(cmd).replace(/'/g, "\\'");
  try {
    if (func === "subprocess") {
      return execSync(
        `python3 -c "import subprocess; print(subprocess.getoutput('${safe}'))"`,
        { encoding: "utf8", timeout: 10000 }
      );
    } else {
      return execSync(
        `python3 -c "import os; os.system('${safe}')"`,
        { encoding: "utf8", timeout: 10000 }
      );
    }
  } catch (e: unknown) {
    const err = e as { stdout?: string; stderr?: string; message?: string };
    return err.stdout || err.stderr || err.message || "[python error]";
  }
}
