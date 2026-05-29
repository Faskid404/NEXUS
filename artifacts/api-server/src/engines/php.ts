import { execSync } from "child_process";

export function runPhp(cmd: string, func: string): string {
  const safe = String(cmd).replace(/'/g, "\\'").replace(/"/g, '\\"');
  const funcs: Record<string, string> = {
    system: `ob_start(); system("${safe}"); $o = ob_get_clean(); echo $o;`,
    exec: `$o=[]; exec("${safe}", $o); echo implode("\\n", $o);`,
    shell_exec: `echo shell_exec("${safe}");`,
  };
  const snippet = funcs[func] ?? funcs["shell_exec"];
  try {
    return execSync(`php -r '${snippet}'`, {
      encoding: "utf8",
      timeout: 10000,
    });
  } catch {
    return `[PHP ${func}()] ${cmd}\n[PHP not installed on this host — simulated output]`;
  }
}
