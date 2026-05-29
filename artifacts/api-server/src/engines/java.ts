import { execSync } from "child_process";
import { writeFileSync } from "fs";
import { tmpdir } from "os";

export function runJava(cmd: string, func: string): string {
  const safe = String(cmd);
  try {
    execSync("java -version", { stdio: "ignore", timeout: 2000 });
    const escaped = safe.replace(/"/g, '\\"').replace(/\\/g, "\\\\");
    const javaCode = `public class NexusExec {
  public static void main(String[] a) throws Exception {
    String[] c = {"/bin/sh","-c","${escaped}"};
    Process p = Runtime.getRuntime().exec(c);
    byte[] b = p.getInputStream().readAllBytes();
    System.out.write(b);
  }
}`;
    const tmp = tmpdir();
    writeFileSync(`${tmp}/NexusExec.java`, javaCode);
    execSync(`javac ${tmp}/NexusExec.java -d ${tmp}`, { timeout: 8000 });
    return execSync(`java -cp ${tmp} NexusExec`, {
      encoding: "utf8",
      timeout: 10000,
    });
  } catch {
    try {
      const out = execSync(safe, {
        shell: "/bin/sh",
        encoding: "utf8",
        timeout: 10000,
      });
      return `[Java Runtime.exec() → shell fallback]\n${out}`;
    } catch (e2: unknown) {
      const err = e2 as { message?: string };
      return `[Java ${func}] ${safe}\n[Simulated — Java not available: ${(err.message ?? "").split("\n")[0]}]`;
    }
  }
}
