import { execSync } from "child_process";

export function runRuby(cmd: string, func = "system"): string {
  const snippets: Record<string, string> = {
    system:   `system(${JSON.stringify(cmd)})`,
    popen:    `IO.popen(${JSON.stringify(cmd)},"r"){|io| $stdout.write(io.read); $stdout.flush}`,
    exec:     `exec(${JSON.stringify(cmd)})`,
    open:     `open("|"+${JSON.stringify(cmd)}){|io| STDOUT.write(io.read); STDOUT.flush}`,
  };
  const snippet = snippets[func] ?? snippets["system"]!;
  try {
    return execSync(`ruby -e ${JSON.stringify(snippet)}`, {
      timeout: 25000,
      maxBuffer: 10 * 1024 * 1024,
      encoding: "utf8",
    });
  } catch (e: unknown) {
    const err = e as { stdout?: Buffer | string; stderr?: Buffer | string };
    return (err.stdout ? String(err.stdout) : "") + (err.stderr ? String(err.stderr) : "") || "[ruby: not available]";
  }
}
