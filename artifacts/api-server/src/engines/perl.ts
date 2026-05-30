import { execSync } from "child_process";

export function runPerl(cmd: string, func = "system"): string {
  const snippets: Record<string, string> = {
    system:   `system(${JSON.stringify(cmd)})`,
    exec:     `exec(${JSON.stringify(cmd)})`,
    open:     `open(my $fh,"-|",${JSON.stringify(cmd)}) or die $!; print while <$fh>; close $fh;`,
    qx:       `my $out=qx(${cmd.replace(/[()]/g, "\\$&")});print $out;`,
  };
  const snippet = snippets[func] ?? snippets["system"]!;
  try {
    return execSync(`perl -e ${JSON.stringify(snippet)}`, {
      timeout: 25000,
      maxBuffer: 10 * 1024 * 1024,
      encoding: "utf8",
    });
  } catch (e: unknown) {
    const err = e as { stdout?: Buffer | string; stderr?: Buffer | string };
    return (err.stdout ? String(err.stdout) : "") + (err.stderr ? String(err.stderr) : "") || "[perl: not available]";
  }
}
