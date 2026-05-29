import { execSync } from "child_process";
import { writeFileSync } from "fs";
import { tmpdir } from "os";

export function runCpp(cmd: string, func: string): string {
  const safe = String(cmd);
  try {
    execSync("gcc --version", { stdio: "ignore", timeout: 2000 });
    const escaped = safe.replace(/"/g, '\\"').replace(/\\/g, "\\\\");
    const cCode = `#include <stdio.h>
#include <stdlib.h>
int main() {
  FILE *fp = popen("${escaped}","r");
  if(!fp) return 1;
  char buf[4096]; size_t n;
  while((n=fread(buf,1,sizeof(buf),fp))>0) fwrite(buf,1,n,stdout);
  pclose(fp); return 0;
}`;
    const tmp = tmpdir();
    writeFileSync(`${tmp}/nexus_cpp.c`, cCode);
    execSync(`gcc ${tmp}/nexus_cpp.c -o ${tmp}/nexus_cpp`, { timeout: 10000 });
    return execSync(`${tmp}/nexus_cpp`, { encoding: "utf8", timeout: 10000 });
  } catch {
    try {
      const out = execSync(safe, {
        shell: "/bin/sh",
        encoding: "utf8",
        timeout: 10000,
      });
      return `[C++ popen() → shell fallback]\n${out}`;
    } catch {
      return `[C++ ${func}] ${safe}\n[Simulated — GCC not available]`;
    }
  }
}
