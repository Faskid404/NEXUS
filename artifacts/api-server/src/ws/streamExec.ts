import { spawn, execSync } from "child_process";
import { writeFileSync, mkdtempSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import type { WebSocket } from "ws";
import { applyQuantumBypass } from "../lib/bypassEngine.js";
import { logInjection } from "../lib/injectionLogger.js";
import { logger } from "../lib/logger.js";

interface ExecRequest {
  cmd: string;
  engine?: string;
  mode?: string;
  target?: string;
  attackerIp?: string;
  attackerPort?: string;
}

function send(ws: WebSocket, obj: unknown): void {
  if (ws.readyState === 1) ws.send(JSON.stringify(obj));
}

function buildSpawnTarget(
  processed: string,
  engine: string
): { file: string; args: string[]; precompile?: () => { file: string; args: string[] } } {
  const [lang, func = "exec"] = engine.split("/");

  switch (lang) {
    case "bash":
      return { file: "/bin/bash", args: ["-c", processed] };

    case "node":
      return {
        file: "node",
        args: [
          "-e",
          `const {spawn}=require('child_process');` +
          `const p=spawn('/bin/sh',['-c',${JSON.stringify(processed)}],{stdio:'inherit'});` +
          `p.on('error',e=>process.stderr.write(e.message+'\\n'));` +
          (func === "spawn" ? "" : ""),
        ],
      };

    case "python":
      if (func === "subprocess") {
        return {
          file: "python3",
          args: [
            "-u", "-c",
            `import subprocess,sys\n` +
            `p=subprocess.Popen(${JSON.stringify(processed)},shell=True,` +
            `stdout=subprocess.PIPE,stderr=subprocess.STDOUT)\n` +
            `[sys.stdout.buffer.write(c) or sys.stdout.flush() ` +
            `for c in iter(lambda:p.stdout.read(1),b'')]\n` +
            `p.wait()`,
          ],
        };
      }
      return {
        file: "python3",
        args: ["-u", "-c", `import os\nos.system(${JSON.stringify(processed)})`],
      };

    case "php": {
      const snippets: Record<string, string> = {
        system:    `$p=popen(${JSON.stringify(processed)},'r');while(!feof($p)){echo fread($p,128);ob_flush();flush();}pclose($p);`,
        exec:      `$o=[];exec(${JSON.stringify(processed)},$o);echo implode("\\n",$o)."\\n";`,
        shell_exec:`echo shell_exec(${JSON.stringify(processed)});`,
      };
      return { file: "php", args: ["-r", snippets[func] ?? snippets["shell_exec"]!] };
    }

    case "powershell":
      return { file: "pwsh", args: ["-NonInteractive", "-Command", processed] };

    case "java": {
      const esc = processed.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
      const src =
        `public class NexusExec {\n` +
        `  public static void main(String[] a) throws Exception {\n` +
        `    ProcessBuilder pb=new ProcessBuilder("/bin/sh","-c","${esc}");\n` +
        `    pb.redirectErrorStream(true);\n` +
        `    Process p=pb.start();\n` +
        `    byte[] buf=new byte[512]; int n;\n` +
        `    while((n=p.getInputStream().read(buf))!=-1){System.out.write(buf,0,n);System.out.flush();}\n` +
        `    p.waitFor();\n` +
        `  }\n` +
        `}`;
      return {
        file: "",
        args: [],
        precompile: () => {
          const tmp = mkdtempSync(join(tmpdir(), "nxj-"));
          writeFileSync(`${tmp}/NexusExec.java`, src);
          execSync(`javac ${tmp}/NexusExec.java -d ${tmp}`, { timeout: 15000, stdio: "ignore" });
          return { file: "java", args: ["-cp", tmp, "NexusExec"] };
        },
      };
    }

    case "cpp": {
      const esc = processed.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
      const src =
        `#include <stdio.h>\n#include <stdlib.h>\n` +
        `int main(){\n` +
        `FILE*fp=popen("${esc}","r");\n` +
        `if(!fp){fputs("popen failed\\n",stderr);return 1;}\n` +
        `char buf[512];size_t n;\n` +
        `while((n=fread(buf,1,sizeof(buf),fp))>0){fwrite(buf,1,n,stdout);fflush(stdout);}\n` +
        `pclose(fp);return 0;}`;
      return {
        file: "",
        args: [],
        precompile: () => {
          const tmp = mkdtempSync(join(tmpdir(), "nxc-"));
          const bin = `${tmp}/nexus_bin`;
          writeFileSync(`${tmp}/nexus.c`, src);
          execSync(`gcc ${tmp}/nexus.c -o ${bin}`, { timeout: 15000, stdio: "ignore" });
          return { file: bin, args: [] };
        },
      };
    }

    default:
      return { file: "/bin/sh", args: ["-c", processed] };
  }
}

export function handleStreamExec(ws: WebSocket): void {
  ws.once("message", (raw) => {
    let req: ExecRequest;
    try {
      req = JSON.parse(raw.toString()) as ExecRequest;
    } catch {
      send(ws, { type: "error", message: "invalid JSON" });
      ws.close();
      return;
    }

    const {
      cmd        = "",
      engine     = "bash/bash",
      mode       = "classic",
      target     = "target",
      attackerIp = "127.0.0.1",
      attackerPort = "4444",
    } = req;

    if (!cmd.trim()) {
      send(ws, { type: "error", message: "cmd is required" });
      ws.close();
      return;
    }

    const processed = applyQuantumBypass(cmd, mode, attackerIp, attackerPort);
    const start = Date.now();
    const [lang] = engine.split("/");

    let spawnConfig: { file: string; args: string[] };

    const descriptor = buildSpawnTarget(processed, engine);
    if (descriptor.precompile) {
      try {
        spawnConfig = descriptor.precompile();
      } catch {
        send(ws, { type: "data", chunk: `[${lang.toUpperCase()} compiler unavailable — shell fallback]\n` });
        spawnConfig = { file: "/bin/bash", args: ["-c", processed] };
      }
    } else {
      spawnConfig = { file: descriptor.file, args: descriptor.args };
    }

    logger.info({ engine, mode, target }, "ws/exec");

    const runSpawn = (file: string, args: string[]) => {
      const child = spawn(file, args, {
        env: { ...process.env, TERM: "xterm-256color", PYTHONUNBUFFERED: "1" },
        detached: false,
      });

      child.stdout.on("data", (chunk: Buffer) => {
        send(ws, { type: "data", chunk: chunk.toString("utf8") });
      });

      child.stderr.on("data", (chunk: Buffer) => {
        send(ws, { type: "data", chunk: chunk.toString("utf8") });
      });

      const killTimer = setTimeout(() => {
        try { child.kill("SIGTERM"); } catch { /* already dead */ }
        send(ws, { type: "data", chunk: "\n[TIMEOUT — 30s]\n" });
      }, 30000);

      child.on("close", (code) => {
        clearTimeout(killTimer);
        const elapsed = Date.now() - start;
        logInjection(cmd, engine, mode, elapsed);
        send(ws, { type: "end", code: code ?? -1, elapsed });
        if (ws.readyState === 1) ws.close();
      });

      child.on("error", (err: NodeJS.ErrnoException) => {
        clearTimeout(killTimer);
        if (err.code === "ENOENT") {
          send(ws, { type: "data", chunk: `[${file}: not found — shell fallback]\n` });
          runSpawn("/bin/bash", ["-c", processed]);
        } else {
          send(ws, { type: "error", message: err.message });
          logInjection(cmd, engine, mode, Date.now() - start);
          if (ws.readyState === 1) ws.close();
        }
      });

      ws.on("close", () => {
        clearTimeout(killTimer);
        try { child.kill("SIGTERM"); } catch { /* already dead */ }
      });
    };

    runSpawn(spawnConfig.file, spawnConfig.args);
  });
}
