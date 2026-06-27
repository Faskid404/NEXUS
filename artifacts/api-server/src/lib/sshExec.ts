import { Client, type ConnectConfig } from "ssh2";

export interface SshOptions {
  host:        string;
  port:        number;
  username:    string;
  password?:   string;
  privateKey?: string;
  timeoutMs?:  number;
}

function buildConnectConfig(opts: SshOptions): ConnectConfig {
  const cfg: ConnectConfig = {
    host:                     opts.host,
    port:                     opts.port || 22,
    username:                 opts.username,
    readyTimeout:             opts.timeoutMs ?? 12_000,
    algorithms: {
      kex: [
        "curve25519-sha256", "curve25519-sha256@libssh.org",
        "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
        "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group14-sha256",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group1-sha1",
      ],
      serverHostKey: [
        "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521", "rsa-sha2-512", "rsa-sha2-256",
        "ssh-rsa", "ssh-dss",
      ],
    },
  };
  if (opts.password)   cfg.password   = opts.password;
  if (opts.privateKey) cfg.privateKey  = Buffer.from(opts.privateKey, "utf8");
  return cfg;
}

/**
 * Execute a command on a remote host via SSH.
 * Promise-based — for REST endpoints.
 */
export async function sshExec(
  opts: SshOptions,
  cmd:  string,
): Promise<{ output: string; exitCode: number; elapsed: number }> {
  return new Promise((resolve, reject) => {
    const conn   = new Client();
    const t0     = Date.now();
    let   output = "";
    let   settled = false;

    const settle = (fn: () => void) => {
      if (!settled) { settled = true; try { conn.end(); } catch { /* ignore */ } fn(); }
    };

    conn.on("ready", () => {
      conn.exec(cmd, (err, stream) => {
        if (err) { settle(() => reject(err)); return; }
        stream.on("data",        (d: Buffer) => { output += d.toString("utf8"); });
        stream.stderr.on("data", (d: Buffer) => { output += d.toString("utf8"); });
        stream.on("close", (code: number | null) => {
          settle(() => resolve({ output, exitCode: code ?? -1, elapsed: Date.now() - t0 }));
        });
      });
    });

    conn.on("error", (err: Error) => settle(() => reject(err)));
    conn.connect(buildConnectConfig(opts));
  });
}

/**
 * Stream command output from a remote host via SSH.
 * Callback-based — for WebSocket streaming handlers.
 * Returns a teardown function to close the connection.
 */
export function sshStreamExec(
  opts:    SshOptions,
  cmd:     string,
  onData:  (chunk: string) => void,
  onClose: (code: number | null, elapsed: number) => void,
  onError: (err: Error) => void,
): () => void {
  const conn  = new Client();
  const t0    = Date.now();
  let   ended = false;

  const teardown = () => {
    if (!ended) { ended = true; try { conn.end(); } catch { /* ignore */ } }
  };

  conn.on("ready", () => {
    conn.exec(cmd, (err, stream) => {
      if (err) { teardown(); onError(err); return; }
      stream.on("data",        (d: Buffer) => onData(d.toString("utf8")));
      stream.stderr.on("data", (d: Buffer) => onData(d.toString("utf8")));
      stream.on("close", (code: number | null) => {
        teardown();
        onClose(code, Date.now() - t0);
      });
    });
  });

  conn.on("error", (err: Error) => { teardown(); onError(err); });
  conn.connect(buildConnectConfig(opts));

  return teardown;
}

export function buildSshJumpChain(
  jumps: Array<{host:string;port:number;user:string;password?:string;key?:string}>,
  finalCmd: string,
  onData: (chunk:string)=>void,
  onClose: (code:number|null, elapsed:number)=>void,
  onError: (err:Error)=>void,
): ()=>void {
  const t0 = Date.now();
  let ended = false;
  const clients: InstanceType<typeof Client>[] = [];
  const teardown = () => {
    if (!ended) { ended = true; for (const c of clients.reverse()) { try { c.end(); } catch {} } }
  };
  function connectJump(idx: number, stream: NodeJS.ReadWriteStream | null): void {
    const hop = jumps[idx]!;
    const conn = new Client();
    clients.push(conn);
    const cfg: import("ssh2").ConnectConfig = {
      host: hop.host, port: hop.port, username: hop.user,
      password: hop.password, privateKey: hop.key,
      readyTimeout: 8000, keepaliveInterval: 5000,
      sock: (stream as import("stream").Readable | null) ?? undefined,
    };
    conn.on("ready", () => {
      if (idx < jumps.length - 1) {
        const nextHop = jumps[idx + 1]!;
        conn.forwardOut("127.0.0.1", 0, nextHop.host, nextHop.port, (err, fwdStream) => {
          if (err) { teardown(); onError(err); return; }
          connectJump(idx + 1, fwdStream);
        });
      } else {
        conn.exec(finalCmd, (err, s) => {
          if (err) { teardown(); onError(err); return; }
          s.on("data", (d: Buffer) => onData(d.toString("utf8")));
          s.stderr.on("data", (d: Buffer) => onData(d.toString("utf8")));
          s.on("close", (code: number | null) => { teardown(); onClose(code, Date.now() - t0); });
        });
      }
    });
    conn.on("error", (err: Error) => { teardown(); onError(err); });
    conn.connect(cfg);
  }
  connectJump(0, null);
  return teardown;
}

export function buildSocks5ProxyScript(socksHost: string, socksPort: number, targetHost: string, targetPort: number, command: string): string {
  return [`ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -D ${socksPort} -N -f ${socksHost} &`,`BGPID=$!`,`sleep 1`,`proxychains4 -q ssh -o StrictHostKeyChecking=no -p ${targetPort} ${targetHost} "${command}"`,`kill $BGPID 2>/dev/null`].join("\n");
}

export function buildLocalPortForwardScript(jumpHost: string, jumpPort: number, jumpUser: string, remoteHost: string, remotePort: number, localPort: number): string {
  return `ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -N -L ${localPort}:${remoteHost}:${remotePort} -p ${jumpPort} ${jumpUser}@${jumpHost}`;
}

export function buildDynamicSocksCommand(jumpHost: string, jumpPort: number, jumpUser: string, localPort: number): string {
  return `ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -N -D ${localPort} -p ${jumpPort} ${jumpUser}@${jumpHost}`;
}

export function buildReversePortForward(lhost: string, lport: number, remotePort: number, targetHost: string, targetPort: number): string {
  return `ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -N -R ${lport}:${targetHost}:${targetPort} -p ${remotePort} root@${lhost}`;
}
