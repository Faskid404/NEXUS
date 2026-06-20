import { z } from "zod";

export const ScanRequestSchema = z.object({
  target:      z.string().min(1).max(512),
  ports:       z.array(z.number().int().min(1).max(65535)).optional(),
  timeout:     z.number().int().min(200).max(30_000).optional(),
  concurrency: z.number().int().min(1).max(256).optional(),
  adaptive:    z.boolean().optional(),
  jitter:      z.number().min(0).max(2000).optional(),
});

export const ExploitChainRequestSchema = z.object({
  target:      z.string().min(1).max(512),
  ports:       z.array(z.number().int().min(1).max(65535)).optional(),
  timeout:     z.number().int().min(200).max(30_000).optional(),
  lhost:       z.string().optional(),
  lport:       z.union([z.string(), z.number()]).optional(),
  skipServices:z.array(z.string()).optional(),
});

export const AutoExploitRequestSchema = z.object({
  targetUrl:       z.string().url(),
  injectParam:     z.string().min(1).max(256).optional(),
  httpMethod:      z.enum(["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"]).optional(),
  cmd:             z.string().max(1024).optional(),
  attackerIp:      z.string().max(128).optional(),
  attackerPort:    z.union([z.string(), z.number()]).optional(),
  oobToken:        z.string().max(64).optional(),
  oobCallbackBase: z.string().max(512).optional(),
  customHeaders:   z.string().max(2048).optional(),
  stopOnHit:       z.boolean().optional(),
  model:           z.string().optional(),
  maxRounds:       z.number().int().min(1).max(50).optional(),
  lhost:           z.string().optional(),
  lport:           z.union([z.string(), z.number()]).optional(),
  bypassProfile:   z.string().optional(),
});

export const MutationScannerRequestSchema = z.object({
  targetUrl:    z.string().url(),
  injectParam:  z.string().min(1).max(256),
  technique:    z.enum(["sqli","ssti","xss","cmdi","xxe","lfi","redirect"]).optional(),
  httpMethod:   z.enum(["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"]).optional(),
  generations:  z.number().int().min(1).max(200).optional(),
  popSize:      z.number().int().min(2).max(100).optional(),
  eliteRatio:   z.number().min(0).max(1).optional(),
  mutationRate: z.number().min(0).max(1).optional(),
  crossoverRate:z.number().min(0).max(1).optional(),
  timeout:      z.number().int().min(500).max(30_000).optional(),
  baseline:     z.string().optional(),
  extraParams:  z.string().max(1024).optional(),
  customHeaders:z.string().max(2048).optional(),
});

export const ChainReactorRequestSchema = z.object({
  chainId:   z.string().optional(),
  custom:    z.unknown().optional(),
  target:    z.string().min(1).max(512).optional(),
  lhost:     z.string().optional(),
  lport:     z.union([z.string(), z.number()]).optional(),
  extraVars: z.record(z.string()).optional(),
});

export const ChainReactorAbortSchema = z.object({
  type: z.literal("abort"),
});

export const C2RelayRequestSchema = z.object({
  c2Url:      z.string().url(),
  interval:   z.number().int().min(1000).max(300_000).optional(),
  xorKey:     z.number().int().min(0).max(255).optional(),
  maxRuns:    z.number().int().min(1).max(10_000).optional(),
  userAgent:  z.string().max(512).optional(),
  proxy:      z.string().optional(),
});

export const C2OperatorCommandSchema = z.object({
  session_id: z.string().max(128).optional(),
  cmd:        z.string().max(4096).optional(),
  args:       z.unknown().optional(),
  type:       z.string().max(64).optional(),
});

export const IronWormScanRequestSchema = z.object({
  packageName:    z.string().min(1).max(256).optional(),
  githubOrg:      z.string().min(1).max(128).optional(),
  githubRepo:     z.string().min(1).max(128).optional(),
  depConfusionOrg:z.string().min(1).max(128).optional(),
  cbHost:         z.string().max(256).optional(),
  cbPort:         z.union([z.string(), z.number()]).optional(),
  propagate:      z.boolean().optional(),
  targetCidr:     z.string().max(64).optional(),
}).refine(d => !!(d.packageName || d.githubOrg || d.depConfusionOrg), {
  message: "at least one of packageName, githubOrg, or depConfusionOrg is required",
});

export const ProbeTargetRequestSchema = z.object({
  url:       z.string().url(),
  scanPorts: z.boolean().optional(),
  ports:     z.array(z.number().int().min(1).max(65535)).optional(),
  sshBrute:  z.boolean().optional(),
});

export const PostExploitRequestSchema = z.object({
  sshHost:     z.string().min(1).max(512),
  sshPort:     z.number().int().min(1).max(65535).optional(),
  sshUser:     z.string().max(128).optional(),
  sshPassword: z.string().max(512).optional(),
  sshKey:      z.string().optional(),
  actions:     z.array(z.string().min(1).max(64)).min(1),
  timeoutMs:   z.number().int().min(1000).max(120_000).optional(),
});

export const StreamExecRequestSchema = z.object({
  cmd:           z.string().min(1).max(4096),
  engine:        z.string().optional(),
  mode:          z.string().optional(),
  injectionUrl:  z.string().optional(),
  injectParam:   z.string().optional(),
  httpMethod:    z.enum(["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"]).optional(),
  customHeaders: z.string().max(2048).optional(),
  attackerIp:    z.string().max(128).optional(),
  attackerPort:  z.string().max(10).optional(),
  sshHost:       z.string().max(512).optional(),
  sshPort:       z.number().int().min(1).max(65535).optional(),
  sshUser:       z.string().max(128).optional(),
  sshPassword:   z.string().max(512).optional(),
  sshKey:        z.string().optional(),
});

export const CveExploitRequestSchema = z.object({
  cveId:      z.string().min(1).max(64),
  mode:       z.enum(["probe","exploit","differential","ssh_probe","ftp_probe","erlang_ssh","shell"]),
  targetUrl:  z.string().optional(),
  targetHost: z.string().max(512).optional(),
  targetPort: z.number().int().min(1).max(65535).optional(),
}).passthrough();

export type ScanRequest            = z.infer<typeof ScanRequestSchema>;
export type ExploitChainRequest    = z.infer<typeof ExploitChainRequestSchema>;
export type AutoExploitRequest     = z.infer<typeof AutoExploitRequestSchema>;
export type MutationScanRequest    = z.infer<typeof MutationScannerRequestSchema>;
export type ChainReactorRequest    = z.infer<typeof ChainReactorRequestSchema>;
export type C2RelayRequest         = z.infer<typeof C2RelayRequestSchema>;
export type C2OperatorCommand      = z.infer<typeof C2OperatorCommandSchema>;
export type IronWormScanRequest    = z.infer<typeof IronWormScanRequestSchema>;
export type ProbeTargetRequest     = z.infer<typeof ProbeTargetRequestSchema>;
export type PostExploitRequest     = z.infer<typeof PostExploitRequestSchema>;
export type StreamExecRequest      = z.infer<typeof StreamExecRequestSchema>;
export type CveExploitRequest      = z.infer<typeof CveExploitRequestSchema>;
