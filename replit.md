# NEXUSFORGE

A command injection laboratory for security researchers — fire payloads through 13 engine variants (Node, Bash, Python, PHP, Java, C++, PowerShell) with real execution, live logs, and AI-generated payload suggestions.

## Run & Operate

- `pnpm --filter @workspace/api-server run dev` — run the API server (port 8080)
- `pnpm --filter @workspace/nexus run dev` — run the frontend (port 18245)
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- API: Express 5
- DB: PostgreSQL + Drizzle ORM (available, not yet used — logs stored as JSON)
- Validation: Zod (`zod/v4`), `drizzle-zod`
- API codegen: Orval (from OpenAPI spec)
- Frontend: React 19 + Vite + Tailwind CSS v4
- Build: esbuild (CJS bundle)

## Where things live

- `lib/api-spec/openapi.yaml` — OpenAPI contract (source of truth)
- `lib/api-client-react/src/generated/` — generated React Query hooks
- `lib/api-zod/src/generated/` — generated Zod schemas
- `artifacts/api-server/src/routes/` — Express route handlers
- `artifacts/api-server/src/engines/` — language engine implementations (bash, node, python, php, java, cpp, powershell)
- `artifacts/api-server/src/lib/` — bypassEngine, payloadAI, injectionLogger
- `artifacts/nexus/src/components/` — React components (LockScreen, MainLab)
- `artifacts/nexus/src/index.css` — dark hacker theme (CSS custom properties)

## Architecture decisions

- Backend lives entirely in `artifacts/api-server` (Express 5, TypeScript, esbuild)
- Injection logs written to `injection_logs.json` at process CWD (not DB) for fast I/O
- Engines degrade gracefully — if the runtime (php, java, gcc) is not installed, engine falls back to shell exec with a label, never crashes
- Frontend proxy: Vite dev server proxies `/api` → `localhost:80` (shared Replit reverse proxy routes `/api` to api-server)
- Password gate uses `sessionStorage` — survives page refresh within the same tab, clears on tab close

## Product

- Password-protected entry gate (`omowoli12345@`)
- 13 injection engines across 7 languages
- 4 injection modes: classic, blind, oob, quantum
- Real-time execution via POST /api/hub/exec
- Live injection log table (polled every 3s)
- AI payload suggestions per mode
- Reverse shell arsenal (copy-to-clipboard)
- Payload library (Basic, Chained, Bypass, Blind/OOB)
- Session analytics (total, blind, oob, quantum counters)
- Score counter (+25 per inject, +55 bonus for slow responses)
- Adaptive layout: mobile (stacked), tablet (2-col), desktop (sidebar + main)

## User preferences

- No emojis in UI
- No placeholder data, no fake code, no comments
- Password: omowoli12345@

## Gotchas

- Always run `pnpm --filter @workspace/api-spec run codegen` after changing `lib/api-spec/openapi.yaml`
- Injection logs file path is relative to `process.cwd()` (workspace root when running via pnpm)
- The api-server `dev` script rebuilds before starting — use `pnpm run build && pnpm run start` if you need separate steps
- For Render deploy: frontend build needs `BASE_PATH=/` and workspace-level `pnpm install` to resolve workspace deps

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
