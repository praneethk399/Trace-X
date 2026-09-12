# TraceX — Cyber Financial Forensics Console

Real-time fraud detection, transaction risk scoring, mule-account detection,
graph intelligence, and AI risk explanations — backed by a parallelized
Node/Express API and Supabase persistence.

## Architecture

```
Browser (React + Vite)
  │  auth: Supabase Auth (email/password + Google OAuth)
  │  data: /api/* → proxied to the local backend
  ▼
Express API server (server/index.ts)
  ├─ parallel.ts      worker-thread pool + bounded-concurrency task pool
  ├─ analysisWorker.ts  runs mule detection / pipeline scoring / graph analysis off the loop
  ├─ supabase.ts      PostgREST client — persists alerts, detections, cases, streams
  ├─ ai.ts            Gemini risk explanations (deterministic fallback)
  └─ src/engines/*    the forensic engines (shared with the frontend seed data)
  ▼
Supabase (https://dtrgsngsgklzqibchqpn.supabase.co)
  └─ tracex_entities / tracex_transactions / tracex_alerts /
     tracex_detected_transactions / tracex_cases / tracex_case_activity /
     tracex_stream_events
```

**Parallel processing** (`server/parallel.ts`):
- `ParallelWorkerPool` — one worker thread per core (capped at 8) runs the
  CPU-heavy engines (`muleDetection`, `transactionPipeline`,
  `graphIntelligence`) so the event loop stays responsive.
- `parallelMap` — bounded-concurrency pool for I/O-shaped work (Supabase
  batched upserts, fan-out fetches) with per-item error capture.
- `runAnalysisPipeline` — partitions edges into batches and accounts into
  chunks, fans all three analysis phases out concurrently, then merges.
- `parallelFetch` — concurrent Supabase table reads for `/api/network/with-persisted`.

## Setup

```bash
npm install

# 1) Provision the database (once):
#    paste supabase/schema.sql into the Supabase SQL editor and run it.

# 2) Configure env (optional — defaults are embedded):
cp .env.example .env
#    add GEMINI_API_KEY for AI explanations (otherwise deterministic fallback)

# 3) Seed Supabase from the canonical dataset:
npm run server &
curl -X POST http://localhost:8787/api/admin/seed

# 4) Run backend + frontend together:
npm run dev:all
#    API on :8787, Vite on :3000 (proxies /api)
```

## API surface

| Route | Method | Description |
|---|---|---|
| `/api/health` | GET | status, worker count, mode |
| `/api/network` | GET | nodes + edges + case files + stats |
| `/api/network/with-persisted` | GET | network + parallel Supabase reads |
| `/api/network/filter` | POST | filter graph by risk/type/search |
| `/api/network/trace?source&destination` | GET | BFS fund-trace between entities |
| `/api/analyze` | POST | full parallel analysis (workers + timing) |
| `/api/analyze/tx` | POST | score one transaction (alerts + AI explanation) |
| `/api/report/:txId` | GET | investigation report for a flagged txn |
| `/api/cases` | GET | case files |
| `/api/cases/from-alert` | POST | open a case from an alert (mule analysis) |
| `/api/stream/events` | GET | next N live events (polling) |
| `/api/stream/sse` | GET | Server-Sent Events live feed |
| `/api/stream/start` / `stop` | POST | control the broadcast loop |
| `/api/admin/seed` | POST | upsert seed data into Supabase |

## Graceful degradation

The frontend works in three modes, shown live in the console footer:
1. **Backend online** — full features, parallel analysis, Supabase persistence.
2. **Supabase direct** — server unreachable: read-only against Supabase REST.
3. **Offline seed** — neither reachable: renders the deterministic seed dataset.
