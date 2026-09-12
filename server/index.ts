/**
 * TraceX — API Server
 * ===================
 * Express backend that fronts the forensic engines. Highlights:
 *  - Parallel analysis via worker-thread pool + bounded-concurrency pools
 *  - Supabase persistence for alerts, detections, cases, and stream events
 *  - Server-Sent Events live transaction stream (the ~60s fraud-detection cycle)
 *  - AI risk explanations (Gemini) with deterministic fallback
 *
 * Run: `npm run server` (tsx) or `npm run build:server && node dist-server/index.js`
 *
 * @license Apache-2.0
 */

import express, { Request, Response } from 'express';
import http from 'node:http';

import {
  EntityNode,
  TransactionEdge,
  StreamEvent,
  DetectedSuspiciousTransaction,
  RiskLevel,
  TransactionType,
} from '../src/types/forensics';
import {
  ENTITY_NODES,
  TRANSACTION_EDGES,
  CASE_FILES,
  formatINR,
} from '../src/data/mockForensics';
import {
  processTransaction,
  PipelineResult,
  Alert,
} from '../src/engines/transactionPipeline';
import { analyzeTransactionForMule } from '../src/engines/muleDetection';
import { calculateTracePath, applyFilters } from '../src/engines/graphEngine';
import { generateInvestigationReport } from '../src/engines/detectionEngine';
import {
  generateNormalTransaction,
  buildSuspiciousScenario,
} from '../src/engines/liveStreamEngine';
import {
  analysisPool,
  runAnalysisPipeline,
  NetworkAnalysisSummary,
  parallelMap,
  parallelFetch,
} from './parallel';
import {
  supabase,
  supabaseConfig,
  TABLES,
  Row,
} from './supabase';
import { explainRisk, aiAvailable, buildDetectedFromPipeline } from './ai';

// ============================================================================
// APP STATE — in-memory network + optional Supabase overlay
// ============================================================================

interface AppState {
  nodes: EntityNode[];
  edges: TransactionEdge[];
  alerts: Alert[];
  detected: DetectedSuspiciousTransaction[];
  lastAnalysis: NetworkAnalysisSummary | null;
  streamSeq: number;
  streamTimer: NodeJS.Timeout | null;
  sseClients: Set<Response>;
  scenarioArmed: string | null;
  demoRunIndex: number;
}

const state: AppState = {
  nodes: [...ENTITY_NODES],
  edges: [...TRANSACTION_EDGES],
  alerts: [],
  detected: [],
  lastAnalysis: null,
  streamSeq: 0,
  streamTimer: null,
  sseClients: new Set(),
  scenarioArmed: null,
  demoRunIndex: 0,
};

// ============================================================================
// EXPRESS SETUP
// ============================================================================

const app = express();
app.use(express.json({ limit: '2mb' }));

// CORS — permissive for local dev; the Vite dev server proxies /api anyway.
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, apikey');
  if (req.method === 'OPTIONS') {
    res.sendStatus(204);
    return;
  }
  next();
});

// Optional bearer token passthrough — used when the frontend forwards its
// Supabase session so RLS-protected reads/writes run as the signed-in user.
function tokenOf(req: Request): string | null {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return null;
  const token = header.slice(7);
  // The frontend never sends the publishable key as a bearer token; if it does,
  // treat it as anonymous rather than as a user session.
  return token === supabaseConfig.publishableKey ? null : token;
}

// ============================================================================
// HELPERS
// ============================================================================

function ok<T>(res: Response, data: T, meta: Record<string, unknown> = {}): void {
  res.json({ ok: true, data, ...meta });
}

function fail(res: Response, status: number, error: string, details?: unknown): void {
  res.status(status).json({ ok: false, error, details });
}

const TX_TYPES: TransactionType[] = ['UPI', 'IMPS', 'NEFT', 'RTGS', 'CARD'];

function makeEdge(tx: {
  source: string;
  target: string;
  type: TransactionType;
  amount: number;
  timestamp: string;
  risk?: RiskLevel;
  flowStatus?: TransactionEdge['flowStatus'];
  note?: string;
  suspiciousPattern?: string;
  hash?: string;
}): TransactionEdge {
  return {
    id: `TXN-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(16).slice(2, 6).toUpperCase()}`,
    source: tx.source,
    target: tx.target,
    type: tx.type,
    amount: tx.amount,
    formattedAmount: formatINR(tx.amount),
    timestamp: tx.timestamp,
    risk: tx.risk ?? 'LOW',
    flowStatus: tx.flowStatus ?? 'SETTLED',
    hash: tx.hash ?? `0x${Math.random().toString(16).slice(2, 10)}`,
    note: tx.note,
    suspiciousPattern: tx.suspiciousPattern,
  };
}

/** Extract labels + a one-hop trace path for a transaction. */
function txContext(edge: TransactionEdge): { sourceLabel?: string; targetLabel?: string; tracePath: string[] } {
  const nodeMap = new Map(state.nodes.map(n => [n.id, n]));
  const src = nodeMap.get(edge.source);
  const tgt = nodeMap.get(edge.target);
  const nextHop = state.edges.find(e => e.source === edge.target && e.target !== edge.source);
  return {
    sourceLabel: src?.label,
    targetLabel: tgt?.label,
    tracePath: nextHop ? [edge.source, edge.target, nextHop.target] : [edge.source, edge.target],
  };
}

// ============================================================================
// CORE ROUTES
// ============================================================================

app.get('/api/health', (_req, res) => {
  ok(res, {
    status: 'online',
    uptimeSec: Math.round(process.uptime()),
    workers: analysisPool.size,
    ai: aiAvailable() ? 'gemini' : 'fallback',
    supabase: supabaseConfig.url,
    network: { nodes: state.nodes.length, edges: state.edges.length },
    stream: {
      running: state.streamTimer !== null,
      clients: state.sseClients.size,
      totalGenerated: state.streamSeq,
    },
  });
});

// ---------------------------------------------------------------------------
// Network snapshot + query
// ---------------------------------------------------------------------------

app.get('/api/network', (_req, res) => {
  ok(res, {
    nodes: state.nodes,
    edges: state.edges,
    cases: CASE_FILES,
    stats: {
      totalNodes: state.nodes.length,
      totalEdges: state.edges.length,
      totalVolume: state.edges.reduce((s, e) => s + e.amount, 0),
      flagged: state.edges.filter(e => e.flowStatus === 'FLAGGED').length,
      criticalAccounts: state.nodes.filter(n => n.risk === 'CRITICAL').length,
    },
  });
});

/**
 * Parallel read endpoint — fetches several Supabase tables concurrently and
 * merges them with the in-memory seed. Demonstrates bounded-concurrency I/O.
 */
app.get('/api/network/with-persisted', async (req, res) => {
  const accessToken = tokenOf(req);
  const { data, errors, durationMs } = await parallelFetch<Row[]>({
    accounts: () => supabase.selectRows(TABLES.entities, { limit: 500, accessToken }).then(r => r.data ?? []),
    transactions: () => supabase.selectRows(TABLES.transactions, { limit: 1000, accessToken }).then(r => r.data ?? []),
    alerts: () => supabase.selectRows(TABLES.alerts, { limit: 100, accessToken }).then(r => r.data ?? []),
    cases: () => supabase.selectRows(TABLES.cases, { limit: 100, accessToken }).then(r => r.data ?? []),
    riskEvents: () => supabase.selectRows(TABLES.detected, { limit: 200, accessToken }).then(r => r.data ?? []),
  }, 5);

  ok(res, {
    nodes: state.nodes,
    edges: state.edges,
    persisted: data,
    errors,
    io: { durationMs: Math.round(durationMs), concurrency: 5 },
  });
});

/** Filter endpoint — reuses the engine's filter logic. */
app.post('/api/network/filter', (req, res) => {
  const filters = req.body ?? {};
  const { filteredNodes, filteredEdges } = applyFilters(state.nodes, state.edges, filters);
  ok(res, { nodes: filteredNodes, edges: filteredEdges });
});

/** Path trace between two entities (BFS through the transaction graph). */
app.get('/api/network/trace', (req, res) => {
  const sourceId = String(req.query.source ?? '');
  const destinationId = String(req.query.destination ?? '');
  if (!sourceId || !destinationId) return fail(res, 400, 'source and destination query params are required');
  const result = calculateTracePath(sourceId, destinationId, state.nodes, state.edges);
  if (!result) return fail(res, 404, `No path found between ${sourceId} and ${destinationId}`);
  ok(res, result);
});

// ---------------------------------------------------------------------------
// Analysis endpoints (parallel, worker-backed)
// ---------------------------------------------------------------------------

/** Full parallel analysis of the current network. */
app.post('/api/analyze', async (_req, res) => {
  try {
    const summary = await runAnalysisPipeline(state.nodes, state.edges);
    state.lastAnalysis = summary;
    ok(res, summary);
  } catch (e) {
    fail(res, 500, `Analysis failed: ${(e as Error).message}`);
  }
});

/** Last cached analysis result (no recompute). */
app.get('/api/analyze/last', (_req, res) => {
  ok(res, state.lastAnalysis);
});

/**
 * Score a single submitted transaction through the full pipeline.
 * Body: { source, target, type, amount, timestamp?, note? }
 */
app.post('/api/analyze/tx', async (req, res) => {
  const body = req.body ?? {};
  if (!body.source || !body.target || !body.amount || !body.type) {
    return fail(res, 400, 'source, target, amount, and type are required');
  }
  if (!TX_TYPES.includes(body.type)) return fail(res, 400, `type must be one of ${TX_TYPES.join(', ')}`);

  const now = new Date();
  const timestamp = body.timestamp ?? now.toTimeString().slice(0, 8);

  const edge = makeEdge({
    source: String(body.source),
    target: String(body.target),
    type: body.type as TransactionType,
    amount: Number(body.amount),
    timestamp,
    note: body.note,
  });

  // Unknown accounts get a stub node so the pipeline can score them.
  const knownIds = new Set(state.nodes.map(n => n.id));
  const stubs: EntityNode[] = [edge.source, edge.target]
    .filter(id => !knownIds.has(id))
    .map((id, i) => ({
      id,
      nodeNumber: 900 + i,
      label: `${id} (Unregistered)`,
      type: 'ACCOUNT' as const,
      risk: 'LOW' as RiskLevel,
      riskScore: 20,
      status: 'NORMAL' as const,
      transactionCount: 1,
      inflow: 0,
      outflow: 0,
      balance: 0,
      firstSeen: now.toISOString(),
      lastActivity: now.toISOString(),
      clusterId: 'CL-UNKNOWN',
      clusterName: 'Unregistered Entities',
      x: 0,
      y: 0,
      riskIndicators: [],
      tags: [],
    }));

  const nodes = [...state.nodes, ...stubs];
  const result = processTransaction(edge, state.edges, nodes);
  const context = txContext(edge);

  // Persist alerts + detected record to Supabase (fire-and-forget).
  const detected = buildDetectedFromPipeline(result, context);
  const persistPromise = Promise.all([
    supabase.saveAlerts(result.alerts),
    result.risk !== 'LOW'
      ? supabase.saveDetectedTransactions([detectedToRow(detected)])
      : Promise.resolve({ saved: 0, error: null }),
  ]);

  // AI explanation (non-blocking; falls back deterministically).
  const aiPromise = result.risk !== 'LOW' ? explainRisk(detected) : Promise.resolve(null);

  const [, ai] = await Promise.all([persistPromise.catch(() => null), aiPromise.catch(() => null)]);

  state.edges.push(edge);
  state.detected.unshift(detected);
  state.alerts.unshift(...result.alerts);

  ok(res, {
    result: {
      transactionId: result.transactionId,
      risk: result.risk,
      riskScore: result.riskScore,
      confidenceScore: result.confidenceScore,
      detectedPatterns: result.detectedPatterns,
      signals: result.signals,
      alerts: result.alerts,
      processingTimeMs: result.processingTimeMs,
      isValid: result.isValid,
      validationErrors: result.validationErrors,
    },
    detected,
    aiExplanation: ai?.text ?? detected.aiExplanation,
    aiSource: ai?.source ?? 'fallback',
  });
});

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

app.get('/api/report/:txId', async (req, res) => {
  const txId = req.params.txId;
  const detected = state.detected.find(d => d.transactionId === txId)
    ?? state.detected[0];
  if (!detected) return fail(res, 404, `No detected transaction for ${txId}`);

  const report = generateInvestigationReport(detected);
  const ai = await explainRisk(detected);
  ok(res, { report, aiExplanation: ai.text, aiSource: ai.source });
});

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

app.get('/api/cases', (_req, res) => {
  ok(res, { cases: CASE_FILES, count: CASE_FILES.length });
});

app.post('/api/cases/from-alert', async (req, res) => {
  const body = req.body ?? {};
  if (!body.transactionId && !body.accountId) {
    return fail(res, 400, 'transactionId or accountId is required');
  }

  const accountId: string | undefined = body.accountId
    ?? state.edges.find(e => e.id === body.transactionId)?.source;
  if (!accountId) return fail(res, 404, 'Could not resolve an account for this alert');

  const analysis = analyzeTransactionForMule(
    state.edges.find(e => e.id === body.transactionId) ?? state.edges[0],
    state.edges,
    state.nodes
  );
  const mule = analysis.sourceAnalysis.accountId === accountId
    ? analysis.sourceAnalysis
    : analysis.targetAnalysis;

  const caseRow: Row = {
    title: body.title ?? `Investigation: ${accountId}`,
    status: 'new',
    priority: mule.investigationPriority.toLowerCase(),
    assigned_to: String(body.analyst ?? 'TraceX Engine'),
    notes: `Mule analysis: risk ${mule.riskScore}/100 (${mule.riskLevel}), confidence ${mule.confidenceScore}%, patterns: ${mule.detectedPatterns.map(p => p.type).join(', ') || 'none'}`,
    created_at: new Date().toISOString(),
  };

  const { saved, error } = await supabase.saveCase(caseRow);
  if (error || !saved) {
    // Non-fatal: writes may be disabled (no service key) — return the case anyway.
    ok(res, { case: caseRow, persisted: false, persistError: error?.message ?? 'not saved' });
    return;
  }
  ok(res, { case: caseRow, persisted: true });
});

// ---------------------------------------------------------------------------
// Live stream (polling + SSE)
// ---------------------------------------------------------------------------

function nextStreamEvents(count: number): StreamEvent[] {
  const events: StreamEvent[] = [];

  // ~25% of ticks escalate to the scripted fraud scenario (~60s cycle).
  const useScenario = state.scenarioArmed && Math.random() < 0.25;
  if (useScenario) {
    state.demoRunIndex++;
    const { streamEvent } = buildSuspiciousScenario(
      state.demoRunIndex,
      state.streamSeq++,
      state.nodes,
      state.edges
    );
    events.push(streamEvent);
  }

  while (events.length < count) {
    events.push(generateNormalTransaction(state.streamSeq++));
  }
  return events;
}

app.get('/api/stream/events', (req, res) => {
  const count = Math.min(20, Math.max(1, Number(req.query.count) || 5));
  const events = nextStreamEvents(count);

  // Persist stream events + any detections to Supabase (fire-and-forget).
  void supabase.saveStreamEvents(events.map(e => streamEventToRow(e)));
  const detectedEvents = events.filter(e => e.detected);
  if (detectedEvents.length) {
    void supabase.saveDetectedTransactions(
      detectedEvents.map(e => ({
        transaction_id: e.id,
        timestamp: e.time,
        source: e.source,
        target: e.target,
        amount: e.numericAmount,
        type: e.type,
        risk_level: e.risk,
        risk_score: e.riskScore,
        signals: e.detectionSignals ?? [],
        created_at: new Date().toISOString(),
      }))
    );
  }

  ok(res, { events, seq: state.streamSeq });
});

/** Server-Sent Events stream — the frontend's real-time channel. */
app.get('/api/stream/sse', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.write(`retry: 3000\n\n`);

  state.sseClients.add(res);
  const heartbeat = setInterval(() => {
    try { res.write(':hb\n\n'); } catch { /* closed */ }
  }, 15000);

  req.on('close', () => {
    clearInterval(heartbeat);
    state.sseClients.delete(res);
  });
});

function broadcast(events: StreamEvent[]): void {
  if (state.sseClients.size === 0) return;
  const payload = `data: ${JSON.stringify({ events })}\n\n`;
  for (const client of state.sseClients) {
    try { client.write(payload); } catch { /* client gone */ }
  }
}

app.post('/api/stream/start', (req, res) => {
  const intervalMs = Math.min(10_000, Math.max(500, Number(req.body?.intervalMs) || 2000));
  if (state.streamTimer) clearInterval(state.streamTimer);

  state.streamTimer = setInterval(() => {
    const events = nextStreamEvents(3);
    state.streamSeq += events.length;
    broadcast(events);
  }, intervalMs);

  ok(res, { running: true, intervalMs, clients: state.sseClients.size });
});

app.post('/api/stream/stop', (_req, res) => {
  if (state.streamTimer) {
    clearInterval(state.streamTimer);
    state.streamTimer = null;
  }
  ok(res, { running: false });
});

/** Arms the fraud scenario injection (see liveStreamEngine scenarios). */
app.post('/api/stream/scenario', (req, res) => {
  const scenario = String(req.body?.scenario ?? '');
  state.scenarioArmed = scenario || null;
  ok(res, { scenarioArmed: state.scenarioArmed });
});

// ---------------------------------------------------------------------------
// Admin: seed + sync
// ---------------------------------------------------------------------------

/** One-shot seed of the Supabase tables from the in-memory dataset. */
app.post('/api/admin/seed', async (req, res) => {
  const accounts: Row[] = state.nodes.map(n => ({
    id: n.id,
    label: n.label,
    type: n.type,
    risk: n.risk,
    risk_score: n.riskScore,
    status: String(n.status).toLowerCase(),
    transaction_count: n.transactionCount,
    inflow: n.inflow,
    outflow: n.outflow,
    balance: n.balance,
    first_seen: n.firstSeen,
    last_activity: n.lastActivity,
    cluster_id: n.clusterId,
    cluster_name: n.clusterName,
    x: n.x,
    y: n.y,
    risk_indicators: n.riskIndicators,
    tags: n.tags,
    bank_name: n.bankName ?? null,
    jurisdiction: n.jurisdiction ?? null,
    ip_address: n.ipAddress ?? null,
    device_fingerprint: n.deviceFingerprint ?? null,
    account_holder: n.accountHolder ?? null,
  }));

  const transactions: Row[] = state.edges.map(e => ({
    id: e.id,
    source: e.source,
    target: e.target,
    type: e.type,
    amount: e.amount,
    formatted_amount: e.formattedAmount,
    timestamp: e.timestamp,
    risk: e.risk,
    flow_status: e.flowStatus,
    hash: e.hash,
    note: e.note ?? null,
    suspicious_pattern: e.suspiciousPattern ?? null,
  }));

  const cases: Row[] = CASE_FILES.map(c => ({
    id: c.id,
    title: c.title,
    status: String(c.status).toLowerCase(),
    priority: String(c.priority).toLowerCase(),
    assigned_to: c.analyst,
    notes: c.summary,
    opened_at: c.openedAt,
  }));

  const result = await supabase.seedDatabase({ accounts, transactions, cases });
  if (!result.writesEnabled) {
    return fail(res, 503, 'Writes disabled — set SUPABASE_SERVICE_ROLE_KEY in .env to enable persistence', result);
  }
  const failures = result.results.filter(r => r.error);
  if (failures.length) {
    return fail(res, 502, 'Seed partially failed', result);
  }
  ok(res, result);
});

// ============================================================================
// ROW MAPPERS (engine types → Supabase rows)
// ============================================================================

function detectedToRow(d: DetectedSuspiciousTransaction): Row {
  return {
    transaction_id: d.transactionId,
    source: d.source,
    type: d.type,
    risk_level: d.riskLevel,
    risk_score: d.fraudRiskScore,
    ai_explanation: d.aiExplanation,
  };
}

function streamEventToRow(e: StreamEvent): Row {
  return {
    event_id: e.id,
    source: e.source,
    target: e.target,
    type: e.type,
    risk: e.risk,
    risk_score: e.riskScore,
    status: e.status,
    formatted_amount: e.amount,
    detected: Boolean(e.detected),
  };
}

// ============================================================================
// BOOT
// ============================================================================

export const server = http.createServer(app);

if (process.env.TRACEX_NO_LISTEN !== '1') {
  const PORT = Number(process.env.PORT || 8787);
  server.listen(PORT, () => {
    console.log(`[TraceX] API server on http://localhost:${PORT}`);
    console.log(`[TraceX] Workers: ${analysisPool.size} | AI: ${aiAvailable() ? 'Gemini' : 'deterministic fallback'} | Supabase: ${supabaseConfig.url}`);
  });
}

// Graceful shutdown — dispose the worker pool so no threads leak.
for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.on(sig, () => {
    analysisPool.dispose();
    server.close(() => process.exit(0));
  });
}
