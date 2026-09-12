/**
 * TraceX — Server-side Supabase client (REST, no SDK)
 * ===================================================
 * Two keys, two roles:
 *   - Publishable key: reads (RLS governs visibility) — safe anywhere.
 *   - Service-role key (SUPABASE_SERVICE_ROLE_KEY in .env): writes. The
 *     project's tables are insert/update-denied for client keys, so all
 *     persistence flows through this server. Without the secret the server
 *     still runs: persistence degrades to no-op with a surfaced reason.
 *
 * Reads with a user access token run under RLS as that user.
 *
 * @license Apache-2.0
 */

import { parallelMap } from './parallel';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://dtrgsngsgklzqibchqpn.supabase.co';
const SUPABASE_PUBLISHABLE_KEY = process.env.SUPABASE_PUBLISHABLE_KEY || 'sb_publishable_NpwSdNWaPzedmNhzoe2pdQ_Qo6uRHuS';
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

const REST_BASE = `${SUPABASE_URL}/rest/v1`;

export const supabaseConfig = {
  url: SUPABASE_URL,
  restBase: REST_BASE,
  publishableKey: SUPABASE_PUBLISHABLE_KEY,
  serviceKeyPresent: Boolean(SUPABASE_SERVICE_ROLE_KEY),
  canWrite: Boolean(SUPABASE_SERVICE_ROLE_KEY),
};

export interface RestError {
  message: string;
  status: number;
  details?: unknown;
}

export type Row = Record<string, unknown>;

// ---------------------------------------------------------------------------
// Low-level request helper
// ---------------------------------------------------------------------------

function headers(accessToken?: string | null, useServiceRole = false): Record<string, string> {
  if (useServiceRole && SUPABASE_SERVICE_ROLE_KEY) {
    return {
      'Content-Type': 'application/json',
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
    };
  }
  return {
    'Content-Type': 'application/json',
    apikey: SUPABASE_PUBLISHABLE_KEY,
    Authorization: `Bearer ${accessToken || SUPABASE_PUBLISHABLE_KEY}`,
  };
}

async function request<T>(
  method: string,
  path: string,
  options: {
    query?: Record<string, string>;
    body?: unknown;
    accessToken?: string | null;
    useServiceRole?: boolean;
    prefer?: string[];
  } = {}
): Promise<{ data: T | null; error: RestError | null }> {
  const url = new URL(path.startsWith('http') ? path : `${REST_BASE}/${path}`);
  for (const [k, v] of Object.entries(options.query ?? {})) url.searchParams.set(k, v);

  try {
    const res = await fetch(url, {
      method,
      headers: { ...headers(options.accessToken, options.useServiceRole), ...(options.prefer?.length ? { Prefer: options.prefer.join(',') } : {}) },
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
    });

    const text = await res.text();
    let body: unknown = null;
    try { body = text ? JSON.parse(text) : null; } catch { body = text; }

    if (!res.ok) {
      const err = body as { message?: string; msg?: string; error_description?: string; error?: string } | null;
      return {
        data: null,
        error: {
          message: String(err?.message || err?.msg || err?.error_description || err?.error || `HTTP ${res.status}`),
          status: res.status,
          details: body,
        },
      };
    }
    return { data: body as T, error: null };
  } catch (e) {
    return { data: null, error: { message: `Network error: ${(e as Error).message}`, status: 0 } };
  }
}

// ---------------------------------------------------------------------------
// Generic table helpers
// ---------------------------------------------------------------------------

export async function selectRows<T = Row>(
  table: string,
  params: {
    columns?: string;
    filters?: Record<string, string>;
    order?: string;
    ascending?: boolean;
    limit?: number;
    accessToken?: string | null;
  } = {}
): Promise<{ data: T[] | null; error: RestError | null }> {
  const query: Record<string, string> = {};
  if (params.columns) query.select = params.columns;
  for (const [k, v] of Object.entries(params.filters ?? {})) query[k] = `eq.${v}`;
  if (params.order) {
    query.order = params.order;
    query.ascending = String(params.ascending ?? false);
  }
  if (params.limit) query.limit = String(params.limit);
  return request<T[]>('GET', table, { query, accessToken: params.accessToken });
}

/** Write path — always uses the service-role key. No-ops when it's absent. */
export async function insertRows(
  table: string,
  rows: Row | Row[],
  opts: { upsert?: boolean; onConflict?: string; returnRepresentation?: boolean } = {}
): Promise<{ data: Row[] | null; error: RestError | null }> {
  if (!SUPABASE_SERVICE_ROLE_KEY) {
    return { data: null, error: { message: 'SUPABASE_SERVICE_ROLE_KEY not configured — writes disabled', status: 403 } };
  }
  if (!rows || (Array.isArray(rows) && rows.length === 0)) return { data: [], error: null };

  const prefer: string[] = [];
  if (opts.upsert) prefer.push('resolution=merge-duplicates');
  if (opts.onConflict) prefer.push(`on_conflict=${opts.onConflict}`);
  if (opts.returnRepresentation) prefer.push('return=representation');

  return request<Row[]>('POST', table, { body: rows, useServiceRole: true, prefer });
}

export async function updateRows(
  table: string,
  filters: Record<string, string>,
  patch: Row,
  opts: { accessToken?: string | null } = {}
): Promise<{ data: Row[] | null; error: RestError | null }> {
  if (!SUPABASE_SERVICE_ROLE_KEY) {
    return { data: null, error: { message: 'SUPABASE_SERVICE_ROLE_KEY not configured — writes disabled', status: 403 } };
  }
  const query: Record<string, string> = {};
  for (const [k, v] of Object.entries(filters)) query[k] = `eq.${v}`;
  return request<Row[]>('PATCH', table, { query, body: patch, useServiceRole: true, prefer: ['return=representation'] });
}

export async function deleteRows(
  table: string,
  filters: Record<string, string>,
  _opts: { accessToken?: string | null } = {}
): Promise<{ data: null; error: RestError | null }> {
  if (!SUPABASE_SERVICE_ROLE_KEY) {
    return { data: null, error: { message: 'SUPABASE_SERVICE_ROLE_KEY not configured — writes disabled', status: 403 } };
  }
  const query: Record<string, string> = {};
  for (const [k, v] of Object.entries(filters)) query[k] = `eq.${v}`;
  return request<null>('DELETE', table, { query, useServiceRole: true });
}

export async function rpcCall<T = unknown>(
  fn: string,
  args: Row,
  opts: { accessToken?: string | null } = {}
): Promise<{ data: T | null; error: RestError | null }> {
  return request<T>('POST', `rpc/${fn}`, { body: args, accessToken: opts.accessToken });
}

// ---------------------------------------------------------------------------
// Table names — matches the EXISTING Supabase project schema
// (discovered via PostgREST probes; see scripts/discoverSchema.mjs)
// ---------------------------------------------------------------------------

export const TABLES = {
  entities: 'accounts',
  transactions: 'transactions',
  alerts: 'alerts',
  detected: 'risk_events',
  cases: 'cases',
  caseActivity: 'case_annotations',
  reports: 'reports',
  audit: 'audit_logs',
  streamEvents: 'risk_events', // live stream events land in risk_events
} as const;

// ---------------------------------------------------------------------------
// Column maps: engine field → existing table column (snake_case)
// Confirmed readable via PostgREST probes; write-only columns are included
// where the name is conventional (insert will surface any mismatch).
// ---------------------------------------------------------------------------

export const COLUMNS = {
  transactions: {
    id: 'id',
    source: 'source',
    target: 'target',
    type: 'channel',
    amount: 'amount',
    currency: 'currency',
    status: 'status',
    risk: 'risk_level',
    riskScore: 'risk_score',
    timestamp: 'timestamp',
    hash: 'reference',
    note: 'note',
    pattern: 'pattern',
    createdAt: 'created_at',
  },
  alerts: {
    id: 'id',
    transactionId: 'transaction_id',
    accountId: 'account_id',
    severity: 'severity',
    type: 'alert_type',
    message: 'message',
    riskScore: 'risk_score',
    status: 'status',
    createdAt: 'created_at',
  },
  cases: {
    id: 'id',
    title: 'title',
    status: 'status',
    priority: 'priority',
    assignedTo: 'assigned_to',
    openedAt: 'opened_at',
    closedAt: 'closed_at',
    summary: 'notes',
    createdAt: 'created_at',
    updatedAt: 'updated_at',
  },
  riskEvents: {
    id: 'id',
    eventType: 'event_type',
    type: 'type',
    severity: 'severity',
    description: 'description',
    entityId: 'entity_id',
    accountId: 'account_id',
    transactionId: 'transaction_id',
    riskScore: 'risk_score',
    createdAt: 'created_at',
  },
} as const;

// ---------------------------------------------------------------------------
// Domain operations (parallel-friendly)
// ---------------------------------------------------------------------------

export async function saveAlerts(alerts: unknown[]): Promise<{ saved: number; error: RestError | null }> {
  if (!alerts.length) return { saved: 0, error: null };
  const rows = (alerts as Row[]).map(a => ({
    transaction_id: a.transactionId,
    account_id: a.accountId ?? null,
    alert_type: a.type,
    severity: String(a.severity ?? 'LOW').toLowerCase(),
    message: a.message,
    risk_score: a.riskScore ?? 0,
    status: 'new',
  }));
  const { error } = await insertRows(TABLES.alerts, rows, { returnRepresentation: false });
  return { saved: error ? 0 : rows.length, error };
}

export async function saveDetectedTransactions(rows: unknown[]): Promise<{ saved: number; error: RestError | null }> {
  if (!rows.length) return { saved: 0, error: null };
  const mapped = (rows as Row[]).map(d => ({
    event_type: 'SUSPICIOUS_TRANSACTION',
    type: d.type ?? 'TRANSACTION',
    severity: String(d.risk_level ?? d.riskLevel ?? 'HIGH').toLowerCase(),
    description: d.ai_explanation ?? d.aiExplanation ?? 'Suspicious transaction detected by pipeline',
    entity_id: d.source ?? null,
    account_id: d.source ?? null,
    transaction_id: d.transaction_id ?? d.transactionId ?? null,
    risk_score: d.risk_score ?? d.riskScore ?? 0,
  }));
  const { error } = await insertRows(TABLES.detected, mapped, { returnRepresentation: false });
  return { saved: error ? 0 : mapped.length, error };
}

export async function saveCase(caseRow: Row): Promise<{ saved: boolean; error: RestError | null }> {
  const row = {
    title: caseRow.title,
    status: String(caseRow.status ?? 'new').toLowerCase(),
    priority: String(caseRow.priority ?? 'medium').toLowerCase(),
    assigned_to: caseRow.assignedTo ?? caseRow.analyst ?? null,
    notes: caseRow.summary ?? caseRow.investigator_notes ?? '',
    opened_at: caseRow.created_at ?? new Date().toISOString(),
  };
  const { error } = await insertRows(TABLES.cases, [row], { returnRepresentation: false });
  return { saved: !error, error };
}

export async function saveCaseAnnotations(rows: Row[]): Promise<{ saved: number; error: RestError | null }> {
  if (!rows.length) return { saved: 0, error: null };
  const mapped = rows.map(r => ({
    case_id: r.caseId,
    author: r.analyst ?? 'TraceX Engine',
    body: r.action ?? r.body ?? '',
  }));
  const { error } = await insertRows(TABLES.caseActivity, mapped, { returnRepresentation: false });
  return { saved: error ? 0 : mapped.length, error };
}

export async function saveStreamEvents(rows: unknown[]): Promise<{ saved: number; error: RestError | null }> {
  if (!rows.length) return { saved: 0, error: null };
  const mapped = (rows as Row[]).filter(e => e.detected).map(e => ({
    event_type: 'STREAM_DETECTION',
    type: e.type ?? 'TRANSACTION',
    severity: String(e.risk ?? 'LOW').toLowerCase(),
    description: `${e.source} → ${e.target} · ${e.formatted_amount ?? ''} (${e.status ?? ''})`,
    entity_id: e.source ?? null,
    account_id: e.source ?? null,
    transaction_id: e.event_id ?? e.id ?? null,
    risk_score: e.risk_score ?? e.riskScore ?? 0,
  }));
  if (!mapped.length) return { saved: 0, error: null };
  const { error } = await insertRows(TABLES.detected, mapped, { returnRepresentation: false });
  return { saved: error ? 0 : mapped.length, error };
}

/**
 * Parallel bulk seed of the canonical dataset. Uses bounded concurrency;
 * every table failure is captured per-table (no partial-failure masking).
 */
export async function seedDatabase(rows: {
  transactions: Row[];
  accounts: Row[];
  cases: Row[];
  caseAnnotations?: Row[];
}): Promise<{
  results: { table: string; saved: number; error: string | null }[];
  writesEnabled: boolean;
}> {
  const jobs: { name: string; rows: Row[] }[] = [
    { name: TABLES.entities, rows: rows.accounts },
    { name: TABLES.transactions, rows: rows.transactions },
    { name: TABLES.cases, rows: rows.cases },
  ];

  const results = await parallelMap(jobs, async (job) => {
    if (!job.rows.length) return { table: job.name, saved: 0, error: null as string | null };
    // Chunk into batches of 100 to stay friendly to PostgREST limits.
    const saved: number[] = [0];
    for (let i = 0; i < job.rows.length; i += 100) {
      const { error } = await insertRows(job.name, job.rows.slice(i, i + 100));
      if (error) return { table: job.name, saved: saved[0], error: error.message };
      saved[0] += Math.min(100, job.rows.length - i);
    }
    return { table: job.name, saved: saved[0], error: null as string | null };
  }, { concurrency: 3 });

  const annotated = results.results.map((r, i) => r ?? { table: jobs[i].name, saved: 0, error: null as string | null });
  for (const e of results.errors) {
    annotated[e.index] = { table: jobs[e.index].name, saved: 0, error: e.error };
  }

  return {
    results: annotated,
    writesEnabled: supabaseConfig.canWrite,
  };
}

export const supabase = {
  selectRows,
  insertRows,
  updateRows,
  deleteRows,
  rpcCall,
  saveAlerts,
  saveDetectedTransactions,
  saveCase,
  saveCaseAnnotations,
  saveStreamEvents,
  seedDatabase,
  TABLES,
  COLUMNS,
  supabaseConfig,
};
