/**
 * TraceX — Frontend API client
 * ============================
 * Single data layer for the UI. Strategy:
 *   1. Prefer the local API server (`/api/*`, proxied by Vite) — it runs the
 *      parallel worker-backed analysis engines and persists to Supabase.
 *   2. If the server is unreachable, degrade to direct Supabase REST reads so
 *      the console still works (read-only) against persisted data.
 *
 * Auth is handled in `authService.ts`; pass the session access token where a
 * user-scoped read matters (RLS).
 *
 * @license Apache-2.0
 */

import {
  EntityNode,
  TransactionEdge,
  CaseFile,
  StreamEvent,
  InvestigationReportData,
  PathAnalysisResult,
} from '../types/forensics';
import type { NetworkAnalysisSummary } from '../../server/parallel';
import { ENTITY_NODES, TRANSACTION_EDGES, CASE_FILES } from '../data/mockForensics';
import { getStoredSession } from './authService';

// ============================================================================
// Config
// ============================================================================

const SUPABASE_URL = 'https://dtrgsngsgklzqibchqpn.supabase.co';
const SUPABASE_KEY = 'sb_publishable_NpwSdNWaPzedmNhzoe2pdQ_Qo6uRHuS';
const REST_BASE = `${SUPABASE_URL}/rest/v1`;

const API_BASE = ''; // empty → same origin (Vite proxies /api in dev)

export type BackendMode = 'server' | 'supabase-direct' | 'offline';

let backendMode: BackendMode = 'server';
export function getBackendMode(): BackendMode { return backendMode; }

/** Once the server fails, remember and stop re-probing every call. */
let serverDown = false;
export function resetServerProbe(): void {
  serverDown = false;
  backendMode = 'server';
}

// ============================================================================
// Low-level helpers
// ============================================================================

function authHeaders(): Record<string, string> {
  const session = getStoredSession();
  const h: Record<string, string> = { 'Content-Type': 'application/json' };
  if (session?.access_token) h.Authorization = `Bearer ${session.access_token}`;
  return h;
}

async function apiFetch<T>(path: string, init: RequestInit = {}, timeoutMs = 8000): Promise<T> {
  if (serverDown) throw new Error('SERVER_DOWN');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: { ...authHeaders(), ...(init.headers ?? {}) },
      signal: controller.signal,
    });
    if (!res.ok) {
      const body = (await res.json().catch(() => null)) as { error?: string } | null;
      throw new Error(body?.error || `HTTP ${res.status}`);
    }
    return (await res.json()).data as T;
  } catch (e) {
    if ((e as Error).message === 'SERVER_DOWN' || (e as Error).name === 'AbortError') {
      serverDown = true;
      backendMode = 'supabase-direct';
    }
    throw e;
  }
}

async function supabaseFetch<T>(path: string): Promise<T> {
  const res = await fetch(path, {
    headers: { apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` },
  });
  if (!res.ok) throw new Error(`SUPABASE HTTP ${res.status}`);
  return (await res.json()) as T;
}

// ============================================================================
// Types
// ============================================================================

export interface NetworkSnapshot {
  nodes: EntityNode[];
  edges: TransactionEdge[];
  cases: CaseFile[];
  stats: {
    totalNodes: number;
    totalEdges: number;
    totalVolume: number;
    flagged: number;
    criticalAccounts: number;
  };
}

export interface AnalyzeTxResponse {
  result: {
    transactionId: string;
    risk: string;
    riskScore: number;
    confidenceScore: number;
    detectedPatterns: string[];
    signals: { id: string; name: string; severity: string; description: string; weight: number }[];
    alerts: { id: string; severity: string; type: string; message: string; riskScore: number }[];
    processingTimeMs: number;
    isValid: boolean;
    validationErrors: string[];
  };
  detected: import('../types/forensics').DetectedSuspiciousTransaction;
  aiExplanation: string;
  aiSource: 'ai' | 'fallback';
}

// ============================================================================
// Network
// ============================================================================

export async function fetchNetwork(): Promise<NetworkSnapshot> {
  try {
    return await apiFetch<NetworkSnapshot>('/api/network');
  } catch {
    // Supabase-direct fallback: read persisted entities/transactions/cases.
    try {
      const [nodes, edges, cases] = await Promise.all([
        supabaseFetch<EntityNode[]>(`${REST_BASE}/tracex_entities?select=*&order=node_number.asc&limit=500`),
        supabaseFetch<Record<string, unknown>[]>(`${REST_BASE}/tracex_transactions?select=*&limit=1000`),
        supabaseFetch<CaseFile[]>(`${REST_BASE}/tracex_cases?select=*&limit=100`),
      ]);
      const mappedEdges = edges.map((e: Record<string, unknown>) => ({
        ...e,
        formattedAmount: (e.formatted_amount as string) ?? (e.formattedAmount as string) ?? '',
        flowStatus: ((e.flow_status as string) ?? (e.flowStatus as string) ?? 'SETTLED'),
      })) as unknown as TransactionEdge[]; // typed via cast above
      const mappedCases = cases as unknown as CaseFile[];
      return {
        nodes,
        edges: mappedEdges,
        cases: mappedCases,
        stats: {
          totalNodes: nodes.length,
          totalEdges: mappedEdges.length,
          totalVolume: mappedEdges.reduce((s, e) => s + e.amount, 0),
          flagged: mappedEdges.filter(e => e.flowStatus === 'FLAGGED').length,
          criticalAccounts: nodes.filter(n => n.risk === 'CRITICAL').length,
          // supabase rows may use snake_case risk/status
        } as NetworkSnapshot['stats'],
      };
    } catch {
      // Offline: use the deterministic seed dataset so the UI still renders.
      backendMode = 'offline';
      return {
        nodes: ENTITY_NODES,
        edges: TRANSACTION_EDGES,
        cases: CASE_FILES,
        stats: {
          totalNodes: ENTITY_NODES.length,
          totalEdges: TRANSACTION_EDGES.length,
          totalVolume: TRANSACTION_EDGES.reduce((s, e) => s + e.amount, 0),
          flagged: TRANSACTION_EDGES.filter(e => e.flowStatus === 'FLAGGED').length,
          criticalAccounts: ENTITY_NODES.filter(n => n.risk === 'CRITICAL').length,
        },
      };
    }
  }
}

// ============================================================================
// Analysis
// ============================================================================

export async function analyzeNetwork(): Promise<NetworkAnalysisSummary> {
  return apiFetch<NetworkAnalysisSummary>('/api/analyze', { method: 'POST' }, 60000);
}

export async function analyzeTransaction(input: {
  source: string;
  target: string;
  type: string;
  amount: number;
  note?: string;
}): Promise<AnalyzeTxResponse> {
  return apiFetch<AnalyzeTxResponse>('/api/analyze/tx', { method: 'POST', body: JSON.stringify(input) }, 15000);
}

export async function traceFunds(source: string, destination: string): Promise<PathAnalysisResult> {
  return apiFetch<PathAnalysisResult>(
    `/api/network/trace?source=${encodeURIComponent(source)}&destination=${encodeURIComponent(destination)}`
  );
}

export async function filterNetwork(filters: Record<string, unknown>): Promise<{ nodes: EntityNode[]; edges: TransactionEdge[] }> {
  return apiFetch('/api/network/filter', { method: 'POST', body: JSON.stringify(filters) });
}

// ============================================================================
// Cases
// ============================================================================

export async function fetchCases(): Promise<CaseFile[]> {
  try {
    const data = await apiFetch<{ cases: CaseFile[] }>('/api/cases');
    return data.cases;
  } catch {
    try {
      return await supabaseFetch<CaseFile[]>(`${REST_BASE}/tracex_cases?select=*&limit=100`);
    } catch {
      backendMode = 'offline';
      return CASE_FILES;
    }
  }
}

export async function openCaseFromAlert(input: { transactionId?: string; accountId?: string; title?: string }) {
  return apiFetch<{ case: Record<string, unknown>; persisted: boolean }>('/api/cases/from-alert', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

// ============================================================================
// Reports
// ============================================================================

export async function fetchReport(txId: string): Promise<{ report: InvestigationReportData; aiExplanation: string; aiSource: string }> {
  return apiFetch(`/api/report/${encodeURIComponent(txId)}`);
}

// ============================================================================
// Live stream
// ============================================================================

export interface StreamEventsResponse {
  events: StreamEvent[];
  seq: number;
}

export async function fetchStreamEvents(count = 5): Promise<StreamEventsResponse> {
  return apiFetch(`/api/stream/events?count=${count}`, {}, 5000);
}

export async function startStream(intervalMs = 2000): Promise<{ running: boolean; intervalMs: number }> {
  return apiFetch('/api/stream/start', { method: 'POST', body: JSON.stringify({ intervalMs }) });
}

export async function stopStream(): Promise<{ running: boolean }> {
  return apiFetch('/api/stream/stop', { method: 'POST' });
}

export function subscribeStream(onEvents: (events: StreamEvent[]) => void, onStatus?: (connected: boolean) => void): () => void {
  try {
    const es = new EventSource('/api/stream/sse');
    es.onopen = () => onStatus?.(true);
    es.onerror = () => onStatus?.(false);
    es.onmessage = (msg) => {
      try {
        const { events } = JSON.parse(msg.data) as { events: StreamEvent[] };
        if (events?.length) onEvents(events);
      } catch { /* ignore malformed frame */ }
    };
    return () => es.close();
  } catch {
    onStatus?.(false);
    return () => {};
  }
}
