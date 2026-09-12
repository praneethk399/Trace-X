/**
 * TraceX — Frontend Supabase REST helper
 * ======================================
 * Direct PostgREST reads using the publishable key, optionally with the
 * signed-in user's access token so RLS policies apply. Used by the UI when
 * the API server is unreachable (`src/lib/api.ts` orchestrates the fallback).
 *
 * @license Apache-2.0
 */

import { getStoredSession } from './authService';

const SUPABASE_URL = 'https://dtrgsngsgklzqibchqpn.supabase.co';
const SUPABASE_KEY = 'sb_publishable_NpwSdNWaPzedmNhzoe2pdQ_Qo6uRHuS';
export const REST_BASE = `${SUPABASE_URL}/rest/v1`;

function headers(): Record<string, string> {
  const session = getStoredSession();
  return {
    apikey: SUPABASE_KEY,
    Authorization: `Bearer ${session?.access_token || SUPABASE_KEY}`,
    'Content-Type': 'application/json',
  };
}

export async function supabaseSelect<T>(
  table: string,
  params: { columns?: string; filters?: Record<string, string>; order?: string; ascending?: boolean; limit?: number } = {}
): Promise<T[]> {
  const url = new URL(`${REST_BASE}/${table}`);
  if (params.columns) url.searchParams.set('select', params.columns);
  for (const [k, v] of Object.entries(params.filters ?? {})) url.searchParams.set(k, `eq.${v}`);
  if (params.order) {
    url.searchParams.set('order', params.order);
    url.searchParams.set('ascending', String(params.ascending ?? false));
  }
  if (params.limit) url.searchParams.set('limit', String(params.limit));

  const res = await fetch(url, { headers: headers() });
  if (!res.ok) throw new Error(`SUPABASE ${res.status}`);
  return (await res.json()) as T[];
}

/** Auth-scoped read that fails loudly (used where RLS matters). */
export async function supabaseSelectAuthed<T>(
  table: string,
  params: Parameters<typeof supabaseSelect>[1] = {}
): Promise<T[]> {
  const session = getStoredSession();
  if (!session?.access_token) throw new Error('NOT_AUTHENTICATED');
  return supabaseSelect<T>(table, params);
}

export const SB_TABLES = {
  entities: 'tracex_entities',
  transactions: 'tracex_transactions',
  alerts: 'tracex_alerts',
  detected: 'tracex_detected_transactions',
  cases: 'tracex_cases',
  caseActivity: 'tracex_case_activity',
  streamEvents: 'tracex_stream_events',
} as const;
