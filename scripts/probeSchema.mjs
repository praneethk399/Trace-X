/**
 * Probe the existing Supabase schema via PostgREST error messages.
 * For each table, start by selecting all candidate columns; when PostgREST
 * reports an unknown column, drop it and retry. Whatever remains is real.
 * Usage: node scripts/probeSchema.mjs
 */
const KEY = 'sb_publishable_NpwSdNWaPzedmNhzoe2pdQ_Qo6uRHuS';
const BASE = 'https://dtrgsngsgklzqibchqpn.supabase.co/rest/v1';
const H = { apikey: KEY, Authorization: `Bearer ${KEY}` };

const CANDIDATES = {
  transactions: ['id', 'source', 'target', 'sender', 'receiver', 'from_account', 'to_account', 'amount', 'amount_inr', 'currency', 'type', 'tx_type', 'transaction_type', 'channel', 'status', 'timestamp', 'created_at', 'txn_time', 'occurred_at', 'risk', 'risk_level', 'risk_score', 'fraud_score', 'hash', 'tx_hash', 'reference', 'note', 'notes', 'metadata', 'suspicious', 'is_suspicious', 'flagged', 'scenario', 'pattern', 'account_id', 'counterparty', 'upi_id', 'description', 'updated_at'],
  accounts: ['id', 'account_id', 'account_number', 'name', 'label', 'holder', 'holder_name', 'account_holder', 'type', 'account_type', 'bank', 'bank_name', 'ifsc', 'branch', 'balance', 'risk', 'risk_level', 'risk_score', 'status', 'flags', 'tags', 'is_mule', 'mule', 'customer_id', 'opened_at', 'created_at', 'updated_at', 'phone', 'email', 'kyc_status', 'address', 'city', 'state', 'metadata'],
  cases: ['id', 'case_id', 'title', 'name', 'status', 'priority', 'severity', 'analyst', 'investigator', 'assigned_to', 'unit', 'team', 'opened_at', 'closed_at', 'created_at', 'updated_at', 'summary', 'description', 'notes', 'account_id', 'transaction_id', 'entities_count', 'transactions_count', 'flagged_count', 'total_value', 'amount', 'evidence', 'activity_log', 'metadata', 'risk_score', 'risk_level', 'confidence'],
  alerts: ['id', 'alert_id', 'transaction_id', 'account_id', 'severity', 'type', 'alert_type', 'message', 'description', 'timestamp', 'created_at', 'risk_score', 'status', 'acknowledged', 'resolved_at', 'assigned_to', 'metadata', 'rule_id', 'pattern'],
  investigators: ['id', 'name', 'email', 'unit', 'team', 'role', 'created_at'],
  risk_events: ['id', 'event_type', 'type', 'severity', 'description', 'entity_id', 'account_id', 'transaction_id', 'created_at', 'metadata', 'risk_score'],
  reports: ['id', 'title', 'case_id', 'generated_at', 'created_at', 'content', 'summary', 'analyst', 'type'],
  audit_logs: ['id', 'actor', 'action', 'entity', 'entity_id', 'timestamp', 'created_at', 'metadata', 'details'],
  case_annotations: ['id', 'case_id', 'author', 'body', 'text', 'created_at'],
};

function extractBadColumns(table, message) {
  // Postgres 42703: "column transactions.bogus_column_xyz does not exist"
  const out = [];
  const re = new RegExp(`column ${table}\\.([\\w]+) does not exist`, 'g');
  let m;
  while ((m = re.exec(message))) out.push(m[1]);
  return out;
}

async function probeTable(table, candidates) {
  let alive = [...candidates];
  for (let guard = 0; guard < candidates.length + 2; guard++) {
    const res = await fetch(`${BASE}/${table}?select=${alive.join(',')}&limit=1`, { headers: H });
    const body = await res.json();
    if (Array.isArray(body)) return alive; // success — everything remaining exists
    if (body.code && body.code !== '42703') return alive; // different problem, stop
    const bad = extractBadColumns(table, body.message || '');
    if (!bad.length) return alive;
    const badSet = new Set(bad);
    const next = alive.filter(c => !badSet.has(c));
    if (next.length === alive.length) return alive; // no progress, bail
    alive = next;
  }
  return alive;
}

for (const [table, cols] of Object.entries(CANDIDATES)) {
  const found = await probeTable(table, cols);
  console.log(`${table}: ${found.join(', ') || '(none matched)'}`);
}
