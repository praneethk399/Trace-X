/**
 * Discover full table schemas: anonymous signup → insert {} with
 * return=representation. The response either returns the full row (all
 * columns + defaults), a not-null violation (names required columns), or an
 * RLS denial (insert path blocked — read columns only).
 * Usage: node scripts/discoverSchema.mjs
 */
const KEY = 'sb_publishable_NpwSdNWaPzedmNhzoe2pdQ_Qo6uRHuS';
const BASE = 'https://dtrgsngsgklzqibchqpn.supabase.co/rest/v1';
const AUTH = 'https://dtrgsngsgklzqibchqpn.supabase.co/auth/v1';

const TABLES = ['transactions', 'accounts', 'cases', 'alerts', 'investigators', 'risk_events', 'reports', 'audit_logs', 'case_annotations'];

// 1. Anonymous session
const signupRes = await fetch(`${AUTH}/signup`, {
  method: 'POST',
  headers: { apikey: KEY, 'Content-Type': 'application/json' },
  body: JSON.stringify({}),
});
const signup = await signupRes.json();
if (!signup.access_token) {
  console.error('signup failed:', JSON.stringify(signup).slice(0, 300));
  process.exit(1);
}
const token = signup.access_token;
console.log('# session acquired:', signup.user?.id);

const H = { apikey: KEY, Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Prefer: 'return=representation' };

for (const table of TABLES) {
  const res = await fetch(`${BASE}/${table}`, { method: 'POST', headers: H, body: '{}' });
  const body = await res.json();
  if (Array.isArray(body) && body[0]) {
    console.log(`\n${table}: WRITABLE`);
    console.log('  columns:', Object.entries(body[0]).map(([k, v]) => `${k}(${v === null ? 'null' : typeof v})`).join(', '));
  } else if (body.code === '23502') {
    console.log(`\n${table}: WRITABLE but required: ${body.message}`);
  } else if (body.code === '42501') {
    console.log(`\n${table}: RLS-DENIED for authenticated (${body.message.slice(0, 80)})`);
  } else {
    console.log(`\n${table}: ${body.code ?? res.status} ${String(body.message).slice(0, 120)}`);
  }
}
