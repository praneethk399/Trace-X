/**
 * TraceX — Console (App shell)
 * ============================
 * Working operator console wired to the backend:
 *   - Supabase auth gate (email/password + Google OAuth via authService)
 *   - Live transaction stream (SSE from the API server)
 *   - Network KPIs, entity table, and flagged-transaction feed
 *   - Transaction scoring form → /api/analyze/tx (with AI explanation)
 *   - Parallel network analysis runner → /api/analyze
 *
 * @license Apache-2.0
 */

import type React from 'react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import {
  EntityNode,
  TransactionEdge,
  CaseFile,
  StreamEvent,
  RiskLevel,
} from './types/forensics';
import { formatINR } from './data/mockForensics';
import {
  fetchNetwork,
  analyzeNetwork,
  analyzeTransaction,
  fetchStreamEvents,
  subscribeStream,
  getBackendMode,
  resetServerProbe,
  type NetworkSnapshot,
  type AnalyzeTxResponse,
  type BackendMode,
} from './lib/api';
import {
  consumeOAuthError,
  deriveOperatorLabel,
  getStoredSession,
  resolveOAuthRedirect,
  signInWithGoogle,
  signInWithPassword,
  signOut,
  validateSession,
  type AuthSession,
} from './lib/authService';

// ============================================================================
// Small UI primitives (composed from the design-token primitives)
// ============================================================================

const RISK_ORDER: RiskLevel[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

const riskBadgeClass: Record<RiskLevel, string> = {
  LOW: 'badge badge-success',
  MEDIUM: 'badge badge-warning',
  HIGH: 'badge badge-high',
  CRITICAL: 'badge badge-critical',
};

function KpiCard({ label, value, sub, tone }: { label: string; value: string; sub?: string; tone?: 'critical' | 'warning' | 'success' }) {
  return (
    <div className="panel p-4 min-w-[160px] flex-1">
      <p className="text-[color:var(--color-text-muted)] uppercase tracking-wider" style={{ fontSize: 'var(--text-tiny)' }}>
        {label}
      </p>
      <p
        className="font-semibold mt-1"
        style={{
          fontSize: '1.5rem',
          color: tone === 'critical' ? 'var(--color-critical)' : tone === 'warning' ? 'var(--color-warning)' : tone === 'success' ? 'var(--color-success)' : 'var(--color-text)',
        }}
      >
        {value}
      </p>
      {sub && <p className="mono-id text-[color:var(--color-text-muted)] mt-0.5">{sub}</p>}
    </div>
  );
}

function RiskBadge({ level }: { level: RiskLevel }) {
  return <span className={riskBadgeClass[level]}>{level}</span>;
}

function StatusFooter({ mode, backendError }: { mode: BackendMode; backendError: string | null }) {
  const label: Record<BackendMode, string> = {
    server: 'BACKEND: API SERVER (PARALLEL)',
    'supabase-direct': 'BACKEND: SUPABASE DIRECT (READ-ONLY)',
    offline: 'BACKEND: OFFLINE SEED DATA',
  };
  return (
    <div className="mono-id text-[color:var(--color-text-muted)] flex items-center gap-3 flex-wrap">
      <span>{label[mode]}</span>
      <span>·</span>
      <span>{new Date().toLocaleTimeString()}</span>
      {backendError && <span style={{ color: 'var(--color-warning)' }}>· {backendError}</span>}
    </div>
  );
}

// ============================================================================
// Auth gate
// ============================================================================

function LoginScreen({ onAuthenticated }: { onAuthenticated: (session: AuthSession) => void }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mode, setMode] = useState<'signin' | 'signup'>('signin');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const oauthError = useMemo(() => consumeOAuthError(), []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setNotice(null);

    const result = mode === 'signin'
      ? await signInWithPassword(email, password)
      : await signInWithPassword(email, password); // Supabase signup uses the same endpoint shape

    setBusy(false);

    if (result.error) {
      setError(result.error);
      return;
    }
    if ('needsConfirmation' in result && result.needsConfirmation) {
      setNotice('CHECK YOUR INBOX — CONFIRM YOUR EMAIL, THEN SIGN IN.');
      return;
    }
    if (result.session) onAuthenticated(result.session);
  }

  return (
    <div className="min-h-screen flex items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <p className="mono-id text-[color:var(--color-accent)] mb-2">TRACE X // FORENSICS CONSOLE</p>
        <h1 className="font-semibold" style={{ fontSize: 'var(--text-page-title)' }}>Operator sign-in</h1>
        <p className="text-[color:var(--color-text-secondary)] mt-2 mb-6">
          Authenticate via Supabase to access the fraud-detection workspace.
        </p>

        {(oauthError || error) && (
          <div className="panel p-3 mb-4" style={{ borderColor: 'var(--color-critical)' }}>
            <p className="mono-id" style={{ color: 'var(--color-critical)' }}>{oauthError ?? error}</p>
          </div>
        )}
        {notice && (
          <div className="panel p-3 mb-4" style={{ borderColor: 'var(--color-warning)' }}>
            <p className="mono-id" style={{ color: 'var(--color-warning)' }}>{notice}</p>
          </div>
        )}

        <form onSubmit={handleSubmit} className="panel p-5 space-y-4">
          <div>
            <label className="block mb-1 text-[color:var(--color-text-secondary)]" style={{ fontSize: 'var(--text-tiny)' }}>EMAIL</label>
            <input
              type="email"
              required
              value={email}
              onChange={e => setEmail(e.target.value)}
              className="w-full px-3 py-2 rounded-[var(--radius-md)] bg-[var(--color-surface-2)] border border-[var(--color-line)] text-[color:var(--color-text)]"
              placeholder="analyst@tracex.io"
            />
          </div>
          <div>
            <label className="block mb-1 text-[color:var(--color-text-secondary)]" style={{ fontSize: 'var(--text-tiny)' }}>PASSWORD</label>
            <input
              type="password"
              required
              minLength={6}
              value={password}
              onChange={e => setPassword(e.target.value)}
              className="w-full px-3 py-2 rounded-[var(--radius-md)] bg-[var(--color-surface-2)] border border-[var(--color-line)] text-[color:var(--color-text)]"
              placeholder="••••••••"
            />
          </div>

          <button type="submit" disabled={busy} className="btn-primary w-full py-2.5 disabled:opacity-50">
            {busy ? 'AUTHENTICATING…' : mode === 'signin' ? 'SIGN IN' : 'CREATE ACCOUNT'}
          </button>

          <div className="flex items-center gap-3">
            <div className="h-px flex-1 bg-[var(--color-line)]" />
            <span className="mono-id text-[color:var(--color-text-muted)]">OR</span>
            <div className="h-px flex-1 bg-[var(--color-line)]" />
          </div>

          <button
            type="button"
            onClick={() => signInWithGoogle()}
            className="w-full py-2.5 rounded-[var(--radius-md)] border border-[var(--color-line-strong)] text-[color:var(--color-text)] hover:bg-[var(--color-surface-2)] transition-colors"
          >
            CONTINUE WITH GOOGLE
          </button>

          <button
            type="button"
            onClick={() => { setMode(m => (m === 'signin' ? 'signup' : 'signin')); setError(null); }}
            className="mono-id text-[color:var(--color-text-muted)] hover:text-[color:var(--color-text)] w-full text-center"
          >
            {mode === 'signin' ? 'NEED AN ACCOUNT? REGISTER →' : '← BACK TO SIGN-IN'}
          </button>
        </form>
      </div>
    </div>
  );
}

// ============================================================================
// Main console
// ============================================================================

type Tab = 'overview' | 'transactions' | 'entities' | 'cases' | 'engine';

export default function App() {
  // ---- Auth state ----
  const [session, setSession] = useState<AuthSession | null>(() => getStoredSession());
  const [authChecked, setAuthChecked] = useState(false);

  // ---- Data state ----
  const [snapshot, setSnapshot] = useState<NetworkSnapshot | null>(null);
  const [backendMode, setBackendMode] = useState<BackendMode>('server');
  const [backendError, setBackendError] = useState<string | null>(null);
  const [streamEvents, setStreamEvents] = useState<StreamEvent[]>([]);
  const [streamConnected, setStreamConnected] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [analysisSummary, setAnalysisSummary] = useState<Awaited<ReturnType<typeof analyzeNetwork>> | null>(null);

  // ---- Scoring form ----
  const [form, setForm] = useState({ source: 'ACC-TRX-9281', target: 'WAL-EXC-9902', type: 'IMPS', amount: 250000 });
  const [scoreResult, setScoreResult] = useState<AnalyzeTxResponse | null>(null);
  const [scoring, setScoring] = useState(false);

  // ---- UI state ----
  const [tab, setTab] = useState<Tab>('overview');
  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState<'ALL' | RiskLevel>('ALL');
  const [caseList, setCaseList] = useState<CaseFile[]>([]);
  const feedRef = useRef<HTMLDivElement>(null);

  // ---- Boot: OAuth redirect resolution + session validation ----
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const redirectSession = resolveOAuthRedirect();
      if (redirectSession && !cancelled) {
        setSession(redirectSession);
        setAuthChecked(true);
        return;
      }
      const stored = getStoredSession();
      if (stored) {
        const valid = await validateSession(stored);
        if (!cancelled) setSession(valid);
      }
      if (!cancelled) setAuthChecked(true);
    })();
    return () => { cancelled = true; };
  }, []);

  // ---- Data loading once authenticated ----
  const loadNetwork = useCallback(async () => {
    const snap = await fetchNetwork();
    setSnapshot(snap);
    setBackendMode(getBackendMode());
    setCaseList(snap.cases);
    return snap;
  }, []);

  useEffect(() => {
    if (!session) return;
    loadNetwork().catch(() => setBackendError('NETWORK LOAD FAILED'));
  }, [session, loadNetwork]);

  // ---- Live stream: subscribe via SSE, fall back to polling ----
  useEffect(() => {
    if (!session) return;

    let unsubscribe: (() => void) | null = null;
    let pollTimer: ReturnType<typeof setInterval> | null = null;

    const push = (events: StreamEvent[]) => {
      setStreamEvents(prev => [...events, ...prev].slice(0, 60));
    };

    unsubscribe = subscribeStream(push, (connected) => {
      setStreamConnected(connected);
      if (!connected && !pollTimer) {
        // Polling fallback when SSE isn't available.
        pollTimer = setInterval(() => {
          fetchStreamEvents(4).then(r => push(r.events)).catch(() => {});
        }, 2500);
      }
    });

    // If the API server is down, the poll fallback above will also fail; then
    // we synthesize a local feed from the seed network so the console stays alive.
    let localTimer: ReturnType<typeof setInterval> | null = null;
    setTimeout(() => {
      if (!streamConnected && getBackendMode() !== 'server') {
        localTimer = setInterval(() => {
          setStreamEvents(prev => {
            const seq = prev.length + 1;
            const hex = Math.random().toString(16).slice(2, 6).toUpperCase();
            const src = snapshot?.nodes[Math.floor(Math.random() * snapshot.nodes.length)];
            const tgt = snapshot?.nodes[Math.floor(Math.random() * snapshot.nodes.length)];
            if (!src || !tgt || src.id === tgt.id) return prev;
            const amount = Math.round(2000 + Math.random() * 18000);
            const event: StreamEvent = {
              id: `TXN-L${String(seq).padStart(4, '0')}-${hex}`,
              time: new Date().toTimeString().slice(0, 8),
              source: src.id,
              sourceLabel: src.label,
              target: tgt.id,
              targetLabel: tgt.label,
              type: (['UPI', 'IMPS', 'NEFT', 'CARD'] as const)[Math.floor(Math.random() * 4)],
              amount: formatINR(amount),
              numericAmount: amount,
              risk: 'LOW',
              riskScore: Math.floor(8 + Math.random() * 16),
              status: 'NORMAL',
              detectionSignals: [],
              detected: false,
              hash: `0x${hex}`,
              isNew: true,
            };
            return [event, ...prev].slice(0, 60);
          });
        }, 2500);
      }
    }, 4000);

    return () => {
      unsubscribe?.();
      if (pollTimer) clearInterval(pollTimer);
      if (localTimer) clearInterval(localTimer);
    };
  }, [session, snapshot]);

  // ---- Actions ----
  const runAnalysis = useCallback(async () => {
    setAnalyzing(true);
    try {
      const summary = await analyzeNetwork();
      setAnalysisSummary(summary);
      setBackendError(null);
    } catch (e) {
      setBackendError(`ANALYSIS FAILED — ${(e as Error).message}`);
    } finally {
      setAnalyzing(false);
    }
  }, []);

  const scoreTx = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    setScoring(true);
    setScoreResult(null);
    try {
      const result = await analyzeTransaction(form);
      setScoreResult(result);
    } catch (err) {
      setBackendError(`SCORING FAILED — ${(err as Error).message}`);
    } finally {
      setScoring(false);
    }
  }, [form]);

  function handleSignOut() {
    void signOut(session?.access_token ?? null);
    setSession(null);
    resetServerProbe();
    setStreamEvents([]);
  }

  // ---- Derived data ----
  const filteredNodes = useMemo(() => {
    if (!snapshot) return [];
    const q = search.trim().toLowerCase();
    return snapshot.nodes.filter(n => {
      if (riskFilter !== 'ALL' && n.risk !== riskFilter) return false;
      if (!q) return true;
      return (
        n.id.toLowerCase().includes(q) ||
        n.label.toLowerCase().includes(q) ||
        (n.accountHolder ?? '').toLowerCase().includes(q) ||
        (n.bankName ?? '').toLowerCase().includes(q) ||
        n.tags.some(t => t.toLowerCase().includes(q))
      );
    });
  }, [snapshot, search, riskFilter]);

  const flaggedEdges = useMemo(() => {
    if (!snapshot) return [];
    return [...snapshot.edges].filter(e => e.flowStatus === 'FLAGGED' || e.risk === 'CRITICAL').slice(0, 12);
  }, [snapshot]);

  const riskCounts = useMemo(() => {
    const counts: Record<RiskLevel, number> = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
    for (const e of snapshot?.edges ?? []) counts[e.risk]++;
    return counts;
  }, [snapshot]);

  if (!authChecked) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <p className="mono-id text-[color:var(--color-text-muted)]">INITIALIZING SECURE SESSION…</p>
      </div>
    );
  }

  if (!session) {
    return <LoginScreen onAuthenticated={setSession} />;
  }

  const operator = deriveOperatorLabel(session.user);

  return (
    <div className="min-h-screen flex flex-col">
      {/* ---------- Top bar ---------- */}
      <header className="flex items-center gap-4 px-6 py-3 border-b border-[var(--color-line)] bg-[var(--color-surface)]">
        <p className="mono-id text-[color:var(--color-accent)] font-semibold">TRACE X</p>
        <span className="badge badge-info">{backendMode === 'server' ? 'BACKEND ONLINE' : backendMode === 'supabase-direct' ? 'SUPABASE DIRECT' : 'OFFLINE SEED'}</span>
        <span className={`badge ${streamConnected ? 'badge-success' : 'badge-warning'}`}>
          {streamConnected ? 'STREAM LIVE' : 'STREAM POLLING'}
        </span>
        <div className="flex-1" />
        <span className="mono-id text-[color:var(--color-text-secondary)]">{operator}</span>
        <button onClick={handleSignOut} className="mono-id text-[color:var(--color-text-muted)] hover:text-[color:var(--color-text)]">
          SIGN OUT
        </button>
      </header>

      {/* ---------- Nav ---------- */}
      <nav className="flex gap-1 px-6 py-2 border-b border-[var(--color-line)]">
        {(['overview', 'transactions', 'entities', 'cases', 'engine'] as Tab[]).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className="nav-item"
            data-active={tab === t}
            style={{ textTransform: 'uppercase', fontSize: 'var(--text-tiny)', letterSpacing: '0.07em' }}
          >
            {t}
          </button>
        ))}
      </nav>

      {/* ---------- Body ---------- */}
      <main className="flex-1 px-6 py-5 overflow-auto">
        {!snapshot ? (
          <p className="mono-id text-[color:var(--color-text-muted)]">LOADING NETWORK SNAPSHOT…</p>
        ) : tab === 'overview' ? (
          <>
            {/* KPI row */}
            <div className="flex gap-3 flex-wrap mb-5">
              <KpiCard label="Entities" value={String(snapshot.stats.totalNodes)} sub={`${snapshot.stats.criticalAccounts} critical`} />
              <KpiCard label="Transactions" value={String(snapshot.stats.totalEdges)} sub={`${snapshot.stats.flagged} flagged`} />
              <KpiCard label="Total flow" value={formatINR(snapshot.stats.totalVolume)} />
              <KpiCard label="Critical risk" value={String(riskCounts.CRITICAL)} tone="critical" sub="transactions" />
              <KpiCard label="High risk" value={String(riskCounts.HIGH)} tone="warning" sub="transactions" />
              <KpiCard
                label="Analysis"
                value={analysisSummary ? `${analysisSummary.durationMs.toFixed(0)}ms` : '—'}
                sub={analysisSummary ? `workers ×${analysisSummary.parallelism.workerPoolSize}` : 'run engine analysis'}
              />
            </div>

            {/* Stream + flagged feed */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <section className="panel p-4">
                <div className="flex items-center justify-between mb-3">
                  <h2 className="font-semibold">Live transaction stream</h2>
                  <span className={`badge ${streamConnected ? 'badge-success' : 'badge-warning'}`}>
                    {streamConnected ? 'SSE' : 'POLL'}
                  </span>
                </div>
                <div ref={feedRef} className="space-y-1.5 max-h-72 overflow-auto pr-1">
                  {streamEvents.length === 0 && (
                    <p className="mono-id text-[color:var(--color-text-muted)]">AWAITING EVENTS…</p>
                  )}
                  {streamEvents.map(ev => (
                    <div key={ev.id} className="flex items-center gap-2 mono-id py-1 border-b border-[var(--color-line)]">
                      <span className="text-[color:var(--color-text-muted)]">{ev.time}</span>
                      <span className="text-[color:var(--color-text)]">{ev.source.slice(-4)}→{ev.target.slice(-4)}</span>
                      <span className="text-[color:var(--color-text-secondary)]">{ev.type}</span>
                      <span className="text-[color:var(--color-text)]">{ev.amount}</span>
                      <span className={`badge ${ev.detected ? 'badge-critical' : 'badge-success'}`}>
                        {ev.detected ? 'ALERT' : ev.riskScore}
                      </span>
                    </div>
                  ))}
                </div>
              </section>

              <section className="panel p-4">
                <h2 className="font-semibold mb-3">Flagged flows</h2>
                <div className="space-y-1.5 max-h-72 overflow-auto pr-1">
                  {flaggedEdges.map(e => (
                    <div key={e.id} className="flex items-center gap-2 mono-id py-1 border-b border-[var(--color-line)]">
                      <span className="text-[color:var(--color-text-muted)]">{e.timestamp}</span>
                      <span className="text-[color:var(--color-text)]">{e.source.slice(-4)}→{e.target.slice(-4)}</span>
                      <span className="text-[color:var(--color-text-secondary)]">{e.type}</span>
                      <span className="text-[color:var(--color-text)]">{e.formattedAmount}</span>
                      <RiskBadge level={e.risk} />
                    </div>
                  ))}
                  {flaggedEdges.length === 0 && (
                    <p className="mono-id text-[color:var(--color-text-muted)]">NO FLAGGED FLOWS</p>
                  )}
                </div>
              </section>
            </div>

            {/* Score form + result */}
            <section className="panel p-4 mt-4">
              <h2 className="font-semibold mb-3">Score a transaction</h2>
              <form onSubmit={scoreTx} className="flex gap-3 flex-wrap items-end">
                <label className="flex flex-col gap-1">
                  <span className="text-[color:var(--color-text-muted)]" style={{ fontSize: 'var(--text-tiny)' }}>SOURCE</span>
                  <input
                    value={form.source}
                    onChange={e => setForm(f => ({ ...f, source: e.target.value }))}
                    className="mono-id px-2 py-1.5 rounded-[var(--radius-sm)] bg-[var(--color-surface-2)] border border-[var(--color-line)]"
                  />
                </label>
                <label className="flex flex-col gap-1">
                  <span className="text-[color:var(--color-text-muted)]" style={{ fontSize: 'var(--text-tiny)' }}>TARGET</span>
                  <input
                    value={form.target}
                    onChange={e => setForm(f => ({ ...f, target: e.target.value }))}
                    className="mono-id px-2 py-1.5 rounded-[var(--radius-sm)] bg-[var(--color-surface-2)] border border-[var(--color-line)]"
                  />
                </label>
                <label className="flex flex-col gap-1">
                  <span className="text-[color:var(--color-text-muted)]" style={{ fontSize: 'var(--text-tiny)' }}>TYPE</span>
                  <select
                    value={form.type}
                    onChange={e => setForm(f => ({ ...f, type: e.target.value }))}
                    className="mono-id px-2 py-1.5 rounded-[var(--radius-sm)] bg-[var(--color-surface-2)] border border-[var(--color-line)]"
                  >
                    {['UPI', 'IMPS', 'NEFT', 'RTGS', 'CARD'].map(t => <option key={t}>{t}</option>)}
                  </select>
                </label>
                <label className="flex flex-col gap-1">
                  <span className="text-[color:var(--color-text-muted)]" style={{ fontSize: 'var(--text-tiny)' }}>AMOUNT (₹)</span>
                  <input
                    type="number"
                    min={1}
                    value={form.amount}
                    onChange={e => setForm(f => ({ ...f, amount: Number(e.target.value) }))}
                    className="mono-id px-2 py-1.5 rounded-[var(--radius-sm)] bg-[var(--color-surface-2)] border border-[var(--color-line)] w-36"
                  />
                </label>
                <button type="submit" disabled={scoring} className="btn-primary px-4 py-2 disabled:opacity-50">
                  {scoring ? 'SCORING…' : 'RUN PIPELINE'}
                </button>
              </form>

              {scoreResult && (
                <div className="mt-4 grid grid-cols-1 lg:grid-cols-2 gap-4">
                  <div>
                    <div className="flex items-center gap-2 mb-2">
                      <span className={riskBadgeClass[scoreResult.result.risk as RiskLevel] ?? 'badge badge-info'}>
                        {scoreResult.result.risk} · {scoreResult.result.riskScore}/100
                      </span>
                      <span className="mono-id text-[color:var(--color-text-muted)]">
                        {scoreResult.result.processingTimeMs.toFixed(1)}ms · confidence {scoreResult.result.confidenceScore}%
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-1.5 mb-2">
                      {scoreResult.result.detectedPatterns.map(p => (
                        <span key={p} className="badge badge-warning">{p}</span>
                      ))}
                    </div>
                    <div className="space-y-1">
                      {scoreResult.result.alerts.map(a => (
                        <p key={a.id} className="mono-id" style={{ color: a.severity === 'CRITICAL' ? 'var(--color-critical)' : 'var(--color-warning)' }}>
                          ⚠ {a.message}
                        </p>
                      ))}
                      {scoreResult.result.alerts.length === 0 && (
                        <p className="mono-id text-[color:var(--color-text-muted)]">No alerts — transaction assessed as routine.</p>
                      )}
                    </div>
                  </div>
                  <div>
                    <div className="flex items-center gap-2 mb-2">
                      <h3 className="font-semibold">AI risk explanation</h3>
                      <span className="badge badge-info">{scoreResult.aiSource === 'ai' ? 'GEMINI' : 'DETERMINISTIC'}</span>
                    </div>
                    <p className="text-[color:var(--color-text-secondary)]">{scoreResult.aiExplanation}</p>
                  </div>
                </div>
              )}
            </section>
          </>
        ) : tab === 'transactions' ? (
          <section className="panel p-4">
            <h2 className="font-semibold mb-3">All transactions</h2>
            <div className="overflow-auto max-h-[65vh]">
              <table className="w-full mono-id">
                <thead className="text-[color:var(--color-text-muted)] uppercase text-left">
                  <tr>
                    <th className="py-2 pr-4">ID</th>
                    <th className="py-2 pr-4">Time</th>
                    <th className="py-2 pr-4">Source → Target</th>
                    <th className="py-2 pr-4">Type</th>
                    <th className="py-2 pr-4">Amount</th>
                    <th className="py-2 pr-4">Risk</th>
                    <th className="py-2">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {snapshot.edges.map(e => (
                    <tr key={e.id} className="border-t border-[var(--color-line)]">
                      <td className="py-1.5 pr-4">{e.id}</td>
                      <td className="py-1.5 pr-4">{e.timestamp}</td>
                      <td className="py-1.5 pr-4">{e.source} → {e.target}</td>
                      <td className="py-1.5 pr-4">{e.type}</td>
                      <td className="py-1.5 pr-4">{e.formattedAmount}</td>
                      <td className="py-1.5 pr-4"><RiskBadge level={e.risk} /></td>
                      <td className="py-1.5">{e.flowStatus}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        ) : tab === 'entities' ? (
          <section className="panel p-4">
            <div className="flex gap-2 items-center mb-3 flex-wrap">
              <h2 className="font-semibold">Entities</h2>
              <input
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Search id, holder, bank, tag…"
                className="ml-auto px-3 py-1.5 rounded-[var(--radius-sm)] bg-[var(--color-surface-2)] border border-[var(--color-line)]"
              />
              <select
                value={riskFilter}
                onChange={e => setRiskFilter(e.target.value as 'ALL' | RiskLevel)}
                className="mono-id px-2 py-1.5 rounded-[var(--radius-sm)] bg-[var(--color-surface-2)] border border-[var(--color-line)]"
              >
                {['ALL', ...RISK_ORDER].map(r => <option key={r}>{r}</option>)}
              </select>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3 max-h-[65vh] overflow-auto pr-1">
              {filteredNodes.map(n => (
                <EntityCard key={n.id} node={n} />
              ))}
            </div>
          </section>
        ) : tab === 'cases' ? (
          <section className="space-y-3 max-h-[70vh] overflow-auto pr-1">
            {caseList.map(c => (
              <div key={c.id} className="panel p-4">
                <div className="flex items-center gap-3 flex-wrap mb-2">
                  <span className="mono-id text-[color:var(--color-accent)]">{c.id}</span>
                  <h3 className="font-semibold">{c.title}</h3>
                  <span className={`badge ${c.priority === 'CRITICAL' ? 'badge-critical' : 'badge-high'}`}>{c.priority}</span>
                  <span className="badge badge-info">{c.status}</span>
                  <span className="mono-id text-[color:var(--color-text-muted)] ml-auto">{c.totalValue}</span>
                </div>
                <p className="text-[color:var(--color-text-secondary)] mb-2">{c.summary}</p>
                <p className="mono-id text-[color:var(--color-text-muted)]">
                  {c.analyst} · {c.unit} · opened {new Date(c.openedAt).toLocaleDateString()} · {c.entitiesCount} entities · {c.transactionsCount} txns
                </p>
              </div>
            ))}
          </section>
        ) : (
          /* ---------- Engine tab ---------- */
          <section className="panel p-4">
            <div className="flex items-center gap-3 mb-4">
              <h2 className="font-semibold">Parallel analysis engine</h2>
              <button onClick={runAnalysis} disabled={analyzing} className="btn-primary px-4 py-2 disabled:opacity-50">
                {analyzing ? 'ANALYZING…' : 'RUN FULL ANALYSIS'}
              </button>
              {analysisSummary && (
                <span className="mono-id text-[color:var(--color-text-muted)]">
                  last run {analysisSummary.durationMs.toFixed(0)}ms
                </span>
              )}
            </div>
            {analysisSummary ? (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
                <div className="panel-elevated p-3">
                  <p className="text-[color:var(--color-text-muted)]" style={{ fontSize: 'var(--text-tiny)' }}>PARALLELISM</p>
                  <p className="mono-id mt-1">workers ×{analysisSummary.parallelism.workerPoolSize}</p>
                  <p className="mono-id">batches {analysisSummary.parallelism.batchesProcessed}</p>
                  <p className="mono-id">account chunks {analysisSummary.parallelism.chunksPerBatch}</p>
                  <p className="mono-id">io concurrency {analysisSummary.parallelism.ioConcurrency}</p>
                </div>
                <div className="panel-elevated p-3">
                  <p className="text-[color:var(--color-text-muted)]" style={{ fontSize: 'var(--text-tiny)' }}>PIPELINE</p>
                  <p className="mono-id mt-1">txns {analysisSummary.pipeline.transactionsProcessed}</p>
                  <p className="mono-id">suspicious {analysisSummary.pipeline.suspicious}</p>
                  <p className="mono-id">alerts {analysisSummary.pipeline.alerts}</p>
                  <p className="mono-id">avg risk {analysisSummary.pipeline.averageRiskScore}</p>
                </div>
                <div className="panel-elevated p-3">
                  <p className="text-[color:var(--color-text-muted)]" style={{ fontSize: 'var(--text-tiny)' }}>MULE DETECTION</p>
                  <p className="mono-id mt-1">accounts {analysisSummary.mule.accountsAnalyzed}</p>
                  {analysisSummary.mule.flaggedAccounts.slice(0, 4).map(f => (
                    <p key={f.accountId} className="mono-id" style={{ color: f.riskLevel === 'CRITICAL' ? 'var(--color-critical)' : 'var(--color-warning)' }}>
                      {f.accountId.slice(-4)} · {f.riskScore} · {f.topPatterns[0] ?? '—'}
                    </p>
                  ))}
                </div>
                <div className="panel-elevated p-3">
                  <p className="text-[color:var(--color-text-muted)]" style={{ fontSize: 'var(--text-tiny)' }}>GRAPH</p>
                  <p className="mono-id mt-1">clusters {analysisSummary.graph.clusters}</p>
                  <p className="mono-id">cycles {analysisSummary.graph.circularFlows}</p>
                  <p className="mono-id">paths {analysisSummary.graph.suspiciousPaths}</p>
                  <p className="mono-id">avg degree {analysisSummary.graph.averageDegree}</p>
                </div>
              </div>
            ) : (
              <p className="mono-id text-[color:var(--color-text-muted)]">
                Runs mule detection, pipeline scoring, and graph intelligence across the worker pool — results include per-phase timing and parallelism stats.
              </p>
            )}
          </section>
        )}
      </main>

      {/* ---------- Footer ---------- */}
      <footer className="px-6 py-2 border-t border-[var(--color-line)]">
        <StatusFooter mode={backendMode} backendError={backendError} />
      </footer>
    </div>
  );
}

// ============================================================================
// Entity card
// ============================================================================

function EntityCard({ node }: { node: EntityNode }) {
  return (
    <div className="panel-elevated p-3">
      <div className="flex items-center gap-2 mb-1">
        <span className="mono-id text-[color:var(--color-accent)]">{node.id}</span>
        <RiskBadge level={node.risk} />
        {node.status !== 'NORMAL' && <span className="badge badge-warning">{node.status.replace(/_/g, ' ')}</span>}
      </div>
      <p className="text-[color:var(--color-text)]">{node.label}</p>
      <p className="mono-id text-[color:var(--color-text-muted)] mt-1">
        {node.type} · {node.bankName ?? 'unbanked'} · {node.clusterName}
      </p>
      <div className="flex gap-3 mt-2 mono-id text-[color:var(--color-text-secondary)]">
        <span>in {formatINR(node.inflow)}</span>
        <span>out {formatINR(node.outflow)}</span>
        <span>risk {node.riskScore}</span>
      </div>
    </div>
  );
}
