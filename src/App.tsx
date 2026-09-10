/**
 * TEMPORARY PREVIEW HARNESS — not a real TraceX screen.
 * ========================================================
 * The actual TraceX source (Overview, Investigations, Money Trail,
 * Transactions, Accounts, Alerts, Evidence, Reports, Data
 * Ingestion, Audit Log, Engine Settings, Login, and their real data
 * and routing) was not present in this repository — only the
 * build config (package.json, tailwind.config.ts, vite.config.ts,
 * tsconfig.json, index.html) had been committed, with no `src/`.
 *
 * This file exists only to prove the new design-token foundation
 * (src/styles/globals.css + tokens.ts) actually compiles and
 * renders correctly, and to give a visual reference sheet for the
 * color, type, radius, badge, and nav-item system defined in the
 * TraceX redesign brief. Delete this file and wire up react-router
 * + the real screens once the actual source is restored here.
 */

import { colors, riskColor, type RiskLevel } from "./styles/tokens";

const swatches: { label: string; varName: string; hex: string }[] = [
  { label: "base", varName: "--color-base", hex: colors.base },
  { label: "app", varName: "--color-app", hex: colors.app },
  { label: "surface", varName: "--color-surface", hex: colors.surface },
  { label: "surface-2", varName: "--color-surface-2", hex: colors.surface2 },
  { label: "elevated", varName: "--color-elevated", hex: colors.elevated },
  { label: "line", varName: "--color-line", hex: colors.line },
  { label: "line-strong", varName: "--color-line-strong", hex: colors.lineStrong },
  { label: "text", varName: "--color-text", hex: colors.text },
  { label: "text-secondary", varName: "--color-text-secondary", hex: colors.textSecondary },
  { label: "text-muted", varName: "--color-text-muted", hex: colors.textMuted },
  { label: "accent", varName: "--color-accent", hex: colors.accent },
  { label: "critical", varName: "--color-critical", hex: colors.critical },
  { label: "risk (high)", varName: "--color-risk", hex: colors.risk },
  { label: "warning", varName: "--color-warning", hex: colors.warning },
  { label: "success", varName: "--color-success", hex: colors.success },
];

const severities: RiskLevel[] = ["info", "success", "warning", "high", "critical"];
const navItems = ["Overview", "Investigations", "Money Trail", "Transactions"];

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-12">
      <h2
        className="mb-4 font-semibold text-[color:var(--color-text)]"
        style={{ fontSize: "var(--text-section-title)" }}
      >
        {title}
      </h2>
      {children}
    </section>
  );
}

export default function App() {
  return (
    <div className="min-h-screen px-8 py-10 max-w-[1000px] mx-auto">
      <header className="mb-10">
        <p className="mono-id text-[color:var(--color-text-muted)] mb-2">
          TRACE X // DESIGN SYSTEM PREVIEW
        </p>
        <h1
          className="font-semibold text-[color:var(--color-text)]"
          style={{
            fontSize: "var(--text-page-title)",
            lineHeight: "var(--text-page-title--line-height)",
            letterSpacing: "var(--text-page-title--letter-spacing)",
          }}
        >
          Token foundation
        </h1>
        <p className="text-[color:var(--color-text-secondary)] mt-2 max-w-[60ch]">
          This is a build-verification harness, not a product screen. It confirms
          the color, type, radius, badge, and nav primitives from the redesign
          brief compile and render before any real screens are wired up.
        </p>
      </header>

      <Section title="Color">
        <div className="grid grid-cols-3 sm:grid-cols-5 gap-3">
          {swatches.map((s) => (
            <div key={s.varName} className="panel p-3">
              <div
                className="h-12 mb-2 rounded-[var(--radius-sm)] border"
                style={{ background: s.hex, borderColor: "var(--color-line)" }}
              />
              <p className="text-[color:var(--color-text)] text-[0.75rem] font-medium">{s.label}</p>
              <p className="mono-id text-[color:var(--color-text-muted)]">{s.hex}</p>
            </div>
          ))}
        </div>
      </Section>

      <Section title="Typography">
        <div className="panel p-5 space-y-3">
          <p style={{ fontSize: "var(--text-page-title)", fontWeight: 600 }}>Page title — 28px / 600</p>
          <p style={{ fontSize: "var(--text-section-title)", fontWeight: 600 }}>Section title — 16px / 600</p>
          <p style={{ fontSize: "var(--text-body)" }}>Body — 13px. The quick brown fox jumps over the lazy dog.</p>
          <p style={{ fontSize: "var(--text-secondary)", color: "var(--color-text-secondary)" }}>
            Secondary information — 12px
          </p>
          <p className="mono-id" style={{ color: "var(--color-text-secondary)" }}>
            ACC-CONV-9017 · TXN-11162 · 2026-09-11T10:42:00Z
          </p>
          <p
            style={{
              fontSize: "var(--text-tiny)",
              letterSpacing: "var(--text-tiny--letter-spacing)",
              color: "var(--color-text-muted)",
            }}
            className="uppercase font-medium"
          >
            Tiny label
          </p>
        </div>
      </Section>

      <Section title="Severity badges">
        <div className="flex flex-wrap gap-2">
          {severities.map((s) => (
            <span key={s} className={`badge badge-${s === "high" ? "high" : s}`}>
              {s}
            </span>
          ))}
        </div>
      </Section>

      <Section title="Navigation states">
        <nav className="panel p-2 max-w-[220px] space-y-1">
          {navItems.map((item, i) => (
            <div key={item} className="nav-item" data-active={i === 2}>
              <span
                className="w-1.5 h-1.5 rounded-full"
                style={{ background: i === 2 ? "var(--color-accent)" : "var(--color-line-strong)" }}
              />
              {item}
            </div>
          ))}
          <div className="nav-item" data-disabled="true">
            Reports
          </div>
        </nav>
      </Section>

      <Section title="Surfaces &amp; primary action">
        <div className="flex flex-wrap gap-4 items-start">
          <div className="panel p-4 w-48">
            <p className="text-[0.75rem] text-[color:var(--color-text-secondary)]">panel</p>
          </div>
          <div className="panel-elevated p-4 w-48">
            <p className="text-[0.75rem] text-[color:var(--color-text-secondary)]">panel-elevated</p>
          </div>
          <button className="btn-primary px-4 py-2 text-[0.8125rem]">Trace Money Trail</button>
        </div>
      </Section>

      <Section title="Risk → color mapping (tokens.ts)">
        <div className="flex gap-2 flex-wrap">
          {severities.map((s) => (
            <div key={s} className="panel px-3 py-2 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full" style={{ background: riskColor[s] }} />
              <span className="mono-id" style={{ color: "var(--color-text-secondary)" }}>
                riskColor.{s}
              </span>
            </div>
          ))}
        </div>
      </Section>
    </div>
  );
}
