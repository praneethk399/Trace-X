/**
 * TraceX design tokens — JS/TS mirror of globals.css
 * ====================================================
 * Tailwind utility classes cover JSX markup, but the money-trail
 * graph (ReactFlow canvas) and any three.js/WebGL surfaces need raw
 * values in JavaScript. This file is the single place those values
 * live so the graph never silently drifts from the rest of the UI.
 *
 * If a color changes in globals.css, mirror the change here too —
 * there are exactly two source-of-truth files by design (one CSS,
 * one JS), not one per component.
 */

export const colors = {
  base: "#030303",
  app: "#050607",
  surface: "#09090b",
  surface2: "#0d0f12",
  elevated: "#111418",

  line: "#1f1f23",
  lineStrong: "#29292f",
  lineHair: "rgba(255,255,255,0.07)",

  text: "#f4f4f5",
  textSecondary: "#a1a1aa",
  textMuted: "#71717a",

  accent: "#00d2ff",
  critical: "#ff2a5f",
  risk: "#ff5c5c",
  warning: "#f5a524",
  success: "#22c55e",
} as const;

export const radius = {
  sm: 8,
  md: 10,
  lg: 12,
  xl: 14,
} as const;

export const motion = {
  easeTrace: "cubic-bezier(0.16, 1, 0.3, 1)",
  fast: 120,
  base: 180,
  slow: 320,
} as const;

export type RiskLevel = "info" | "success" | "warning" | "high" | "critical";

/** Maps a risk/severity level to its badge + graph-node color. */
export const riskColor: Record<RiskLevel, string> = {
  info: colors.textSecondary,
  success: colors.success,
  warning: colors.warning,
  high: colors.risk,
  critical: colors.critical,
};

/**
 * Money-trail graph node visual states (brief section 13).
 * Consumed by the ReactFlow node renderer — kept separate from
 * `colors` because a node's *state* (selected vs. dimmed) is a
 * different axis from its *risk level* and the two combine, e.g. a
 * CRITICAL node that is also DIMMED because it's outside the
 * current selection's neighborhood.
 */
export const graphNodeState = {
  default:   { border: colors.line,       opacity: 1 },
  hover:     { border: colors.lineStrong, opacity: 1 },
  selected:  { border: colors.accent,     opacity: 1 },
  connected: { border: colors.accent,     opacity: 0.9 },
  dimmed:    { border: colors.line,       opacity: 0.35 },
} as const;
