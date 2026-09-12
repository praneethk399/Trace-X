/**
 * TraceX — Canonical forensic dataset
 * ===================================
 * Deterministic seed network used to bootstrap the app, the backend
 * analysis endpoints, and (via `supabase/schema.sql` + `/api/admin/seed`)
 * the Supabase tables. `formatINR` is the single money formatter every
 * engine imports.
 *
 * @license Apache-2.0
 */

import { EntityNode, TransactionEdge, CaseFile } from '../types/forensics';

// ============================================================================
// FORMATTERS
// ============================================================================

const INR_UNITS = [
  { limit: 1_00_00_000, suffix: 'Cr', divisor: 1_00_00_000 },
  { limit: 1_00_000,    suffix: 'L',  divisor: 1_00_000 },
  { limit: 1_000,       suffix: 'K',  divisor: 1_000 },
] as const;

/** ₹12,34,567 → "₹12.35L" — compact Indian-notation label used across the UI. */
export function formatINR(amount: number): string {
  const abs = Math.abs(amount);
  for (const u of INR_UNITS) {
    if (abs >= u.limit) {
      const value = amount / u.divisor;
      const digits = Math.abs(value) >= 100 ? 0 : 2;
      return `₹${Number(value.toFixed(digits))}${u.suffix}`;
    }
  }
  return `₹${amount.toLocaleString('en-IN')}`;
}

/** ₹1234567 → "₹12,34,567" — full Indian-grouping format. */
export function formatINRFull(amount: number): string {
  return `₹${amount.toLocaleString('en-IN')}`;
}

// ============================================================================
// ENTITY GRAPH — deterministic seed network
// ============================================================================

interface NodeSeed {
  id: string;
  nodeNumber: number;
  label: string;
  type: EntityNode['type'];
  risk: EntityNode['risk'];
  riskScore: number;
  status: EntityNode['status'];
  clusterId: string;
  clusterName: string;
  bankName?: string;
  accountHolder?: string;
  tags?: string[];
}

const NODE_SEEDS: NodeSeed[] = [
  // ---- Cluster 1: Rapid-movement laundering ring -------------------------
  { id: 'ACC-TRX-9281', nodeNumber: 1,  label: 'ACC-9281 (Primary Mule)',            type: 'MULE',         risk: 'CRITICAL', riskScore: 92, status: 'UNDER_SURVEILLANCE', clusterId: 'CL-1', clusterName: 'Rapid Movement Ring',  bankName: 'HDFC Bank',    accountHolder: 'R. Malhotra',  tags: ['mule', 'rapid-movement'] },
  { id: 'ACC-INT-7712', nodeNumber: 2,  label: 'ACC-7712 (Transit Intermediary)',    type: 'INTERMEDIARY', risk: 'HIGH',     riskScore: 78, status: 'FLAGGED',            clusterId: 'CL-1', clusterName: 'Rapid Movement Ring',  bankName: 'ICICI Bank',   accountHolder: 'S. Teotia',    tags: ['transit', 'layering'] },
  { id: 'ACC-INT-4428', nodeNumber: 3,  label: 'ACC-4428 (Clearing Bridge)',         type: 'INTERMEDIARY', risk: 'HIGH',     riskScore: 74, status: 'FLAGGED',            clusterId: 'CL-1', clusterName: 'Rapid Movement Ring',  bankName: 'Axis Bank',    accountHolder: 'K. Bhatia',    tags: ['bridge'] },
  { id: 'ACC-SUB-9912', nodeNumber: 4,  label: 'ACC-9912 (Sub-Treasury)',            type: 'ACCOUNT',      risk: 'MEDIUM',   riskScore: 55, status: 'REVIEW_REQUIRED',    clusterId: 'CL-1', clusterName: 'Rapid Movement Ring',  bankName: 'SBI',          accountHolder: 'V. Enterprises', tags: ['treasury'] },
  { id: 'ACC-VIC-1002', nodeNumber: 5,  label: 'ACC-VIC-1002 (Corporate Victim)',    type: 'ACCOUNT',      risk: 'LOW',      riskScore: 18, status: 'NORMAL',             clusterId: 'CL-1', clusterName: 'Rapid Movement Ring',  bankName: 'Kotak Mahindra', accountHolder: 'Vertex Logistics Pvt Ltd', tags: ['victim'] },
  { id: 'WAL-EXC-9902', nodeNumber: 6,  label: 'WAL-EXC-9902 (Crypto Gateway)',      type: 'EXCHANGE',     risk: 'CRITICAL', riskScore: 95, status: 'UNDER_SURVEILLANCE', clusterId: 'CL-1', clusterName: 'Rapid Movement Ring',  accountHolder: 'Unhosted Offramp', tags: ['offramp', 'crypto', 'gateway'] },

  // ---- Cluster 2: Fan-in/fan-out mule hub --------------------------------
  { id: 'ACC-ML-3310',  nodeNumber: 7,  label: 'ACC-3310 (Mule Hub)',                type: 'MULE',         risk: 'CRITICAL', riskScore: 89, status: 'UNDER_SURVEILLANCE', clusterId: 'CL-2', clusterName: 'Fan Mule Hub',         bankName: 'Paytm Payments Bank', accountHolder: 'A. Sayed', tags: ['mule', 'hub'] },
  { id: 'ACC-IN-1182',  nodeNumber: 8,  label: 'ACC-1182 (Retail Gateway)',          type: 'ACCOUNT',      risk: 'MEDIUM',   riskScore: 48, status: 'REVIEW_REQUIRED',    clusterId: 'CL-2', clusterName: 'Fan Mule Hub',         bankName: 'Yes Bank',     accountHolder: 'M. Retail Ventures', tags: ['fan-in'] },
  { id: 'ACC-IN-2245',  nodeNumber: 9,  label: 'ACC-2245 (Salary aggregation)',      type: 'ACCOUNT',      risk: 'MEDIUM',   riskScore: 44, status: 'NORMAL',             clusterId: 'CL-2', clusterName: 'Fan Mule Hub',         bankName: 'Bandhan Bank', accountHolder: 'P. Services',    tags: ['fan-in'] },
  { id: 'ACC-IN-3391',  nodeNumber: 10, label: 'ACC-3391 (Cash intake)',             type: 'ACCOUNT',      risk: 'MEDIUM',   riskScore: 46, status: 'NORMAL',             clusterId: 'CL-2', clusterName: 'Fan Mule Hub',         bankName: 'IndusInd Bank', accountHolder: 'N. Traders',    tags: ['fan-in'] },
  { id: 'ACC-OUT-6604', nodeNumber: 11, label: 'ACC-6604 (Distribution A)',          type: 'ACCOUNT',      risk: 'HIGH',     riskScore: 66, status: 'FLAGGED',            clusterId: 'CL-2', clusterName: 'Fan Mule Hub',         bankName: 'IDFC First',   accountHolder: 'G. Exports',     tags: ['fan-out'] },
  { id: 'ACC-OUT-7718', nodeNumber: 12, label: 'ACC-7718 (Distribution B)',          type: 'ACCOUNT',      risk: 'HIGH',     riskScore: 63, status: 'FLAGGED',            clusterId: 'CL-2', clusterName: 'Fan Mule Hub',         bankName: 'Federal Bank', accountHolder: 'H. Imports',     tags: ['fan-out'] },
  { id: 'ATM-CASH-5520',nodeNumber: 13, label: 'ATM-5520 (Cash-out Terminal)',       type: 'ATM_CASHOUT',  risk: 'CRITICAL', riskScore: 93, status: 'UNDER_SURVEILLANCE', clusterId: 'CL-2', clusterName: 'Fan Mule Hub',         accountHolder: 'Terminal Cluster NE', tags: ['cashout', 'atm'] },

  // ---- Cluster 3: Circular / shell-corp layering -------------------------
  { id: 'ACC-SH-4021',  nodeNumber: 14, label: 'ACC-4021 (Shell Corp Alpha)',        type: 'SHELL_CORP',   risk: 'CRITICAL', riskScore: 90, status: 'UNDER_SURVEILLANCE', clusterId: 'CL-3', clusterName: 'Shell Layering Cycle', bankName: 'RBL Bank',     accountHolder: 'Alpha Holdings Ltd', tags: ['shell', 'circular'] },
  { id: 'ACC-SH-5132',  nodeNumber: 15, label: 'ACC-5132 (Shell Corp Beta)',         type: 'SHELL_CORP',   risk: 'HIGH',     riskScore: 81, status: 'FLAGGED',            clusterId: 'CL-3', clusterName: 'Shell Layering Cycle', bankName: 'Utkarsh Bank', accountHolder: 'Beta Holdings Ltd', tags: ['shell', 'circular'] },
  { id: 'ACC-SH-6243',  nodeNumber: 16, label: 'ACC-6243 (Shell Corp Gamma)',        type: 'SHELL_CORP',   risk: 'HIGH',     riskScore: 76, status: 'FLAGGED',            clusterId: 'CL-3', clusterName: 'Shell Layering Cycle', bankName: 'Jammu & Kashmir Bank', accountHolder: 'Gamma Holdings Ltd', tags: ['shell', 'circular'] },
  { id: 'ACC-SRC-7354', nodeNumber: 17, label: 'ACC-7354 (Origin Depository)',       type: 'ACCOUNT',      risk: 'MEDIUM',   riskScore: 52, status: 'REVIEW_REQUIRED',    clusterId: 'CL-3', clusterName: 'Shell Layering Cycle', bankName: 'Punjab National Bank', accountHolder: 'Delta Commodities', tags: ['origin'] },
  { id: 'ACC-DST-8465', nodeNumber: 18, label: 'ACC-8465 (Beneficiary Terminal)',    type: 'ACCOUNT',      risk: 'HIGH',     riskScore: 70, status: 'FLAGGED',            clusterId: 'CL-3', clusterName: 'Shell Layering Cycle', bankName: 'Bank of Baroda', accountHolder: 'Epsilon Realty',  tags: ['beneficiary'] },

  // ---- Cluster 4: Dormancy-burst ring ------------------------------------
  { id: 'ACC-DRM-9102', nodeNumber: 19, label: 'ACC-9102 (Dormant → Burst)',         type: 'MULE',         risk: 'CRITICAL', riskScore: 87, status: 'UNDER_SURVEILLANCE', clusterId: 'CL-4', clusterName: 'Dormancy Burst Ring',  bankName: 'AU Small Finance Bank', accountHolder: 'T. Kirana Store', tags: ['dormancy-burst', 'mule'] },
  { id: 'ACC-DRM-0213', nodeNumber: 20, label: 'ACC-0213 (Dormant Relay)',           type: 'INTERMEDIARY', risk: 'HIGH',     riskScore: 68, status: 'FLAGGED',            clusterId: 'CL-4', clusterName: 'Dormancy Burst Ring',  bankName: 'CSB Bank',     accountHolder: 'U. Enterprises', tags: ['dormancy'] },
  { id: 'ACC-NRM-1324', nodeNumber: 21, label: 'ACC-1324 (Merchant Op)',             type: 'MERCHANT',     risk: 'LOW',      riskScore: 12, status: 'NORMAL',             clusterId: 'CL-4', clusterName: 'Dormancy Burst Ring',  bankName: 'HDFC Bank',    accountHolder: 'Saravana Stores', tags: ['merchant', 'baseline'] },
  { id: 'ACC-NRM-2435', nodeNumber: 22, label: 'ACC-2435 (Payroll Corp)',            type: 'ACCOUNT',      risk: 'LOW',      riskScore: 14, status: 'NORMAL',             clusterId: 'CL-4', clusterName: 'Dormancy Burst Ring',  bankName: 'ICICI Bank',   accountHolder: 'Nimbus Software Pvt Ltd', tags: ['payroll', 'baseline'] },
  { id: 'WAL-PRV-3546', nodeNumber: 23, label: 'WAL-3546 (P2P Wallet Dealer)',       type: 'WALLET',       risk: 'HIGH',     riskScore: 72, status: 'REVIEW_REQUIRED',    clusterId: 'CL-4', clusterName: 'Dormancy Burst Ring',  accountHolder: 'P2P Dealer Net', tags: ['wallet', 'p2p'] },
  { id: 'ACC-NRM-4657', nodeNumber: 24, label: 'ACC-4657 (Retail Settlement)',       type: 'MERCHANT',     risk: 'LOW',      riskScore: 16, status: 'NORMAL',             clusterId: 'CL-4', clusterName: 'Dormancy Burst Ring',  bankName: 'Axis Bank',    accountHolder: 'Metro Mart Retail', tags: ['merchant', 'baseline'] },
];

// Deterministic pseudo-random (mulberry32) so seeds are stable across runs.
function seededRandom(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function nodeFromSeed(seed: NodeSeed): EntityNode {
  const rand = seededRandom(seed.nodeNumber * 7919);
  const inflow = Math.round(80_000 + rand() * 900_000);
  const outflow = Math.round(inflow * (0.55 + rand() * 0.75));
  const txCount = Math.round(6 + rand() * 34);
  return {
    id: seed.id,
    nodeNumber: seed.nodeNumber,
    label: seed.label,
    type: seed.type,
    risk: seed.risk,
    riskScore: seed.riskScore,
    status: seed.status,
    transactionCount: txCount,
    inflow,
    outflow,
    balance: Math.round(inflow - outflow + 250_000 + rand() * 500_000),
    firstSeen: `2026-0${1 + (seed.nodeNumber % 6)}-${String(2 + (seed.nodeNumber % 26)).padStart(2, '0')}T09:${String(seed.nodeNumber * 3 % 60).padStart(2, '0')}:00Z`,
    lastActivity: `2026-09-11T1${seed.nodeNumber % 9}:${String((seed.nodeNumber * 7) % 60).padStart(2, '0')}:22Z`,
    clusterId: seed.clusterId,
    clusterName: seed.clusterName,
    x: 120 + (seed.nodeNumber % 4) * 220 + Math.round(rand() * 60),
    y: 90 + Math.floor((seed.nodeNumber - 1) / 4) * 170 + Math.round(rand() * 40),
    riskIndicators: seed.riskScore >= 80
      ? ['Unusual velocity', 'Layered inflow', 'High-risk counterparties']
      : seed.riskScore >= 60
        ? ['Elevated inflow ratio', 'Cross-cluster transfers']
        : ['Baseline behaviour'],
    tags: seed.tags ?? [],
    bankName: seed.bankName,
    jurisdiction: seed.nodeNumber % 5 === 0 ? 'SG' : 'IN',
    ipAddress: `10.${seed.nodeNumber}.${seed.nodeNumber * 3 % 250}.${(seed.nodeNumber * 17) % 250}`,
    deviceFingerprint: `fp-${(seed.nodeNumber * 8191).toString(16).padStart(6, '0')}`,
    accountHolder: seed.accountHolder,
  };
}

export const ENTITY_NODES: EntityNode[] = NODE_SEEDS.map(nodeFromSeed);

// ============================================================================
// TRANSACTION EDGES — deterministic seed flows
// ============================================================================

interface EdgeSeed {
  source: string;
  target: string;
  type: TransactionEdge['type'];
  amount: number;
  time: string;
  risk?: TransactionEdge['risk'];
  flowStatus?: TransactionEdge['flowStatus'];
  pattern?: string;
}

const EDGE_SEEDS: EdgeSeed[] = [
  // Rapid-movement ring
  { source: 'ACC-VIC-1002', target: 'ACC-TRX-9281', type: 'RTGS', amount: 250_000, time: '17:54:11', pattern: 'Unusual Transaction Amount' },
  { source: 'ACC-TRX-9281', target: 'ACC-INT-7712', type: 'IMPS', amount: 245_000, time: '17:55:02', risk: 'HIGH', pattern: 'Rapid Money Movement' },
  { source: 'ACC-INT-7712', target: 'ACC-INT-4428', type: 'IMPS', amount: 240_000, time: '17:56:19', risk: 'HIGH', pattern: 'Rapid Money Movement' },
  { source: 'ACC-INT-4428', target: 'ACC-SUB-9912', type: 'NEFT', amount: 235_000, time: '17:57:40' },
  { source: 'ACC-INT-4428', target: 'WAL-EXC-9902', type: 'RTGS', amount: 450_000, time: '17:50:22', risk: 'CRITICAL', flowStatus: 'FLAGGED', pattern: 'High-Risk Gateway Settlement' },
  { source: 'ACC-TRX-9281', target: 'WAL-EXC-9902', type: 'RTGS', amount: 120_000, time: '17:58:31', risk: 'CRITICAL', flowStatus: 'FLAGGED', pattern: 'High-Risk Gateway Settlement' },

  // Fan-in / fan-out hub
  { source: 'ACC-IN-1182',  target: 'ACC-ML-3310',  type: 'NEFT', amount: 84_000,  time: '11:02:10', pattern: 'Fan-In Pattern' },
  { source: 'ACC-IN-2245',  target: 'ACC-ML-3310',  type: 'NEFT', amount: 91_500,  time: '11:04:44', pattern: 'Fan-In Pattern' },
  { source: 'ACC-IN-3391',  target: 'ACC-ML-3310',  type: 'UPI',  amount: 76_200,  time: '11:07:21', pattern: 'Fan-In Pattern' },
  { source: 'ACC-NRM-2435', target: 'ACC-ML-3310',  type: 'UPI',  amount: 64_900,  time: '11:09:03' },
  { source: 'ACC-ML-3310',  target: 'ACC-OUT-6604', type: 'IMPS', amount: 120_000, time: '11:11:37', risk: 'HIGH', pattern: 'Fan-Out Pattern' },
  { source: 'ACC-ML-3310',  target: 'ACC-OUT-7718', type: 'IMPS', amount: 118_500, time: '11:12:02', risk: 'HIGH', pattern: 'Fan-Out Pattern' },
  { source: 'ACC-ML-3310',  target: 'ATM-CASH-5520',type: 'IMPS', amount: 96_000,  time: '11:13:29', risk: 'CRITICAL', flowStatus: 'FLAGGED', pattern: 'ATM Cash-Out' },
  { source: 'ACC-OUT-6604', target: 'ATM-CASH-5520',type: 'UPI',  amount: 41_000,  time: '11:15:55', risk: 'HIGH' },

  // Circular shell-corp cycle: 7354 → 4021 → 5132 → 6243 → 4021 … → 8465
  { source: 'ACC-SRC-7354', target: 'ACC-SH-4021',  type: 'RTGS', amount: 480_000, time: '09:14:00', pattern: 'Layering' },
  { source: 'ACC-SH-4021',  target: 'ACC-SH-5132',  type: 'RTGS', amount: 465_000, time: '09:31:12', risk: 'HIGH', pattern: 'Circular Transfer' },
  { source: 'ACC-SH-5132',  target: 'ACC-SH-6243',  type: 'RTGS', amount: 452_000, time: '09:47:48', risk: 'HIGH', pattern: 'Circular Transfer' },
  { source: 'ACC-SH-6243',  target: 'ACC-SH-4021',  type: 'RTGS', amount: 440_000, time: '10:02:19', risk: 'CRITICAL', flowStatus: 'FLAGGED', pattern: 'Circular Transfer' },
  { source: 'ACC-SH-5132',  target: 'ACC-DST-8465', type: 'RTGS', amount: 310_000, time: '10:11:41', risk: 'HIGH' },

  // Dormancy burst ring
  { source: 'ACC-DRM-9102', target: 'ACC-DRM-0213', type: 'RTGS', amount: 720_000, time: '03:12:44', risk: 'CRITICAL', flowStatus: 'FLAGGED', pattern: 'Dormancy Burst' },
  { source: 'ACC-DRM-0213', target: 'WAL-PRV-3546', type: 'IMPS', amount: 340_000, time: '03:19:02', risk: 'HIGH' },
  { source: 'ACC-NRM-1324', target: 'ACC-DRM-9102', type: 'CARD', amount: 38_400,  time: '03:02:17' },
  { source: 'ACC-NRM-2435', target: 'ACC-NRM-1324', type: 'UPI',  amount: 9_200,   time: '12:40:00' },
  { source: 'ACC-NRM-4657', target: 'ACC-NRM-1324', type: 'UPI',  amount: 12_700,  time: '13:15:33' },
  { source: 'ACC-DRM-0213', target: 'ACC-NRM-4657', type: 'NEFT', amount: 155_000, time: '03:26:51', risk: 'MEDIUM' },
];

function edgeFromSeed(seed: EdgeSeed, index: number): TransactionEdge {
  return {
    id: `TXN-${String(index + 1).padStart(4, '0')}-${seed.source.split('-').pop()}`,
    source: seed.source,
    target: seed.target,
    type: seed.type,
    amount: seed.amount,
    formattedAmount: formatINR(seed.amount),
    timestamp: seed.time,
    risk: seed.risk ?? (seed.amount >= 200_000 ? 'HIGH' : seed.amount >= 100_000 ? 'MEDIUM' : 'LOW'),
    flowStatus: seed.flowStatus ?? (seed.pattern ? 'FLAGGED' : 'SETTLED'),
    hash: `0x${(index * 2654435761 >>> 0).toString(16).padStart(8, '0')}${(index * 40503 >>> 0).toString(16).padStart(4, '0')}`,
    suspiciousPattern: seed.pattern,
  };
}

export const TRANSACTION_EDGES: TransactionEdge[] = EDGE_SEEDS.map(edgeFromSeed);

// ============================================================================
// CASE FILES
// ============================================================================

export const CASE_FILES: CaseFile[] = [
  {
    id: 'CASE-0001',
    title: 'Rapid Movement Ring — ACC-9281',
    status: 'ACTIVE INVESTIGATION',
    priority: 'CRITICAL',
    analyst: 'A. Verma',
    unit: 'FORENSICS-ANALYST-UNIT-4',
    openedAt: '2026-09-08T14:22:00Z',
    entitiesCount: 6,
    transactionsCount: 6,
    flaggedCount: 3,
    totalValue: '₹15.4L',
    summary:
      'Layered rapid movement ring moving corporate victim funds through a mule chain into an unhosted crypto gateway. Dwell times under 90 seconds per hop.',
    evidence: [
      { id: 'EV-001', title: 'Dwell-time analysis', type: 'TEMPORAL', timestamp: '2026-09-08T14:30:00Z', confidence: 91, description: 'Average inter-hop dwell time 88s across 4 hops — far below the 14-minute baseline.' },
      { id: 'EV-002', title: 'Gateway settlement', type: 'NETWORK', timestamp: '2026-09-08T14:41:00Z', confidence: 96, description: 'Direct settlement into WAL-EXC-9902 unhosted offramp (2 flows, ₹5.7L).' },
      { id: 'EV-003', title: 'Victim deposit anomaly', type: 'TRANSACTION', timestamp: '2026-09-08T15:02:00Z', confidence: 84, description: 'ACC-VIC-1002 RTGS of ₹2.5L is +340% above its historical outflow baseline.' },
    ],
    activityLog: [
      { id: 'AL-001', timestamp: '2026-09-08T14:22:00Z', analyst: 'A. Verma', action: 'Case opened from alert ALT-CRIT-9281', tag: 'OPENED' },
      { id: 'AL-002', timestamp: '2026-09-09T09:12:00Z', analyst: 'A. Verma', action: 'Trace topology discovered — 4 hops to offramp', tag: 'ANALYSIS' },
      { id: 'AL-003', timestamp: '2026-09-10T16:48:00Z', analyst: 'R. Iyer', action: 'Escalation draft prepared for FIU review', tag: 'ESCALATION' },
    ],
  },
  {
    id: 'CASE-0002',
    title: 'Fan Mule Hub — ACC-3310',
    status: 'ESCALATED_FIU',
    priority: 'HIGH',
    analyst: 'R. Iyer',
    unit: 'FORENSICS-ANALYST-UNIT-2',
    openedAt: '2026-09-05T10:05:00Z',
    entitiesCount: 7,
    transactionsCount: 8,
    flaggedCount: 4,
    totalValue: '₹8.9L',
    summary:
      'Central mule hub aggregating retail fan-in deposits and distributing to fan-out beneficiaries plus an ATM cash-out terminal.',
    evidence: [
      { id: 'EV-101', title: 'Fan-in degree', type: 'NETWORK', timestamp: '2026-09-05T10:20:00Z', confidence: 88, description: '4 unrelated senders from 2+ clusters feed the hub within 9 minutes.' },
      { id: 'EV-102', title: 'Cash-out terminal linkage', type: 'NETWORK', timestamp: '2026-09-05T10:31:00Z', confidence: 93, description: 'Hub and Distribution A both settle into ATM-CASH-5520.' },
    ],
    activityLog: [
      { id: 'AL-101', timestamp: '2026-09-05T10:05:00Z', analyst: 'R. Iyer', action: 'Case opened from mule-hub detection', tag: 'OPENED' },
      { id: 'AL-102', timestamp: '2026-09-06T11:44:00Z', analyst: 'R. Iyer', action: 'Confirmed fan-in/fan-out convergence — escalated to FIU', tag: 'ESCALATION' },
    ],
  },
  {
    id: 'CASE-0003',
    title: 'Shell Layering Cycle — CL-3',
    status: 'CLOSED',
    priority: 'HIGH',
    analyst: 'M. Chatterjee',
    unit: 'FORENSICS-ANALYST-UNIT-1',
    openedAt: '2026-08-27T08:40:00Z',
    entitiesCount: 5,
    transactionsCount: 5,
    flaggedCount: 2,
    totalValue: '₹21.5L',
    summary:
      'Three-shell circular RTGS cycle cycling ₹4.4L+ back to origin while skimming to a beneficiary terminal. Cycle broken and accounts frozen.',
    evidence: [
      { id: 'EV-201', title: 'Cycle topology', type: 'PATTERN', timestamp: '2026-08-27T09:00:00Z', confidence: 97, description: 'Directed cycle ACC-4021 → ACC-5132 → ACC-6243 → ACC-4021 confirmed.' },
      { id: 'EV-202', title: 'Registration cross-match', type: 'BEHAVIOURAL', timestamp: '2026-08-27T09:35:00Z', confidence: 82, description: 'All three shells share device fingerprint fp-02b41c and /8 IP block.' },
    ],
    activityLog: [
      { id: 'AL-201', timestamp: '2026-08-27T08:40:00Z', analyst: 'M. Chatterjee', action: 'Case opened from circular-flow detector', tag: 'OPENED' },
      { id: 'AL-202', timestamp: '2026-08-29T14:10:00Z', analyst: 'M. Chatterjee', action: 'Freeze requests filed for all shell accounts', tag: 'ACTION' },
      { id: 'AL-203', timestamp: '2026-09-01T17:30:00Z', analyst: 'M. Chatterjee', action: 'Case closed — assets frozen, report archived', tag: 'CLOSED' },
    ],
  },
];

export const CURRENT_ANALYST = { name: 'A. Verma', unit: 'FORENSICS-ANALYST-UNIT-4' };

export const NETWORK_SNAPSHOT = {
  generatedAt: '2026-09-11T18:00:00Z',
  nodes: ENTITY_NODES,
  edges: TRANSACTION_EDGES,
  cases: CASE_FILES,
};
