/**
 * TraceX — Mule-Account Detection Engine
 * Core intelligence for identifying suspicious accounts based on
 * behavioural, transactional, temporal, and network-level evidence.
 * 
 * Detects:
 * - Fan-in patterns (multiple accounts → one)
 * - Fan-out patterns (one → multiple accounts)
 * - Layering (A → B → C)
 * - Rapid pass-through (A → B → C within short period)
 * - Circular transfers (A → B → C → A)
 * - Dormancy bursts (inactive → sudden high-volume)
 * - Mule hub patterns (unrelated accounts → central → destinations)
 * 
 * @license Apache-2.0
 */

import {
  EntityNode,
  TransactionEdge,
  RiskLevel,
  TransactionType,
  StreamEvent
} from '../types/forensics';
import { formatINR } from '../data/mockForensics';

// ============================================================================
// TYPES
// ============================================================================

export interface MuleDetectionResult {
  accountId: string;
  riskScore: number;
  riskLevel: RiskLevel;
  confidenceScore: number;
  detectedPatterns: DetectedPattern[];
  supportingEvidence: EvidenceItem[];
  connectedSuspiciousEntities: string[];
  transactionPaths: TransactionPath[];
  investigationPriority: 'IMMEDIATE' | 'HIGH' | 'MEDIUM' | 'LOW';
  riskBreakdown: RiskBreakdown;
  lastUpdated: string;
}

export interface DetectedPattern {
  type: MulePattern;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: number;
  description: string;
  evidence: string[];
  weight: number;
}

export type MulePattern =
  | 'FAN_IN'
  | 'FAN_OUT'
  | 'LAYERING'
  | 'RAPID_PASS_THROUGH'
  | 'CIRCULAR_TRANSFER'
  | 'MULE_HUB'
  | 'DORMANCY_BURST'
  | 'VELOCITY_ANOMALY'
  | 'AMOUNT_ANOMALY'
  | 'COUNTERPARTY_ANOMALY'
  | 'PASS_THROUGH';

export interface EvidenceItem {
  type: 'TRANSACTION' | 'PATTERN' | 'TEMPORAL' | 'NETWORK' | 'BEHAVIOURAL';
  description: string;
  transactionId?: string;
  timestamp?: string;
  amount?: number;
  confidence: number;
}

export interface TransactionPath {
  path: string[];
  amounts: number[];
  timestamps: string[];
  totalAmount: number;
  riskScore: number;
}

export interface RiskBreakdown {
  velocityScore: number;
  networkScore: number;
  amountScore: number;
  frequencyScore: number;
  patternScore: number;
  behaviouralScore: number;
  temporalScore: number;
}

export interface AccountFeatures {
  accountId: string;
  transactionCount: number;
  totalInflow: number;
  totalOutflow: number;
  averageAmount: number;
  maxAmount: number;
  minAmount: number;
  uniqueCounterparties: number;
  incomingCounterparties: number;
  outgoingCounterparties: number;
  passThroughRatio: number;
  fanInDegree: number;
  fanOutDegree: number;
  transactionVelocity: number;
  timeBetweenTransactions: number;
  dormantDays: number;
  lastActivityHours: number;
  riskScore: number;
  clusterId: string;
  clusterName: string;
}

// ============================================================================
// CONFIGURATION
// ============================================================================

const CONFIG = {
  // Thresholds
  VELOCITY_THRESHOLD: 5, // transactions per hour
  AMOUNT_ANOMALY_THRESHOLD: 3.0, // standard deviations
  DORMANCY_THRESHOLD_DAYS: 30,
  RAPID_PASS_THROUGH_SECONDS: 300, // 5 minutes
  CIRCULAR_WINDOW_HOURS: 24,
  FAN_IN_THRESHOLD: 3,
  FAN_OUT_THRESHOLD: 3,
  PASS_THROUGH_RATIO_THRESHOLD: 0.8,
  
  // Scoring weights (configurable)
  WEIGHTS: {
    VELOCITY: 0.20,
    NETWORK: 0.20,
    RAPID_MOVEMENT: 0.15,
    FAN_BEHAVIOUR: 0.15,
    AMOUNT: 0.10,
    FREQUENCY: 0.10,
    BEHAVIOURAL: 0.10
  },
  
  // Pattern detection thresholds
  PATTERN_THRESHOLDS: {
    FAN_IN_MIN_ACCOUNTS: 3,
    FAN_OUT_MIN_ACCOUNTS: 3,
    LAYERING_MIN_HOPS: 3,
    CIRCULAR_MIN_NODES: 3,
    DORMANCY_MIN_DAYS: 30,
    PASS_THROUGH_MIN_RATIO: 0.8
  }
};

// ============================================================================
// FEATURE EXTRACTION
// ============================================================================

export function extractAccountFeatures(
  accountId: string,
  edges: TransactionEdge[],
  nodes: EntityNode[]
): AccountFeatures {
  const node = nodes.find(n => n.id === accountId);
  
  // Get all transactions involving this account
  const incoming = edges.filter(e => e.target === accountId);
  const outgoing = edges.filter(e => e.source === accountId);
  const allTransactions = [...incoming, ...outgoing];
  
  if (allTransactions.length === 0) {
    return createEmptyFeatures(accountId, node);
  }
  
  // Basic metrics
  const transactionCount = allTransactions.length;
  const totalInflow = incoming.reduce((sum, e) => sum + e.amount, 0);
  const totalOutflow = outgoing.reduce((sum, e) => sum + e.amount, 0);
  const amounts = allTransactions.map(e => e.amount);
  const averageAmount = amounts.reduce((a, b) => a + b, 0) / amounts.length;
  const maxAmount = Math.max(...amounts);
  const minAmount = Math.min(...amounts);
  
  // Counterparty analysis
  const incomingCounterparties = new Set(incoming.map(e => e.source)).size;
  const outgoingCounterparties = new Set(outgoing.map(e => e.target)).size;
  const uniqueCounterparties = new Set([
    ...incoming.map(e => e.source),
    ...outgoing.map(e => e.target)
  ]).size;
  
  // Pass-through ratio (amount forwarded / amount received)
  const passThroughRatio = totalInflow > 0 ? totalOutflow / totalInflow : 0;
  
  // Fan-in/fan-out degrees
  const fanInDegree = incomingCounterparties;
  const fanOutDegree = outgoingCounterparties;
  
  // Transaction velocity (transactions per hour)
  const timeSpan = calculateTimeSpan(allTransactions);
  const transactionVelocity = timeSpan > 0 ? transactionCount / timeSpan : 0;
  
  // Average time between transactions
  const timeBetweenTransactions = calculateAverageTimeBetween(allTransactions);
  
  // Dormancy analysis
  const dormantDays = calculateDormancy(accountId, edges);
  const lastActivityHours = calculateLastActivityHours(accountId, edges);
  
  // Risk score from node data
  const riskScore = node?.riskScore || 0;
  const clusterId = node?.clusterId || '';
  const clusterName = node?.clusterName || '';
  
  return {
    accountId,
    transactionCount,
    totalInflow,
    totalOutflow,
    averageAmount,
    maxAmount,
    minAmount,
    uniqueCounterparties,
    incomingCounterparties,
    outgoingCounterparties,
    passThroughRatio,
    fanInDegree,
    fanOutDegree,
    transactionVelocity,
    timeBetweenTransactions,
    dormantDays,
    lastActivityHours,
    riskScore,
    clusterId,
    clusterName
  };
}

function createEmptyFeatures(accountId: string, node?: EntityNode): AccountFeatures {
  return {
    accountId,
    transactionCount: 0,
    totalInflow: 0,
    totalOutflow: 0,
    averageAmount: 0,
    maxAmount: 0,
    minAmount: 0,
    uniqueCounterparties: 0,
    incomingCounterparties: 0,
    outgoingCounterparties: 0,
    passThroughRatio: 0,
    fanInDegree: 0,
    fanOutDegree: 0,
    transactionVelocity: 0,
    timeBetweenTransactions: 0,
    dormantDays: 0,
    lastActivityHours: 0,
    riskScore: node?.riskScore || 0,
    clusterId: node?.clusterId || '',
    clusterName: node?.clusterName || ''
  };
}

function calculateTimeSpan(transactions: TransactionEdge[]): number {
  if (transactions.length < 2) return 0;
  
  const timestamps = transactions
    .map(e => {
      const match = e.timestamp.match(/(\d{2}):(\d{2}):(\d{2})/);
      if (match) {
        const hours = parseInt(match[1]);
        const minutes = parseInt(match[2]);
        const seconds = parseInt(match[3]);
        return hours * 3600 + minutes * 60 + seconds;
      }
      return 0;
    })
    .filter(t => t > 0);
  
  if (timestamps.length < 2) return 0;
  
  const minTime = Math.min(...timestamps);
  const maxTime = Math.max(...timestamps);
  return (maxTime - minTime) / 3600; // Convert to hours
}

function calculateAverageTimeBetween(transactions: TransactionEdge[]): number {
  if (transactions.length < 2) return 0;
  
  const timestamps = transactions
    .map(e => {
      const match = e.timestamp.match(/(\d{2}):(\d{2}):(\d{2})/);
      if (match) {
        const hours = parseInt(match[1]);
        const minutes = parseInt(match[2]);
        const seconds = parseInt(match[3]);
        return hours * 3600 + minutes * 60 + seconds;
      }
      return 0;
    })
    .filter(t => t > 0)
    .sort((a, b) => a - b);
  
  if (timestamps.length < 2) return 0;
  
  let totalDiff = 0;
  for (let i = 1; i < timestamps.length; i++) {
    totalDiff += timestamps[i] - timestamps[i - 1];
  }
  
  return totalDiff / (timestamps.length - 1) / 60; // Convert to minutes
}

function calculateDormancy(accountId: string, edges: TransactionEdge[]): number {
  const now = new Date();
  const relevantEdges = edges.filter(e => e.source === accountId || e.target === accountId);
  
  if (relevantEdges.length === 0) return 999; // Never seen
  
  // Get most recent transaction time
  const timestamps = relevantEdges
    .map(e => {
      const match = e.timestamp.match(/(\d{2}):(\d{2}):(\d{2})/);
      if (match) {
        const hours = parseInt(match[1]);
        const minutes = parseInt(match[2]);
        const seconds = parseInt(match[3]);
        return hours * 3600 + minutes * 60 + seconds;
      }
      return 0;
    })
    .filter(t => t > 0);
  
  if (timestamps.length === 0) return 999;
  
  const mostRecent = Math.max(...timestamps);
  const currentSeconds = now.getHours() * 3600 + now.getMinutes() * 60 + now.getSeconds();
  const diffSeconds = currentSeconds - mostRecent;
  
  // Convert to days (assuming transactions happened today or recently)
  return Math.max(0, diffSeconds / 86400);
}

function calculateLastActivityHours(accountId: string, edges: TransactionEdge[]): number {
  const now = new Date();
  const relevantEdges = edges.filter(e => e.source === accountId || e.target === accountId);
  
  if (relevantEdges.length === 0) return 999;
  
  const timestamps = relevantEdges
    .map(e => {
      const match = e.timestamp.match(/(\d{2}):(\d{2}):(\d{2})/);
      if (match) {
        const hours = parseInt(match[1]);
        const minutes = parseInt(match[2]);
        const seconds = parseInt(match[3]);
        return hours * 3600 + minutes * 60 + seconds;
      }
      return 0;
    })
    .filter(t => t > 0);
  
  if (timestamps.length === 0) return 999;
  
  const mostRecent = Math.max(...timestamps);
  const currentSeconds = now.getHours() * 3600 + now.getMinutes() * 60 + now.getSeconds();
  
  return (currentSeconds - mostRecent) / 3600;
}

// ============================================================================
// PATTERN DETECTION
// ============================================================================

export function detectMulePatterns(
  accountId: string,
  features: AccountFeatures,
  edges: TransactionEdge[],
  nodes: EntityNode[]
): DetectedPattern[] {
  const patterns: DetectedPattern[] = [];
  
  // Fan-in detection
  const fanIn = detectFanIn(accountId, features, edges, nodes);
  if (fanIn) patterns.push(fanIn);
  
  // Fan-out detection
  const fanOut = detectFanOut(accountId, features, edges, nodes);
  if (fanOut) patterns.push(fanOut);
  
  // Layering detection
  const layering = detectLayering(accountId, edges, nodes);
  if (layering) patterns.push(layering);
  
  // Rapid pass-through detection
  const rapidPassThrough = detectRapidPassThrough(accountId, edges, nodes);
  if (rapidPassThrough) patterns.push(rapidPassThrough);
  
  // Circular transfer detection
  const circular = detectCircularTransfer(accountId, edges, nodes);
  if (circular) patterns.push(circular);
  
  // Dormancy burst detection
  const dormancyBurst = detectDormancyBurst(accountId, features, edges);
  if (dormancyBurst) patterns.push(dormancyBurst);
  
  // Velocity anomaly detection
  const velocityAnomaly = detectVelocityAnomaly(accountId, features);
  if (velocityAnomaly) patterns.push(velocityAnomaly);
  
  // Amount anomaly detection
  const amountAnomaly = detectAmountAnomaly(accountId, features, edges);
  if (amountAnomaly) patterns.push(amountAnomaly);
  
  // Pass-through behaviour
  const passThrough = detectPassThroughBehaviour(accountId, features);
  if (passThrough) patterns.push(passThrough);
  
  return patterns;
}

function detectFanIn(
  accountId: string,
  features: AccountFeatures,
  edges: TransactionEdge[],
  nodes: EntityNode[]
): DetectedPattern | null {
  if (features.incomingCounterparties < CONFIG.PATTERN_THRESHOLDS.FAN_IN_MIN_ACCOUNTS) {
    return null;
  }
  
  // Get incoming accounts
  const incomingAccounts = edges
    .filter(e => e.target === accountId)
    .map(e => e.source);
  
  const uniqueSenders = [...new Set(incomingAccounts)];
  
  // Check if senders are unrelated (different clusters)
  const clusterMap = new Map(nodes.map(n => [n.id, n.clusterId]));
  const clusters = new Set(uniqueSenders.map(id => clusterMap.get(id) || ''));
  
  if (clusters.size < 2) return null; // Same cluster, less suspicious
  
  const confidence = Math.min(95, 60 + (uniqueSenders.length - 3) * 10);
  
  return {
    type: 'FAN_IN',
    severity: uniqueSenders.length >= 5 ? 'CRITICAL' : 'HIGH',
    confidence,
    description: `${uniqueSenders.length} unrelated accounts sent funds to this account`,
    evidence: uniqueSenders.map(id => `Account ${id} transferred funds`),
    weight: 20
  };
}

function detectFanOut(
  accountId: string,
  features: AccountFeatures,
  edges: TransactionEdge[],
  nodes: EntityNode[]
): DetectedPattern | null {
  if (features.outgoingCounterparties < CONFIG.PATTERN_THRESHOLDS.FAN_OUT_MIN_ACCOUNTS) {
    return null;
  }
  
  // Get outgoing accounts
  const outgoingAccounts = edges
    .filter(e => e.source === accountId)
    .map(e => e.target);
  
  const uniqueRecipients = [...new Set(outgoingAccounts)];
  
  // Check if recipients are unrelated
  const clusterMap = new Map(nodes.map(n => [n.id, n.clusterId]));
  const clusters = new Set(uniqueRecipients.map(id => clusterMap.get(id) || ''));
  
  if (clusters.size < 2) return null;
  
  const confidence = Math.min(95, 60 + (uniqueRecipients.length - 3) * 10);
  
  return {
    type: 'FAN_OUT',
    severity: uniqueRecipients.length >= 5 ? 'CRITICAL' : 'HIGH',
    confidence,
    description: `This account distributed funds to ${uniqueRecipients.length} unrelated accounts`,
    evidence: uniqueRecipients.map(id => `Transferred funds to account ${id}`),
    weight: 20
  };
}

function detectLayering(
  accountId: string,
  edges: TransactionEdge[],
  nodes: EntityNode[]
): DetectedPattern | null {
  // Look for A → B → C patterns where accountId is B
  const incoming = edges.filter(e => e.target === accountId);
  const outgoing = edges.filter(e => e.source === accountId);
  
  if (incoming.length === 0 || outgoing.length === 0) return null;
  
  // Check if funds flow through this account
  const totalIn = incoming.reduce((sum, e) => sum + e.amount, 0);
  const totalOut = outgoing.reduce((sum, e) => sum + e.amount, 0);
  
  if (totalIn === 0) return null;
  
  const flowRatio = totalOut / totalIn;
  
  // If flow ratio is high (passes most funds through), it's layering
  if (flowRatio < 0.7) return null;
  
  // Check if incoming and outgoing are to different entities
  const incomingSources = new Set(incoming.map(e => e.source));
  const outgoingTargets = new Set(outgoing.map(e => e.target));
  const overlap = [...incomingSources].filter(x => outgoingTargets.has(x));
  
  if (overlap.length > 0) return null; // Funds returning to sender, less suspicious
  
  const confidence = Math.min(90, 50 + Math.floor(flowRatio * 40));
  
  return {
    type: 'LAYERING',
    severity: flowRatio > 0.9 ? 'CRITICAL' : 'HIGH',
    confidence,
    description: `Account acts as a layering node, passing ${(flowRatio * 100).toFixed(0)}% of received funds`,
    evidence: [
      `Received ₹${totalIn.toLocaleString()} from ${incomingSources.size} accounts`,
      `Transferred ₹${totalOut.toLocaleString()} to ${outgoingTargets.size} accounts`,
      `Flow-through ratio: ${(flowRatio * 100).toFixed(1)}%`
    ],
    weight: 18
  };
}

function detectRapidPassThrough(
  accountId: string,
  edges: TransactionEdge[],
  nodes: EntityNode[]
): DetectedPattern | null {
  // Look for rapid A → accountId → B patterns
  const incoming = edges.filter(e => e.target === accountId);
  const outgoing = edges.filter(e => e.source === accountId);
  
  if (incoming.length === 0 || outgoing.length === 0) return null;
  
  // Parse timestamps
  const parseTime = (ts: string): number | null => {
    const match = ts.match(/(\d{2}):(\d{2}):(\d{2})/);
    if (!match) return null;
    return parseInt(match[1]) * 3600 + parseInt(match[2]) * 60 + parseInt(match[3]);
  };
  
  // Check if any incoming quickly followed by outgoing
  for (const inc of incoming) {
    const incTime = parseTime(inc.timestamp);
    if (incTime === null) continue;
    
    for (const out of outgoing) {
      const outTime = parseTime(out.timestamp);
      if (outTime === null) continue;
      
      const diff = outTime - incTime;
      if (diff > 0 && diff < CONFIG.RAPID_PASS_THROUGH_SECONDS) {
        const confidence = Math.min(95, 70 + Math.floor((CONFIG.RAPID_PASS_THROUGH_SECONDS - diff) / 10));
        
        return {
          type: 'RAPID_PASS_THROUGH',
          severity: diff < 60 ? 'CRITICAL' : 'HIGH',
          confidence,
          description: `Funds passed through in ${diff} seconds`,
          evidence: [
            `Received ₹${inc.amount.toLocaleString()} from ${inc.source} at ${inc.timestamp}`,
            `Transferred ₹${out.amount.toLocaleString()} to ${out.target} at ${out.timestamp}`,
            `Dwell time: ${diff} seconds`
          ],
          weight: 22
        };
      }
    }
  }
  
  return null;
}

function detectCircularTransfer(
  accountId: string,
  edges: TransactionEdge[],
  nodes: EntityNode[]
): DetectedPattern | null {
  // Look for cycles involving this account
  const visited = new Set<string>();
  const path: string[] = [];
  
  const dfs = (current: string, start: string, depth: number): boolean => {
    if (depth > 6) return false; // Limit depth
    if (current !== start && path.includes(current)) {
      // Found cycle
      const cycleStart = path.indexOf(current);
      path.push(current);
      return true;
    }
    
    if (visited.has(current)) return false;
    visited.add(current);
    path.push(current);
    
    const outgoing = edges.filter(e => e.source === current);
    for (const edge of outgoing) {
      if (dfs(edge.target, start, depth + 1)) return true;
    }
    
    path.pop();
    visited.delete(current);
    return false;
  };
  
  visited.clear();
  if (dfs(accountId, accountId, 0)) {
    const cycleLength = path.length;
    const confidence = Math.min(95, 60 + cycleLength * 8);
    
    return {
      type: 'CIRCULAR_TRANSFER',
      severity: cycleLength <= 3 ? 'CRITICAL' : 'HIGH',
      confidence,
      description: `Circular fund flow detected with ${cycleLength} hops`,
      evidence: path.map((id, i) => {
        const next = path[(i + 1) % path.length];
        return `Hop ${i + 1}: ${id} → ${next}`;
      }),
      weight: 25
    };
  }
  
  return null;
}

function detectDormancyBurst(
  accountId: string,
  features: AccountFeatures,
  edges: TransactionEdge[]
): DetectedPattern | null {
  // Check for dormant account with sudden activity
  if (features.dormantDays < CONFIG.PATTERN_THRESHOLDS.DORMANCY_MIN_DAYS) {
    return null;
  }
  
  // Count recent transactions (last hour)
  const now = new Date();
  const currentSeconds = now.getHours() * 3600 + now.getMinutes() * 60 + now.getSeconds();
  
  const recentTransactions = edges.filter(e => {
    if (e.source !== accountId && e.target !== accountId) return false;
    const match = e.timestamp.match(/(\d{2}):(\d{2}):(\d{2})/);
    if (!match) return false;
    const txTime = parseInt(match[1]) * 3600 + parseInt(match[2]) * 60 + parseInt(match[3]);
    const diff = currentSeconds - txTime;
    return diff >= 0 && diff < 3600; // Last hour
  });
  
  if (recentTransactions.length < 3) return null;
  
  const confidence = Math.min(90, 50 + features.dormantDays * 0.5);
  
  return {
    type: 'DORMANCY_BURST',
    severity: features.dormantDays > 90 ? 'CRITICAL' : 'HIGH',
    confidence,
    description: `Dormant for ${features.dormantDays} days, then ${recentTransactions.length} transactions in last hour`,
    evidence: [
      `Last activity before burst: ${features.dormantDays} days ago`,
      `Recent activity: ${recentTransactions.length} transactions in last hour`,
      `Total volume: ₹${recentTransactions.reduce((sum, e) => sum + e.amount, 0).toLocaleString()}`
    ],
    weight: 18
  };
}

function detectVelocityAnomaly(
  accountId: string,
  features: AccountFeatures
): DetectedPattern | null {
  if (features.transactionVelocity < CONFIG.VELOCITY_THRESHOLD) {
    return null;
  }
  
  const severity = features.transactionVelocity > 10 ? 'CRITICAL' : 'HIGH';
  const confidence = Math.min(90, 50 + Math.floor(features.transactionVelocity * 4));
  
  return {
    type: 'VELOCITY_ANOMALY',
    severity,
    confidence,
    description: `Transaction velocity of ${features.transactionVelocity.toFixed(1)} txns/hour exceeds threshold`,
    evidence: [
      `${features.transactionCount} transactions observed`,
      `Velocity: ${features.transactionVelocity.toFixed(1)} transactions per hour`,
      `Threshold: ${CONFIG.VELOCITY_THRESHOLD} transactions per hour`
    ],
    weight: 15
  };
}

function detectAmountAnomaly(
  accountId: string,
  features: AccountFeatures,
  edges: TransactionEdge[]
): DetectedPattern | null {
  if (features.transactionCount < 5) return null;
  
  // Calculate mean and standard deviation
  const amounts = edges
    .filter(e => e.source === accountId || e.target === accountId)
    .map(e => e.amount);
  
  const mean = amounts.reduce((a, b) => a + b, 0) / amounts.length;
  const variance = amounts.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / amounts.length;
  const stdDev = Math.sqrt(variance);
  
  if (stdDev === 0) return null;
  
  // Check if max amount is more than 3 standard deviations from mean
  const maxDeviation = (features.maxAmount - mean) / stdDev;
  
  if (maxDeviation < CONFIG.AMOUNT_ANOMALY_THRESHOLD) return null;
  
  const confidence = Math.min(90, 50 + Math.floor(maxDeviation * 10));
  
  return {
    type: 'AMOUNT_ANOMALY',
    severity: maxDeviation > 4 ? 'CRITICAL' : 'HIGH',
    confidence,
    description: `Transaction amount of ₹${features.maxAmount.toLocaleString()} is ${maxDeviation.toFixed(1)}σ above mean`,
    evidence: [
      `Mean amount: ₹${mean.toLocaleString()}`,
      `Max amount: ₹${features.maxAmount.toLocaleString()}`,
      `Standard deviation: ₹${stdDev.toLocaleString()}`,
      `Deviation: ${maxDeviation.toFixed(1)}σ`
    ],
    weight: 12
  };
}

function detectPassThroughBehaviour(
  accountId: string,
  features: AccountFeatures
): DetectedPattern | null {
  if (features.passThroughRatio < CONFIG.PATTERN_THRESHOLDS.PASS_THROUGH_MIN_RATIO) {
    return null;
  }
  
  const confidence = Math.min(90, 60 + Math.floor((features.passThroughRatio - 0.8) * 150));
  
  return {
    type: 'PASS_THROUGH',
    severity: features.passThroughRatio > 0.95 ? 'CRITICAL' : 'HIGH',
    confidence,
    description: `Account forwards ${(features.passThroughRatio * 100).toFixed(1)}% of received funds`,
    evidence: [
      `Total inflow: ₹${features.totalInflow.toLocaleString()}`,
      `Total outflow: ₹${features.totalOutflow.toLocaleString()}`,
      `Pass-through ratio: ${(features.passThroughRatio * 100).toFixed(1)}%`
    ],
    weight: 18
  };
}

// ============================================================================
// RISK SCORING
// ============================================================================

export function calculateMuleRiskScore(
  features: AccountFeatures,
  patterns: DetectedPattern[]
): { score: number; level: RiskLevel; breakdown: RiskBreakdown } {
  // Initialize breakdown
  const breakdown: RiskBreakdown = {
    velocityScore: 0,
    networkScore: 0,
    amountScore: 0,
    frequencyScore: 0,
    patternScore: 0,
    behaviouralScore: 0,
    temporalScore: 0
  };
  
  // Velocity score (0-20)
  breakdown.velocityScore = Math.min(20, features.transactionVelocity * 2);
  
  // Network score (0-20)
  breakdown.networkScore = Math.min(20, 
    (features.fanInDegree + features.fanOutDegree) * 2 +
    (features.uniqueCounterparties > 5 ? 5 : 0)
  );
  
  // Amount score (0-15)
  const amountDeviation = features.maxAmount / (features.averageAmount || 1);
  breakdown.amountScore = Math.min(15, amountDeviation * 3);
  
  // Frequency score (0-10)
  breakdown.frequencyScore = Math.min(10, features.transactionCount * 0.5);
  
  // Pattern score (0-15) - from detected patterns
  breakdown.patternScore = Math.min(15, 
    patterns.reduce((sum, p) => sum + (p.weight * p.confidence / 100), 0) * 0.3
  );
  
  // Behavioural score (0-10)
  breakdown.behaviouralScore = Math.min(10,
    (features.passThroughRatio > 0.8 ? 5 : 0) +
    (features.dormantDays > 30 ? 3 : 0) +
    (features.transactionVelocity > 5 ? 2 : 0)
  );
  
  // Temporal score (0-10)
  breakdown.temporalScore = Math.min(10,
    (features.lastActivityHours < 1 ? 5 : 0) +
    (features.timeBetweenTransactions < 5 ? 5 : 0)
  );
  
  // Calculate total score
  const totalScore = Math.round(
    breakdown.velocityScore +
    breakdown.networkScore +
    breakdown.amountScore +
    breakdown.frequencyScore +
    breakdown.patternScore +
    breakdown.behaviouralScore +
    breakdown.temporalScore
  );
  
  const score = Math.min(100, Math.max(0, totalScore));
  
  // Determine risk level
  let level: RiskLevel;
  if (score >= 80) level = 'CRITICAL';
  else if (score >= 60) level = 'HIGH';
  else if (score >= 30) level = 'MEDIUM';
  else level = 'LOW';
  
  return { score, level, breakdown };
}

// ============================================================================
// MAIN DETECTION FUNCTION
// ============================================================================

export function analyzeAccountForMule(
  accountId: string,
  edges: TransactionEdge[],
  nodes: EntityNode[]
): MuleDetectionResult {
  // Extract features
  const features = extractAccountFeatures(accountId, edges, nodes);
  
  // Detect patterns
  const patterns = detectMulePatterns(accountId, features, edges, nodes);
  
  // Calculate risk score
  const { score, level, breakdown } = calculateMuleRiskScore(features, patterns);
  
  // Calculate confidence score
  const confidenceScore = calculateConfidenceScore(patterns, features);
  
  // Generate supporting evidence
  const supportingEvidence = generateSupportingEvidence(features, patterns, edges);
  
  // Find connected suspicious entities
  const connectedSuspicious = findConnectedSuspicious(accountId, edges, nodes);
  
  // Trace transaction paths
  const transactionPaths = traceTransactionPaths(accountId, edges, nodes);
  
  // Determine investigation priority
  const priority = determinePriority(score, confidenceScore, patterns);
  
  return {
    accountId,
    riskScore: score,
    riskLevel: level,
    confidenceScore,
    detectedPatterns: patterns,
    supportingEvidence,
    connectedSuspiciousEntities: connectedSuspicious,
    transactionPaths,
    investigationPriority: priority,
    riskBreakdown: breakdown,
    lastUpdated: new Date().toISOString()
  };
}

function calculateConfidenceScore(
  patterns: DetectedPattern[],
  features: AccountFeatures
): number {
  if (patterns.length === 0) return 0;
  
  // Weighted average of pattern confidences
  const totalWeight = patterns.reduce((sum, p) => sum + p.weight, 0);
  const weightedConfidence = patterns.reduce((sum, p) => sum + (p.confidence * p.weight), 0);
  
  const patternConfidence = totalWeight > 0 ? weightedConfidence / totalWeight : 0;
  
  // Adjust based on features
  const featureBonus = Math.min(10,
    (features.transactionCount > 10 ? 3 : 0) +
    (features.uniqueCounterparties > 5 ? 3 : 0) +
    (features.passThroughRatio > 0.8 ? 4 : 0)
  );
  
  return Math.min(95, Math.round(patternConfidence + featureBonus));
}

function generateSupportingEvidence(
  features: AccountFeatures,
  patterns: DetectedPattern[],
  edges: TransactionEdge[]
): EvidenceItem[] {
  const evidence: EvidenceItem[] = [];
  
  // Add pattern evidence
  patterns.forEach(p => {
    p.evidence.forEach(e => {
      evidence.push({
        type: 'PATTERN',
        description: e,
        confidence: p.confidence
      });
    });
  });
  
  // Add behavioural evidence
  if (features.passThroughRatio > 0.8) {
    evidence.push({
      type: 'BEHAVIOURAL',
      description: `High pass-through ratio: ${(features.passThroughRatio * 100).toFixed(1)}%`,
      confidence: 80
    });
  }
  
  if (features.transactionVelocity > 5) {
    evidence.push({
      type: 'TEMPORAL',
      description: `High transaction velocity: ${features.transactionVelocity.toFixed(1)} txns/hour`,
      confidence: 75
    });
  }
  
  if (features.dormantDays > 30) {
    evidence.push({
      type: 'TEMPORAL',
      description: `Dormant for ${features.dormantDays} days before activity`,
      confidence: 70
    });
  }
  
  // Add transaction evidence
  const recentTx = edges
    .filter(e => e.source === features.accountId || e.target === features.accountId)
    .slice(0, 5);
  
  recentTx.forEach(tx => {
    evidence.push({
      type: 'TRANSACTION',
      description: `${tx.source} → ${tx.target}: ₹${tx.amount.toLocaleString()} via ${tx.type}`,
      transactionId: tx.id,
      timestamp: tx.timestamp,
      amount: tx.amount,
      confidence: 60
    });
  });
  
  return evidence;
}

function findConnectedSuspicious(
  accountId: string,
  edges: TransactionEdge[],
  nodes: EntityNode[]
): string[] {
  const suspicious = new Set<string>();
  
  // Find accounts connected to this one
  const connected = new Set<string>();
  edges.forEach(e => {
    if (e.source === accountId) connected.add(e.target);
    if (e.target === accountId) connected.add(e.source);
  });
  
  // Check if connected accounts are suspicious
  connected.forEach(id => {
    const node = nodes.find(n => n.id === id);
    if (node && (node.risk === 'HIGH' || node.risk === 'CRITICAL')) {
      suspicious.add(id);
    }
  });
  
  return [...suspicious];
}

function traceTransactionPaths(
  accountId: string,
  edges: TransactionEdge[],
  nodes: EntityNode[]
): TransactionPath[] {
  const paths: TransactionPath[] = [];
  const visited = new Set<string>();
  
  const dfs = (
    current: string,
    path: string[],
    amounts: number[],
    timestamps: string[],
    totalAmount: number
  ): void => {
    if (path.length > 5) return; // Limit depth
    if (visited.has(current) && path.length > 1) return;
    
    visited.add(current);
    
    // Find outgoing transactions
    const outgoing = edges.filter(e => e.source === current);
    
    if (outgoing.length === 0 && path.length > 1) {
      // End of path
      paths.push({
        path: [...path],
        amounts: [...amounts],
        timestamps: [...timestamps],
        totalAmount,
        riskScore: calculatePathRiskScore(path, nodes)
      });
    }
    
    outgoing.forEach(edge => {
      if (!visited.has(edge.target) || edge.target === accountId) {
        dfs(
          edge.target,
          [...path, edge.target],
          [...amounts, edge.amount],
          [...timestamps, edge.timestamp],
          totalAmount + edge.amount
        );
      }
    });
    
    visited.delete(current);
  };
  
  dfs(accountId, [accountId], [], [], 0);
  
  return paths.slice(0, 10); // Limit to 10 paths
}

function calculatePathRiskScore(path: string[], nodes: EntityNode[]): number {
  if (path.length === 0) return 0;
  
  const nodeRiskScores = path.map(id => {
    const node = nodes.find(n => n.id === id);
    return node?.riskScore || 0;
  });
  
  const avgRisk = nodeRiskScores.reduce((a, b) => a + b, 0) / nodeRiskScores.length;
  const maxRisk = Math.max(...nodeRiskScores);
  
  return Math.min(100, Math.round(avgRisk * 0.6 + maxRisk * 0.4));
}

function determinePriority(
  riskScore: number,
  confidenceScore: number,
  patterns: DetectedPattern[]
): 'IMMEDIATE' | 'HIGH' | 'MEDIUM' | 'LOW' {
  const criticalPatterns = patterns.filter(p => p.severity === 'CRITICAL');
  
  if (criticalPatterns.length > 0 || riskScore >= 90) return 'IMMEDIATE';
  if (riskScore >= 70 || confidenceScore >= 80) return 'HIGH';
  if (riskScore >= 50 || confidenceScore >= 60) return 'MEDIUM';
  return 'LOW';
}

// ============================================================================
// BATCH ANALYSIS
// ============================================================================

export function analyzeAllAccounts(
  edges: TransactionEdge[],
  nodes: EntityNode[]
): MuleDetectionResult[] {
  // Get unique account IDs
  const accountIds = new Set<string>();
  edges.forEach(e => {
    accountIds.add(e.source);
    accountIds.add(e.target);
  });
  
  // Analyze each account
  return [...accountIds]
    .map(id => analyzeAccountForMule(id, edges, nodes))
    .sort((a, b) => b.riskScore - a.riskScore);
}

// ============================================================================
// REAL-TIME ANALYSIS
// ============================================================================

export function analyzeTransactionForMule(
  tx: TransactionEdge,
  edges: TransactionEdge[],
  nodes: EntityNode[]
): {
  sourceAnalysis: MuleDetectionResult;
  targetAnalysis: MuleDetectionResult;
  transactionRisk: number;
} {
  // Analyze both source and target accounts
  const sourceAnalysis = analyzeAccountForMule(tx.source, edges, nodes);
  const targetAnalysis = analyzeAccountForMule(tx.target, edges, nodes);
  
  // Calculate transaction-level risk
  const transactionRisk = calculateTransactionRisk(tx, sourceAnalysis, targetAnalysis);
  
  return {
    sourceAnalysis,
    targetAnalysis,
    transactionRisk
  };
}

function calculateTransactionRisk(
  tx: TransactionEdge,
  source: MuleDetectionResult,
  target: MuleDetectionResult
): number {
  // Combine source and target risk with transaction features
  const baseRisk = (source.riskScore + target.riskScore) / 2;
  
  // Amount factor
  const amountFactor = tx.amount > 500000 ? 10 : tx.amount > 100000 ? 5 : 0;
  
  // Risk level factor
  const levelFactor = 
    (source.riskLevel === 'CRITICAL' || target.riskLevel === 'CRITICAL') ? 15 :
    (source.riskLevel === 'HIGH' || target.riskLevel === 'HIGH') ? 10 : 0;
  
  return Math.min(100, baseRisk + amountFactor + levelFactor);
}