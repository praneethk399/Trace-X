/**
 * TraceX — Real-Time Transaction Processing Pipeline
 * Processes each transaction through: Validation → Feature Extraction →
 * Rule Detection → Graph Update → Risk Calculation → Alert Generation
 * 
 * @license Apache-2.0
 */

import {
  TransactionEdge,
  EntityNode,
  RiskLevel,
  TransactionType,
  StreamEvent,
  DetectedSuspiciousTransaction,
  DetectionSignal
} from '../types/forensics';
import {
  analyzeTransactionForMule,
  extractAccountFeatures,
  detectMulePatterns,
  calculateMuleRiskScore,
  MuleDetectionResult
} from './muleDetection';
import {
  STANDARD_SIGNALS,
  calculateFraudScore,
  generateAiRiskExplanation
} from './detectionEngine';
import { formatINR } from '../data/mockForensics';

// ============================================================================
// TYPES
// ============================================================================

export interface PipelineResult {
  transactionId: string;
  timestamp: string;
  source: string;
  target: string;
  amount: number;
  risk: RiskLevel;
  riskScore: number;
  confidenceScore: number;
  detectedPatterns: string[];
  signals: DetectionSignal[];
  sourceAnalysis: MuleDetectionResult;
  targetAnalysis: MuleDetectionResult;
  alerts: Alert[];
  processingTimeMs: number;
  isValid: boolean;
  validationErrors: string[];
}

export interface Alert {
  id: string;
  transactionId: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  type: string;
  message: string;
  timestamp: string;
  accountId?: string;
  riskScore: number;
}

export interface PipelineMetrics {
  totalProcessed: number;
  totalSuspicious: number;
  totalAlerts: number;
  averageProcessingTimeMs: number;
  alertsByType: Record<string, number>;
  alertsBySeverity: Record<string, number>;
}

// ============================================================================
// CONFIGURATION
// ============================================================================

const PIPELINE_CONFIG = {
  // Validation thresholds
  MIN_AMOUNT: 1,
  MAX_AMOUNT: 10000000, // 1 Crore
  ALLOWED_TYPES: ['UPI', 'IMPS', 'NEFT', 'RTGS', 'CARD'] as TransactionType[],
  
  // Risk thresholds
  CRITICAL_THRESHOLD: 80,
  HIGH_THRESHOLD: 60,
  MEDIUM_THRESHOLD: 30,
  
  // Alert thresholds
  ALERT_THRESHOLDS: {
    HIGH_AMOUNT: 500000,
    VELOCITY_ALERT: 10,
    RAPID_PASS_THROUGH: 60 // seconds
  }
};

// ============================================================================
// VALIDATION
// ============================================================================

export function validateTransaction(tx: TransactionEdge): {
  isValid: boolean;
  errors: string[];
} {
  const errors: string[] = [];
  
  // Amount validation
  if (tx.amount < PIPELINE_CONFIG.MIN_AMOUNT) {
    errors.push('Transaction amount below minimum threshold');
  }
  if (tx.amount > PIPELINE_CONFIG.MAX_AMOUNT) {
    errors.push('Transaction amount exceeds maximum threshold');
  }
  
  // Type validation
  if (!PIPELINE_CONFIG.ALLOWED_TYPES.includes(tx.type)) {
    errors.push(`Invalid transaction type: ${tx.type}`);
  }
  
  // Source/target validation
  if (!tx.source || tx.source.trim() === '') {
    errors.push('Missing source account');
  }
  if (!tx.target || tx.target.trim() === '') {
    errors.push('Missing target account');
  }
  if (tx.source === tx.target) {
    errors.push('Source and target accounts are identical');
  }
  
  // Timestamp validation
  if (!tx.timestamp || !tx.timestamp.match(/\d{2}:\d{2}:\d{2}/)) {
    errors.push('Invalid timestamp format');
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
}

// ============================================================================
// FEATURE EXTRACTION
// ============================================================================

interface TransactionFeatures {
  amount: number;
  type: TransactionType;
  sourceAccountAge: number;
  targetAccountAge: number;
  sourceTransactionCount: number;
  targetTransactionCount: number;
  sourceUniqueCounterparties: number;
  targetUniqueCounterparties: number;
  sourceInflowOutflowRatio: number;
  targetInflowOutflowRatio: number;
  timeSinceLastTransaction: number;
  isHighValue: boolean;
  isRoundAmount: boolean;
  isOffHours: boolean;
}

export function extractTransactionFeatures(
  tx: TransactionEdge,
  edges: TransactionEdge[],
  nodes: EntityNode[]
): TransactionFeatures {
  const sourceNode = nodes.find(n => n.id === tx.source);
  const targetNode = nodes.find(n => n.id === tx.target);
  
  // Get transaction history for source and target
  const sourceEdges = edges.filter(e => e.source === tx.source || e.target === tx.source);
  const targetEdges = edges.filter(e => e.source === tx.target || e.target === tx.target);
  
  // Calculate features
  const sourceInflow = sourceEdges
    .filter(e => e.target === tx.source)
    .reduce((sum, e) => sum + e.amount, 0);
  const sourceOutflow = sourceEdges
    .filter(e => e.source === tx.source)
    .reduce((sum, e) => sum + e.amount, 0);
  
  const targetInflow = targetEdges
    .filter(e => e.target === tx.target)
    .reduce((sum, e) => sum + e.amount, 0);
  const targetOutflow = targetEdges
    .filter(e => e.source === tx.target)
    .reduce((sum, e) => sum + e.amount, 0);
  
  // Parse timestamp
  const txTime = parseTimestamp(tx.timestamp);
  const lastTxTime = getLastTransactionTime(tx.source, edges);
  
  return {
    amount: tx.amount,
    type: tx.type,
    sourceAccountAge: sourceNode ? calculateAccountAge(sourceNode) : 0,
    targetAccountAge: targetNode ? calculateAccountAge(targetNode) : 0,
    sourceTransactionCount: sourceEdges.length,
    targetTransactionCount: targetEdges.length,
    sourceUniqueCounterparties: new Set(sourceEdges.map(e => 
      e.source === tx.source ? e.target : e.source
    )).size,
    targetUniqueCounterparties: new Set(targetEdges.map(e => 
      e.source === tx.target ? e.target : e.source
    )).size,
    sourceInflowOutflowRatio: sourceOutflow > 0 ? sourceInflow / sourceOutflow : 0,
    targetInflowOutflowRatio: targetOutflow > 0 ? targetInflow / targetOutflow : 0,
    timeSinceLastTransaction: lastTxTime ? txTime - lastTxTime : Infinity,
    isHighValue: tx.amount > PIPELINE_CONFIG.ALERT_THRESHOLDS.HIGH_AMOUNT,
    isRoundAmount: tx.amount % 10000 === 0,
    isOffHours: isOffHours(txTime)
  };
}

function parseTimestamp(ts: string): number {
  const match = ts.match(/(\d{2}):(\d{2}):(\d{2})/);
  if (!match) return 0;
  return parseInt(match[1]) * 3600 + parseInt(match[2]) * 60 + parseInt(match[3]);
}

function calculateAccountAge(node: EntityNode): number {
  // Simplified: assume account age based on transaction count
  return Math.min(365, node.transactionCount * 7);
}

function getLastTransactionTime(accountId: string, edges: TransactionEdge[]): number | null {
  const relevantEdges = edges.filter(e => e.source === accountId || e.target === accountId);
  if (relevantEdges.length === 0) return null;
  
  const times = relevantEdges.map(e => parseTimestamp(e.timestamp)).filter(t => t > 0);
  return times.length > 0 ? Math.max(...times) : null;
}

function isOffHours(timeInSeconds: number): boolean {
  const hours = Math.floor(timeInSeconds / 3600);
  // Off hours: 11 PM to 5 AM
  return hours >= 23 || hours < 5;
}

// ============================================================================
// RULE-BASED DETECTION
// ============================================================================

export function applyDetectionRules(
  tx: TransactionEdge,
  features: TransactionFeatures,
  edges: TransactionEdge[],
  nodes: EntityNode[]
): {
  signals: DetectionSignal[];
  riskScore: number;
  patterns: string[];
} {
  const signals: DetectionSignal[] = [];
  const patterns: string[] = [];
  let riskScore = 20; // Base score
  
  // Rule 1: High-value transaction
  if (features.isHighValue) {
    signals.push(STANDARD_SIGNALS.UNUSUAL_AMOUNT);
    riskScore += 20;
    patterns.push('HIGH_VALUE_TRANSACTION');
  }
  
  // Rule 2: Rapid money movement (IMPS/UPI typically fast)
  if (tx.type === 'IMPS' || tx.type === 'UPI') {
    signals.push(STANDARD_SIGNALS.RAPID_MONEY_MOVEMENT);
    riskScore += 15;
    patterns.push('RAPID_MONEY_MOVEMENT');
  }
  
  // Rule 3: Cross-cluster transfer
  const sourceNode = nodes.find(n => n.id === tx.source);
  const targetNode = nodes.find(n => n.id === tx.target);
  if (sourceNode && targetNode && sourceNode.clusterId !== targetNode.clusterId) {
    signals.push(STANDARD_SIGNALS.UNRELATED_ACCOUNT);
    riskScore += 12;
    patterns.push('CROSS_CLUSTER_TRANSFER');
  }
  
  // Rule 4: High-risk gateway interaction
  if (targetNode && (targetNode.type === 'EXCHANGE' || targetNode.type === 'ATM_CASHOUT')) {
    signals.push(STANDARD_SIGNALS.UNHOSTED_GATEWAY);
    riskScore += 18;
    patterns.push('HIGH_RISK_GATEWAY');
  }
  
  // Rule 5: Rapid pass-through (transaction very fast after previous)
  if (features.timeSinceLastTransaction < PIPELINE_CONFIG.ALERT_THRESHOLDS.RAPID_PASS_THROUGH) {
    riskScore += 15;
    patterns.push('RAPID_PASS_THROUGH');
  }
  
  // Rule 6: Off-hours activity
  if (features.isOffHours) {
    riskScore += 8;
    patterns.push('OFF_HOURS_ACTIVITY');
  }
  
  // Rule 7: Round amount (potential structuring)
  if (features.isRoundAmount && tx.amount > 100000) {
    riskScore += 10;
    patterns.push('ROUND_AMOUNT');
  }
  
  // Rule 8: New account with high volume
  if (features.sourceAccountAge < 30 && features.sourceTransactionCount > 5) {
    riskScore += 12;
    patterns.push('NEW_ACCOUNT_HIGH_VOLUME');
  }
  
  // Cap risk score
  riskScore = Math.min(100, Math.max(0, riskScore));
  
  return { signals, riskScore, patterns };
}

// ============================================================================
// GRAPH UPDATE
// ============================================================================

export function updateGraphWithTransaction(
  tx: TransactionEdge,
  nodes: EntityNode[],
  edges: TransactionEdge[]
): {
  updatedNodes: EntityNode[];
  newEdges: TransactionEdge[];
  affectedNodes: string[];
} {
  const affectedNodes = new Set<string>([tx.source, tx.target]);
  const updatedNodes = [...nodes];
  
  // Update source node
  const sourceIdx = updatedNodes.findIndex(n => n.id === tx.source);
  if (sourceIdx >= 0) {
    updatedNodes[sourceIdx] = {
      ...updatedNodes[sourceIdx],
      outflow: updatedNodes[sourceIdx].outflow + tx.amount,
      transactionCount: updatedNodes[sourceIdx].transactionCount + 1,
      lastActivity: tx.timestamp
    };
  }
  
  // Update target node
  const targetIdx = updatedNodes.findIndex(n => n.id === tx.target);
  if (targetIdx >= 0) {
    updatedNodes[targetIdx] = {
      ...updatedNodes[targetIdx],
      inflow: updatedNodes[targetIdx].inflow + tx.amount,
      transactionCount: updatedNodes[targetIdx].transactionCount + 1,
      lastActivity: tx.timestamp
    };
  }
  
  // Add new edge
  const newEdge: TransactionEdge = {
    ...tx,
    flowStatus: 'SETTLED'
  };
  
  return {
    updatedNodes,
    newEdges: [...edges, newEdge],
    affectedNodes: [...affectedNodes]
  };
}

// ============================================================================
// ALERT GENERATION
// ============================================================================

export function generateAlerts(
  tx: TransactionEdge,
  riskScore: number,
  patterns: string[],
  sourceAnalysis: MuleDetectionResult,
  targetAnalysis: MuleDetectionResult
): Alert[] {
  const alerts: Alert[] = [];
  const timestamp = new Date().toISOString();
  
  // Generate alerts based on risk score
  if (riskScore >= PIPELINE_CONFIG.CRITICAL_THRESHOLD) {
    alerts.push({
      id: `ALT-${Date.now()}-CRIT`,
      transactionId: tx.id,
      severity: 'CRITICAL',
      type: 'HIGH_RISK_TRANSACTION',
      message: `CRITICAL: Transaction ${tx.id} flagged with risk score ${riskScore}/100`,
      timestamp,
      riskScore
    });
  } else if (riskScore >= PIPELINE_CONFIG.HIGH_THRESHOLD) {
    alerts.push({
      id: `ALT-${Date.now()}-HIGH`,
      transactionId: tx.id,
      severity: 'HIGH',
      type: 'ELEVATED_RISK',
      message: `HIGH: Transaction ${tx.id} flagged with risk score ${riskScore}/100`,
      timestamp,
      riskScore
    });
  }
  
  // Generate alerts for specific patterns
  if (patterns.includes('RAPID_PASS_THROUGH')) {
    alerts.push({
      id: `ALT-${Date.now()}-RPT`,
      transactionId: tx.id,
      severity: 'HIGH',
      type: 'RAPID_PASS_THROUGH',
      message: `Rapid pass-through detected: ${tx.source} → ${tx.target}`,
      timestamp,
      accountId: tx.source,
      riskScore
    });
  }
  
  if (patterns.includes('HIGH_RISK_GATEWAY')) {
    alerts.push({
      id: `ALT-${Date.now()}-HRG`,
      transactionId: tx.id,
      severity: 'CRITICAL',
      type: 'HIGH_RISK_GATEWAY',
      message: `High-risk gateway interaction: ${tx.target}`,
      timestamp,
      accountId: tx.target,
      riskScore
    });
  }
  
  // Generate alerts for mule account patterns
  if (sourceAnalysis.detectedPatterns.length > 0) {
    const criticalPatterns = sourceAnalysis.detectedPatterns.filter(p => p.severity === 'CRITICAL');
    if (criticalPatterns.length > 0) {
      alerts.push({
        id: `ALT-${Date.now()}-MULE-S`,
        transactionId: tx.id,
        severity: 'CRITICAL',
        type: 'MULE_ACCOUNT_DETECTED',
        message: `Mule account pattern detected for source: ${tx.source}`,
        timestamp,
        accountId: tx.source,
        riskScore: sourceAnalysis.riskScore
      });
    }
  }
  
  if (targetAnalysis.detectedPatterns.length > 0) {
    const criticalPatterns = targetAnalysis.detectedPatterns.filter(p => p.severity === 'CRITICAL');
    if (criticalPatterns.length > 0) {
      alerts.push({
        id: `ALT-${Date.now()}-MULE-T`,
        transactionId: tx.id,
        severity: 'CRITICAL',
        type: 'MULE_ACCOUNT_DETECTED',
        message: `Mule account pattern detected for target: ${tx.target}`,
        timestamp,
        accountId: tx.target,
        riskScore: targetAnalysis.riskScore
      });
    }
  }
  
  return alerts;
}

// ============================================================================
// MAIN PIPELINE
// ============================================================================

let pipelineMetrics: PipelineMetrics = {
  totalProcessed: 0,
  totalSuspicious: 0,
  totalAlerts: 0,
  averageProcessingTimeMs: 0,
  alertsByType: {},
  alertsBySeverity: {}
};

export function processTransaction(
  tx: TransactionEdge,
  edges: TransactionEdge[],
  nodes: EntityNode[]
): PipelineResult {
  const startTime = performance.now();
  
  // Step 1: Validation
  const validation = validateTransaction(tx);
  
  // Step 2: Feature extraction
  const features = extractTransactionFeatures(tx, edges, nodes);
  
  // Step 3: Rule-based detection
  const { signals, riskScore, patterns } = applyDetectionRules(tx, features, edges, nodes);
  
  // Step 4: Graph update (returns updated state)
  const graphUpdate = updateGraphWithTransaction(tx, nodes, edges);
  
  // Step 5: Mule detection analysis
  const { sourceAnalysis, targetAnalysis } = analyzeTransactionForMule(tx, edges, nodes);
  
  // Step 6: Alert generation
  const alerts = generateAlerts(tx, riskScore, patterns, sourceAnalysis, targetAnalysis);
  
  // Step 7: Determine final risk level
  const finalRiskScore = Math.max(riskScore, sourceAnalysis.riskScore, targetAnalysis.riskScore);
  let risk: RiskLevel;
  if (finalRiskScore >= 80) risk = 'CRITICAL';
  else if (finalRiskScore >= 60) risk = 'HIGH';
  else if (finalRiskScore >= 30) risk = 'MEDIUM';
  else risk = 'LOW';
  
  const endTime = performance.now();
  const processingTimeMs = endTime - startTime;
  
  // Update metrics
  updatePipelineMetrics(processingTimeMs, risk !== 'LOW', alerts);
  
  return {
    transactionId: tx.id,
    timestamp: tx.timestamp,
    source: tx.source,
    target: tx.target,
    amount: tx.amount,
    risk,
    riskScore: finalRiskScore,
    confidenceScore: Math.max(sourceAnalysis.confidenceScore, targetAnalysis.confidenceScore),
    detectedPatterns: patterns,
    signals,
    sourceAnalysis,
    targetAnalysis,
    alerts,
    processingTimeMs,
    isValid: validation.isValid,
    validationErrors: validation.errors
  };
}

function updatePipelineMetrics(
  processingTimeMs: number,
  isSuspicious: boolean,
  alerts: Alert[]
): void {
  pipelineMetrics.totalProcessed++;
  if (isSuspicious) pipelineMetrics.totalSuspicious++;
  pipelineMetrics.totalAlerts += alerts.length;
  
  // Update average processing time
  pipelineMetrics.averageProcessingTimeMs = 
    (pipelineMetrics.averageProcessingTimeMs * (pipelineMetrics.totalProcessed - 1) + processingTimeMs) /
    pipelineMetrics.totalProcessed;
  
  // Update alert counts by type
  alerts.forEach(alert => {
    pipelineMetrics.alertsByType[alert.type] = 
      (pipelineMetrics.alertsByType[alert.type] || 0) + 1;
    pipelineMetrics.alertsBySeverity[alert.severity] = 
      (pipelineMetrics.alertsBySeverity[alert.severity] || 0) + 1;
  });
}

export function getPipelineMetrics(): PipelineMetrics {
  return { ...pipelineMetrics };
}

export function resetPipelineMetrics(): void {
  pipelineMetrics = {
    totalProcessed: 0,
    totalSuspicious: 0,
    totalAlerts: 0,
    averageProcessingTimeMs: 0,
    alertsByType: {},
    alertsBySeverity: {}
  };
}

// ============================================================================
// STREAM PROCESSING
// ============================================================================

export function processStreamEvent(
  event: StreamEvent,
  edges: TransactionEdge[],
  nodes: EntityNode[]
): PipelineResult & { streamEvent: StreamEvent } {
  // Convert stream event to transaction edge
  const tx: TransactionEdge = {
    id: event.id,
    source: event.source,
    target: event.target,
    type: event.type,
    amount: event.numericAmount,
    formattedAmount: event.amount,
    timestamp: event.time,
    risk: event.risk,
    flowStatus: 'IN_TRANSIT',
    hash: event.hash || `0x${Math.random().toString(16).slice(2, 10)}`
  };
  
  // Process through pipeline
  const result = processTransaction(tx, edges, nodes);
  
  // Update stream event with pipeline results
  const updatedEvent: StreamEvent = {
    ...event,
    risk: result.risk,
    riskScore: result.riskScore,
    status: result.risk !== 'LOW' ? 'ALERT GENERATED' : 'ASSESSED',
    detectionSignals: result.signals.map(s => s.name),
    detected: result.risk !== 'LOW'
  };
  
  return {
    ...result,
    streamEvent: updatedEvent
  };
}

// ============================================================================
// BATCH PROCESSING
// ============================================================================

export function processBatch(
  transactions: TransactionEdge[],
  edges: TransactionEdge[],
  nodes: EntityNode[]
): PipelineResult[] {
  let currentEdges = [...edges];
  const results: PipelineResult[] = [];
  
  for (const tx of transactions) {
    const result = processTransaction(tx, currentEdges, nodes);
    results.push(result);
    
    // Update edges for next transaction
    currentEdges = [...currentEdges, {
      ...tx,
      flowStatus: 'SETTLED'
    }];
  }
  
  return results;
}

// ============================================================================
// UTILITIES
// ============================================================================

export function formatRiskScore(score: number): string {
  return `${score}/100`;
}

export function getRiskColor(risk: RiskLevel): string {
  switch (risk) {
    case 'CRITICAL': return '#EF4444';
    case 'HIGH': return '#F59E0B';
    case 'MEDIUM': return '#EAB308';
    case 'LOW': return '#22C55E';
    default: return '#6B7280';
  }
}

export function getRiskLabel(risk: RiskLevel): string {
  switch (risk) {
    case 'CRITICAL': return 'CRITICAL RISK';
    case 'HIGH': return 'HIGH RISK';
    case 'MEDIUM': return 'MEDIUM RISK';
    case 'LOW': return 'LOW RISK';
    default: return 'UNKNOWN';
  }
}

export function generatePipelineSummary(results: PipelineResult[]): {
  totalTransactions: number;
  suspiciousTransactions: number;
  averageRiskScore: number;
  riskDistribution: Record<RiskLevel, number>;
  topPatterns: { pattern: string; count: number }[];
  alertsGenerated: number;
} {
  const totalTransactions = results.length;
  const suspiciousTransactions = results.filter(r => r.risk !== 'LOW').length;
  const averageRiskScore = results.reduce((sum, r) => sum + r.riskScore, 0) / totalTransactions;
  
  const riskDistribution: Record<RiskLevel, number> = {
    'CRITICAL': 0,
    'HIGH': 0,
    'MEDIUM': 0,
    'LOW': 0
  };
  
  const patternCounts: Record<string, number> = {};
  
  results.forEach(r => {
    riskDistribution[r.risk]++;
    r.detectedPatterns.forEach(p => {
      patternCounts[p] = (patternCounts[p] || 0) + 1;
    });
  });
  
  const topPatterns = Object.entries(patternCounts)
    .map(([pattern, count]) => ({ pattern, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);
  
  const alertsGenerated = results.reduce((sum, r) => sum + r.alerts.length, 0);
  
  return {
    totalTransactions,
    suspiciousTransactions,
    averageRiskScore,
    riskDistribution,
    topPatterns,
    alertsGenerated
  };
}