/**
 * TraceX — Investigation Workspace Service
 * Manages the investigation workflow:
 * ALERT → OPEN CASE → INSPECT ACCOUNT → REVIEW RISK → TRACE FUNDS →
 * ANALYSE NETWORK → REVIEW TIMELINE → GENERATE EXPLANATION →
 * GENERATE REPORT → CLOSE CASE
 * 
 * @license Apache-2.0
 */

import {
  InvestigationCase,
  InvestigationStatus,
  EvidenceItem,
  TransactionPathInfo,
  DetectedPattern,
  RiskLevel,
  Alert,
  EntityNode,
  TransactionEdge
} from '../types/forensics';
import {
  MuleDetectionResult,
  analyzeAccountForMule
} from './muleDetection';
import { generateInvestigationReport } from './detectionEngine';

// ============================================================================
// TYPES
// ============================================================================

export interface CaseCreationRequest {
  accountId: string;
  accountLabel: string;
  riskScore: number;
  riskLevel: RiskLevel;
  confidenceScore: number;
  detectedPatterns: string[];
  evidence: EvidenceItem[];
  connectedEntities: string[];
  transactionPaths: TransactionPathInfo[];
  priority: 'IMMEDIATE' | 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface CaseUpdateRequest {
  status?: InvestigationStatus;
  investigatorNotes?: string;
  falsePositiveReason?: string;
  assignedTo?: string;
}

export interface InvestigationSummary {
  totalCases: number;
  casesByStatus: Record<InvestigationStatus, number>;
  casesByPriority: Record<string, number>;
  averageResolutionTimeHours: number;
  falsePositiveRate: number;
  confirmedFraudRate: number;
}

// ============================================================================
// CASE MANAGEMENT
// ============================================================================

let cases: InvestigationCase[] = [];
let caseCounter = 0;

export function createCase(request: CaseCreationRequest): InvestigationCase {
  caseCounter++;
  const now = new Date().toISOString();
  
  const newCase: InvestigationCase = {
    id: `CASE-${String(caseCounter).padStart(4, '0')}`,
    title: `Investigation: ${request.accountLabel}`,
    status: 'NEW',
    priority: request.priority,
    accountId: request.accountId,
    accountLabel: request.accountLabel,
    riskScore: request.riskScore,
    riskLevel: request.riskLevel,
    confidenceScore: request.confidenceScore,
    detectedPatterns: request.detectedPatterns,
    evidence: request.evidence,
    connectedEntities: request.connectedEntities,
    transactionPaths: request.transactionPaths,
    investigatorNotes: '',
    createdAt: now,
    updatedAt: now
  };
  
  cases.push(newCase);
  return newCase;
}

export function updateCase(caseId: string, update: CaseUpdateRequest): InvestigationCase | null {
  const caseIndex = cases.findIndex(c => c.id === caseId);
  if (caseIndex === -1) return null;
  
  const updatedCase = { ...cases[caseIndex] };
  const now = new Date().toISOString();
  
  if (update.status) {
    updatedCase.status = update.status;
    if (update.status === 'CLOSED' || update.status === 'FALSE_POSITIVE') {
      updatedCase.closedAt = now;
    }
  }
  
  if (update.investigatorNotes) {
    updatedCase.investigatorNotes = update.investigatorNotes;
  }
  
  if (update.falsePositiveReason) {
    updatedCase.falsePositiveReason = update.falsePositiveReason;
    updatedCase.status = 'FALSE_POSITIVE';
  }
  
  if (update.assignedTo) {
    updatedCase.assignedTo = update.assignedTo;
  }
  
  updatedCase.updatedAt = now;
  cases[caseIndex] = updatedCase;
  
  return updatedCase;
}

export function getCase(caseId: string): InvestigationCase | null {
  return cases.find(c => c.id === caseId) || null;
}

export function getAllCases(): InvestigationCase[] {
  return [...cases];
}

export function getCasesByStatus(status: InvestigationStatus): InvestigationCase[] {
  return cases.filter(c => c.status === status);
}

export function getCasesByPriority(priority: string): InvestigationCase[] {
  return cases.filter(c => c.priority === priority);
}

export function deleteCase(caseId: string): boolean {
  const initialLength = cases.length;
  cases = cases.filter(c => c.id !== caseId);
  return cases.length < initialLength;
}

// ============================================================================
// FALSE-POSITIVE MANAGEMENT
// ============================================================================

export function markAsFalsePositive(
  caseId: string,
  reason: string
): InvestigationCase | null {
  return updateCase(caseId, {
    status: 'FALSE_POSITIVE',
    falsePositiveReason: reason
  });
}

export function getFalsePositiveCases(): InvestigationCase[] {
  return cases.filter(c => c.status === 'FALSE_POSITIVE');
}

export function getFalsePositiveRate(): number {
  if (cases.length === 0) return 0;
  const falsePositives = cases.filter(c => c.status === 'FALSE_POSITIVE').length;
  return (falsePositives / cases.length) * 100;
}

// ============================================================================
// INVESTIGATION WORKFLOW
// ============================================================================

export function openCaseFromAlert(
  alert: Alert,
  edges: TransactionEdge[],
  nodes: EntityNode[]
): InvestigationCase | null {
  // Find account involved in alert
  const accountId = alert.accountId || extractAccountIdFromTransaction(alert.transactionId, edges);
  if (!accountId) return null;
  
  // Analyze account
  const analysis = analyzeAccountForMule(accountId, edges, nodes);
  
  // Create case
  return createCase({
    accountId,
    accountLabel: nodes.find(n => n.id === accountId)?.label || accountId,
    riskScore: analysis.riskScore,
    riskLevel: analysis.riskLevel,
    confidenceScore: analysis.confidenceScore,
    detectedPatterns: analysis.detectedPatterns.map(p => p.type),
    evidence: analysis.supportingEvidence,
    connectedEntities: analysis.connectedSuspiciousEntities,
    transactionPaths: analysis.transactionPaths,
    priority: analysis.investigationPriority
  });
}

function extractAccountIdFromTransaction(transactionId: string, edges: TransactionEdge[]): string | null {
  const edge = edges.find(e => e.id === transactionId);
  return edge ? edge.source : null;
}

export function inspectAccount(
  caseId: string,
  edges: TransactionEdge[],
  nodes: EntityNode[]
): MuleDetectionResult | null {
  const caseObj = getCase(caseId);
  if (!caseObj) return null;
  
  return analyzeAccountForMule(caseObj.accountId, edges, nodes);
}

export function traceFunds(
  caseId: string,
  edges: TransactionEdge[],
  nodes: EntityNode[]
): TransactionPathInfo[] | null {
  const caseObj = getCase(caseId);
  if (!caseObj) return null;
  
  const analysis = analyzeAccountForMule(caseObj.accountId, edges, nodes);
  return analysis.transactionPaths;
}

export function generateExplanation(caseId: string): string | null {
  const caseObj = getCase(caseId);
  if (!caseObj) return null;
  
  const explanation: string[] = [];
  
  // Risk explanation
  explanation.push(`RISK SCORE: ${caseObj.riskScore}/100 (${caseObj.riskLevel})`);
  explanation.push(`CONFIDENCE: ${caseObj.confidenceScore}%`);
  explanation.push('');
  
  // Pattern explanation
  if (caseObj.detectedPatterns.length > 0) {
    explanation.push('DETECTED PATTERNS:');
    caseObj.detectedPatterns.forEach(pattern => {
      explanation.push(`  - ${formatPatternName(pattern)}`);
    });
    explanation.push('');
  }
  
  // Evidence explanation
  if (caseObj.evidence.length > 0) {
    explanation.push('SUPPORTING EVIDENCE:');
    caseObj.evidence.slice(0, 5).forEach(evidence => {
      explanation.push(`  - ${evidence.description}`);
    });
    explanation.push('');
  }
  
  // Connected entities
  if (caseObj.connectedEntities.length > 0) {
    explanation.push(`CONNECTED SUSPICIOUS ENTITIES: ${caseObj.connectedEntities.length}`);
    explanation.push('');
  }
  
  // Investigation priority
  explanation.push(`INVESTIGATION PRIORITY: ${caseObj.priority}`);
  
  return explanation.join('\\n');
}

function formatPatternName(pattern: string): string {
  return pattern
    .split('_')
    .map(word => word.charAt(0) + word.slice(1).toLowerCase())
    .join(' ');
}

// ============================================================================
// REPORT GENERATION
// ============================================================================

export function generateCaseReport(caseId: string): string | null {
  const caseObj = getCase(caseId);
  if (!caseObj) return null;
  
  const report: string[] = [];
  
  // Header
  report.push('='.repeat(60));
  report.push('TRACE X - INVESTIGATION REPORT');
  report.push('='.repeat(60));
  report.push('');
  
  // Case Information
  report.push('CASE INFORMATION');
  report.push('-'.repeat(40));
  report.push(`Case ID: ${caseObj.id}`);
  report.push(`Title: ${caseObj.title}`);
  report.push(`Status: ${caseObj.status}`);
  report.push(`Priority: ${caseObj.priority}`);
  report.push(`Created: ${caseObj.createdAt}`);
  report.push(`Updated: ${caseObj.updatedAt}`);
  if (caseObj.closedAt) report.push(`Closed: ${caseObj.closedAt}`);
  if (caseObj.assignedTo) report.push(`Assigned To: ${caseObj.assignedTo}`);
  report.push('');
  
  // Account Information
  report.push('ACCOUNT INFORMATION');
  report.push('-'.repeat(40));
  report.push(`Account ID: ${caseObj.accountId}`);
  report.push(`Account Label: ${caseObj.accountLabel}`);
  report.push(`Risk Score: ${caseObj.riskScore}/100`);
  report.push(`Risk Level: ${caseObj.riskLevel}`);
  report.push(`Confidence Score: ${caseObj.confidenceScore}%`);
  report.push('');
  
  // Detected Patterns
  report.push('DETECTED PATTERNS');
  report.push('-'.repeat(40));
  caseObj.detectedPatterns.forEach(pattern => {
    report.push(`  - ${formatPatternName(pattern)}`);
  });
  report.push('');
  
  // Evidence
  report.push('SUPPORTING EVIDENCE');
  report.push('-'.repeat(40));
  caseObj.evidence.forEach((evidence, idx) => {
    report.push(`${idx + 1}. [${evidence.type}] ${evidence.description}`);
    if (evidence.confidence) report.push(`   Confidence: ${evidence.confidence}%`);
  });
  report.push('');
  
  // Connected Entities
  report.push('CONNECTED SUSPICIOUS ENTITIES');
  report.push('-'.repeat(40));
  if (caseObj.connectedEntities.length === 0) {
    report.push('  None identified');
  } else {
    caseObj.connectedEntities.forEach(entity => {
      report.push(`  - ${entity}`);
    });
  }
  report.push('');
  
  // Transaction Paths
  report.push('TRANSACTION PATHS');
  report.push('-'.repeat(40));
  if (caseObj.transactionPaths.length === 0) {
    report.push('  No suspicious paths identified');
  } else {
    caseObj.transactionPaths.slice(0, 3).forEach((path, idx) => {
      report.push(`Path ${idx + 1}: ${path.path.join(' → ')}`);
      report.push(`  Total Amount: ₹${path.totalAmount.toLocaleString()}`);
      report.push(`  Risk Score: ${path.riskScore}/100`);
      report.push(`  Hops: ${path.path.length - 1}`);
    });
  }
  report.push('');
  
  // Investigator Notes
  report.push('INVESTIGATOR NOTES');
  report.push('-'.repeat(40));
  report.push(caseObj.investigatorNotes || 'No notes added');
  if (caseObj.falsePositiveReason) {
    report.push('');
    report.push(`FALSE POSITIVE REASON: ${caseObj.falsePositiveReason}`);
  }
  report.push('');
  
  // Footer
  report.push('='.repeat(60));
  report.push('Generated by TraceX Investigation Workspace');
  report.push(`Report Generated: ${new Date().toISOString()}`);
  report.push('='.repeat(60));
  
  return report.join('\\n');
}

// ============================================================================
// INVESTIGATION SUMMARY
// ============================================================================

export function getInvestigationSummary(): InvestigationSummary {
  const totalCases = cases.length;
  
  const casesByStatus: Record<InvestigationStatus, number> = {
    'NEW': 0,
    'INVESTIGATING': 0,
    'CONFIRMED': 0,
    'FALSE_POSITIVE': 0,
    'ESCALATED': 0,
    'CLOSED': 0
  };
  
  const casesByPriority: Record<string, number> = {
    'IMMEDIATE': 0,
    'HIGH': 0,
    'MEDIUM': 0,
    'LOW': 0
  };
  
  let totalResolutionTime = 0;
  let resolvedCases = 0;
  
  cases.forEach(c => {
    casesByStatus[c.status]++;
    casesByPriority[c.priority]++;
    
    if (c.closedAt && c.createdAt) {
      const created = new Date(c.createdAt).getTime();
      const closed = new Date(c.closedAt).getTime();
      totalResolutionTime += (closed - created) / (1000 * 60 * 60); // Convert to hours
      resolvedCases++;
    }
  });
  
  const averageResolutionTimeHours = resolvedCases > 0 ? totalResolutionTime / resolvedCases : 0;
  const falsePositiveRate = getFalsePositiveRate();
  const confirmedFraudRate = totalCases > 0 ? 
    (casesByStatus['CONFIRMED'] / totalCases) * 100 : 0;
  
  return {
    totalCases,
    casesByStatus,
    casesByPriority,
    averageResolutionTimeHours,
    falsePositiveRate,
    confirmedFraudRate
  };
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

export function formatCaseSummary(caseObj: InvestigationCase): string {
  return `[${caseObj.id}] ${caseObj.title} - ${caseObj.status} (${caseObj.priority})`;
}

export function getCaseAge(caseId: string): number | null {
  const caseObj = getCase(caseId);
  if (!caseObj) return null;
  
  const created = new Date(caseObj.createdAt).getTime();
  const now = Date.now();
  return (now - created) / (1000 * 60 * 60); // Return hours
}

export function getOverdueCases(hoursThreshold: number = 24): InvestigationCase[] {
  return cases.filter(c => {
    if (c.status === 'CLOSED' || c.status === 'FALSE_POSITIVE') return false;
    const age = getCaseAge(c.id);
    return age !== null && age > hoursThreshold;
  });
}

export function searchCases(query: string): InvestigationCase[] {
  const lowerQuery = query.toLowerCase();
  return cases.filter(c => 
    c.id.toLowerCase().includes(lowerQuery) ||
    c.title.toLowerCase().includes(lowerQuery) ||
    c.accountId.toLowerCase().includes(lowerQuery) ||
    c.accountLabel.toLowerCase().includes(lowerQuery) ||
    c.investigatorNotes.toLowerCase().includes(lowerQuery)
  );
}

export function exportCases(): InvestigationCase[] {
  return [...cases];
}

export function importCases(importedCases: InvestigationCase[]): void {
  cases = importedCases;
  // Update case counter
  const maxId = importedCases.reduce((max, c) => {
    const match = c.id.match(/CASE-(\d+)/);
    return match ? Math.max(max, parseInt(match[1])) : max;
  }, 0);
  caseCounter = maxId;
}

export function clearAllCases(): void {
  cases = [];
  caseCounter = 0;
}

// ============================================================================
// REAL-TIME CASE CREATION FROM PIPELINE
// ============================================================================

export function createCaseFromPipelineResult(
  result: {
    transactionId: string;
    source: string;
    target: string;
    amount: number;
    risk: RiskLevel;
    riskScore: number;
    confidenceScore: number;
    detectedPatterns: string[];
    sourceAnalysis?: MuleDetectionResult;
    targetAnalysis?: MuleDetectionResult;
  },
  edges: TransactionEdge[],
  nodes: EntityNode[]
): InvestigationCase | null {
  // Determine which account to investigate
  const accountId = result.source;
  const accountNode = nodes.find(n => n.id === accountId);
  
  // Get analysis for the account
  const analysis = result.sourceAnalysis || analyzeAccountForMule(accountId, edges, nodes);
  
  // Only create case if risk is significant
  if (analysis.riskScore < 50) return null;
  
  return createCase({
    accountId,
    accountLabel: accountNode?.label || accountId,
    riskScore: analysis.riskScore,
    riskLevel: analysis.riskLevel,
    confidenceScore: analysis.confidenceScore,
    detectedPatterns: analysis.detectedPatterns.map(p => p.type),
    evidence: analysis.supportingEvidence,
    connectedEntities: analysis.connectedSuspiciousEntities,
    transactionPaths: analysis.transactionPaths,
    priority: analysis.investigationPriority
  });
}