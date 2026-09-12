export type EntityType = 
  | 'ACCOUNT' 
  | 'WALLET' 
  | 'MERCHANT' 
  | 'MULE' 
  | 'EXCHANGE' 
  | 'SHELL_CORP' 
  | 'ATM_CASHOUT' 
  | 'INTERMEDIARY';

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type TransactionType = 'UPI' | 'IMPS' | 'NEFT' | 'RTGS' | 'CARD';

export type EntityStatus = 'NORMAL' | 'FLAGGED' | 'REVIEW_REQUIRED' | 'UNDER_SURVEILLANCE';

export interface EntityNode {
  id: string;
  nodeNumber: number;
  label: string;
  type: EntityType;
  risk: RiskLevel;
  riskScore: number;
  status: EntityStatus;
  transactionCount: number;
  inflow: number;
  outflow: number;
  balance: number;
  firstSeen: string;
  lastActivity: string;
  clusterId: string;
  clusterName: string;
  x: number;
  y: number;
  riskIndicators: string[];
  tags: string[];
  bankName?: string;
  jurisdiction?: string;
  ipAddress?: string;
  deviceFingerprint?: string;
  accountHolder?: string;
}

export interface TransactionEdge {
  id: string;
  source: string;
  target: string;
  type: TransactionType;
  amount: number;
  formattedAmount: string;
  timestamp: string;
  risk: RiskLevel;
  flowStatus: 'SETTLED' | 'IN_TRANSIT' | 'FLAGGED';
  hash: string;
  note?: string;
  suspiciousPattern?: string;
}

export interface PathAnalysisResult {
  sourceId: string;
  destinationId: string;
  nodes: EntityNode[];
  edges: TransactionEdge[];
  pathLength: number;
  totalValue: number;
  intermediariesCount: number;
  riskScore: number;
  steps: {
    fromNode: EntityNode;
    toNode: EntityNode;
    edge: TransactionEdge;
    amount: number;
  }[];
}

export interface CaseFile {
  id: string;
  title: string;
  status: 'ACTIVE INVESTIGATION' | 'CLOSED' | 'ESCALATED_FIU';
  priority: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  analyst: string;
  unit: string;
  openedAt: string;
  entitiesCount: number;
  transactionsCount: number;
  flaggedCount: number;
  totalValue: string;
  summary: string;
  evidence: {
    id: string;
    title: string;
    type: string;
    timestamp: string;
    confidence: number;
    description: string;
  }[];
  activityLog: {
    id: string;
    timestamp: string;
    analyst: string;
    action: string;
    tag: string;
  }[];
}

export interface FilterState {
  risk: 'ALL' | RiskLevel;
  txType: 'ALL' | TransactionType;
  timeRange: '1H' | '6H' | '24H' | '7D' | '30D';
  entityType: 'ALL' | EntityType;
  searchQuery: string;
  onlyFlagged: boolean;
}

export type ActiveView = 
  | 'INVESTIGATE' 
  | 'NETWORK' 
  | 'TRANSACTIONS' 
  | 'ENTITIES' 
  | 'RISK_ENGINE' 
  | 'CASES' 
  | 'TIMELINE';

export type TransactionProcessingStatus = 
  | 'RECEIVED' 
  | 'ANALYZING' 
  | 'ASSESSED' 
  | 'NORMAL' 
  | 'SUSPICIOUS' 
  | 'ALERT GENERATED';

export interface StreamEvent {
  id: string;
  time: string;
  source: string;
  target: string;
  sourceLabel?: string;
  targetLabel?: string;
  type: TransactionType;
  amount: string;
  numericAmount: number;
  risk: RiskLevel;
  riskScore: number;
  status: TransactionProcessingStatus;
  detectionSignals?: string[];
  detected?: boolean;
  hash?: string;
  isNew?: boolean;
  scenarioRun?: number;
}

export interface DetectionSignal {
  id: string;
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  weight: number;
}

export interface DetectedSuspiciousTransaction {
  transactionId: string;
  timestamp: string;
  source: string;
  sourceLabel?: string;
  target: string;
  targetLabel?: string;
  amount: number;
  formattedAmount: string;
  type: TransactionType;
  fraudRiskScore: number;
  riskLevel: RiskLevel;
  signals: DetectionSignal[];
  aiExplanation: string;
  tracePath: string[];
  connectedEntitiesCount: number;
  transactionsInTrace: number;
  totalFlow: string;
  traceDepth: number;
  detectionSteps: {
    time: string;
    action: string;
    completed: boolean;
  }[];
  scenarioName?: string;
  scenarioRun?: number;
}

export interface InvestigationReportData {
  transactionId: string;
  detectionTimestamp: string;
  fraudRiskScore: number;
  riskLevel: RiskLevel;
  sender: string;
  senderLabel?: string;
  receiver: string;
  receiverLabel?: string;
  amount: string;
  transactionType: TransactionType;
  timestamp: string;
  signals: DetectionSignal[];
  traceNodes: string[];
  connectedEntitiesCount: number;
  transactionsCount: number;
  totalFlow: string;
  traceDepth: number;
  aiExplanation: string;
  systemConclusion: string;
  generatedAt: string;
  analystRef: string;
}

// ============================================================================
// MULE DETECTION TYPES
// ============================================================================

export type InvestigationStatus = 
  | 'NEW' 
  | 'INVESTIGATING' 
  | 'CONFIRMED' 
  | 'FALSE_POSITIVE' 
  | 'ESCALATED' 
  | 'CLOSED';

export interface InvestigationCase {
  id: string;
  title: string;
  status: InvestigationStatus;
  priority: 'IMMEDIATE' | 'HIGH' | 'MEDIUM' | 'LOW';
  accountId: string;
  accountLabel: string;
  riskScore: number;
  riskLevel: RiskLevel;
  confidenceScore: number;
  detectedPatterns: string[];
  evidence: EvidenceItem[];
  connectedEntities: string[];
  transactionPaths: TransactionPathInfo[];
  investigatorNotes: string;
  falsePositiveReason?: string;
  createdAt: string;
  updatedAt: string;
  closedAt?: string;
  assignedTo?: string;
}

export interface EvidenceItem {
  type: 'TRANSACTION' | 'PATTERN' | 'TEMPORAL' | 'NETWORK' | 'BEHAVIOURAL';
  description: string;
  transactionId?: string;
  timestamp?: string;
  amount?: number;
  confidence: number;
}

export interface TransactionPathInfo {
  path: string[];
  amounts: number[];
  timestamps: string[];
  totalAmount: number;
  riskScore: number;
}

export interface MuleDetectionResult {
  accountId: string;
  riskScore: number;
  riskLevel: RiskLevel;
  confidenceScore: number;
  detectedPatterns: DetectedPattern[];
  supportingEvidence: EvidenceItem[];
  connectedSuspiciousEntities: string[];
  transactionPaths: TransactionPathInfo[];
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

export interface RiskBreakdown {
  velocityScore: number;
  networkScore: number;
  amountScore: number;
  frequencyScore: number;
  patternScore: number;
  behaviouralScore: number;
  temporalScore: number;
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
  status: 'NEW' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'RESOLVED';
}

export interface PipelineMetrics {
  totalProcessed: number;
  totalSuspicious: number;
  totalAlerts: number;
  averageProcessingTimeMs: number;
  alertsByType: Record<string, number>;
  alertsBySeverity: Record<string, number>;
}

