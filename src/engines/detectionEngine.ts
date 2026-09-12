import { 
  DetectedSuspiciousTransaction, 
  DetectionSignal, 
  InvestigationReportData, 
  RiskLevel, 
  EntityNode, 
  TransactionEdge,
  TransactionType
} from '../types/forensics';
import { formatINR } from '../data/mockForensics';

// Canonical detection signals specified in prompt
export const STANDARD_SIGNALS: Record<string, DetectionSignal> = {
  RAPID_MONEY_MOVEMENT: {
    id: 'SIG-RMM',
    name: 'Rapid Money Movement',
    severity: 'HIGH',
    description: 'Funds moved through multiple accounts within a short interval (< 14 minutes dwell time).',
    weight: 32,
  },
  UNUSUAL_AMOUNT: {
    id: 'SIG-UNA',
    name: 'Unusual Transaction Amount',
    severity: 'HIGH',
    description: 'Transaction value significantly differs from the observed historical baseline (+340% deviation).',
    weight: 30,
  },
  UNRELATED_ACCOUNT: {
    id: 'SIG-URA',
    name: 'Unrelated Account',
    severity: 'MEDIUM',
    description: 'Transaction involves an account with an unusual or non-reciprocal relationship to the network.',
    weight: 25,
  },
  CIRCULAR_ROUTING: {
    id: 'SIG-CIR',
    name: 'Circular Network Routing',
    severity: 'HIGH',
    description: 'Cyclic layered flow identified attempting to obscure primary origin of funds.',
    weight: 28,
  },
  UNHOSTED_GATEWAY: {
    id: 'SIG-VAS',
    name: 'High-Risk Gateway Interaction',
    severity: 'CRITICAL',
    description: 'Direct settlement into unhosted offramp node or non-cooperative digital terminal.',
    weight: 35,
  }
};

// Helper to calculate explainable deterministic fraud risk score based on Section 15 of user prompt
export function calculateFraudScore(signals: DetectionSignal[], baseFactors: number = 2): number {
  let score = baseFactors;
  for (const s of signals) {
    if (s.id === 'SIG-RMM') score += 30; // Rapid money movement
    else if (s.id === 'SIG-UNA') score += 35; // Unusual transaction amount
    else if (s.id === 'SIG-URA') score += 20; // Unrelated account
    else score += (s.weight || 20);
  }
  return Math.min(98, Math.max(15, score));
}

// Helper to generate AI risk explanation based ONLY on detected signals (Section 17)
export function generateAiRiskExplanation(signals: DetectionSignal[]): string {
  const signalIds = new Set(signals.map(s => s.id));
  const reasons: string[] = [];

  if (signalIds.has('SIG-RMM')) {
    reasons.push('a large amount moved through connected accounts within a short time period');
  }
  if (signalIds.has('SIG-UNA')) {
    reasons.push('the transaction value significantly exceeds the observed historical baseline for these counterparties');
  }
  if (signalIds.has('SIG-URA')) {
    reasons.push('the receiving account exhibits an unusual relationship within the observed transaction network');
  }
  if (signalIds.has('SIG-VAS')) {
    reasons.push('settlement was routed toward an unhosted or non-cooperative digital asset gateway');
  }
  if (signalIds.has('SIG-CIR')) {
    reasons.push('circular layered fund flows were detected attempting to obscure fund provenance');
  }

  if (reasons.length === 0) {
    return 'The transaction received an elevated risk score based on observed behavioral anomalies within the transaction stream.';
  }

  if (reasons.length === 1) {
    return `The transaction received a high-risk score because ${reasons[0]}.`;
  }

  const primary = reasons.slice(0, -1).join(', and ');
  const secondary = reasons[reasons.length - 1];
  return `The transaction received a high-risk score because ${primary}. Additionally, ${secondary}.`;
}

// Primary reference transaction required by user prompt
export const PRIMARY_DETECTED_TRANSACTION: DetectedSuspiciousTransaction = {
  transactionId: 'TXN-7F82A91C',
  timestamp: '17:53:04',
  source: 'ACC-TRX-9281',
  sourceLabel: 'ACC-9281 (Primary Mule)',
  target: 'ACC-INT-7712',
  targetLabel: 'ACC-7712 (Transit Intermediary)',
  amount: 250000,
  formattedAmount: '₹2,50,000',
  type: 'IMPS',
  fraudRiskScore: 87,
  riskLevel: 'HIGH',
  signals: [
    STANDARD_SIGNALS.RAPID_MONEY_MOVEMENT,
    STANDARD_SIGNALS.UNUSUAL_AMOUNT,
    STANDARD_SIGNALS.UNRELATED_ACCOUNT,
  ],
  aiExplanation: 'The transaction received a high-risk score because a large amount moved through connected accounts within a short time period, and the transaction value significantly exceeds the observed historical baseline. Additionally, the receiving account exhibits an unusual relationship within the observed transaction network.',
  tracePath: ['ACC-TRX-9281', 'ACC-INT-7712', 'ACC-INT-4428', 'ACC-SUB-9912'],
  connectedEntitiesCount: 27,
  transactionsInTrace: 14,
  totalFlow: '₹4.82L',
  traceDepth: 4,
  scenarioName: 'Rapid Money Movement',
  scenarioRun: 1,
  detectionSteps: [
    { time: '17:53:02', action: 'TRANSACTION RECEIVED', completed: true },
    { time: '17:53:03', action: 'TRANSACTION ANALYZED', completed: true },
    { time: '17:53:04', action: 'FRAUD RISK SCORE CALCULATED (87/100)', completed: true },
    { time: '17:53:04', action: 'SUSPICIOUS PATTERN DETECTED: RAPID MONEY MOVEMENT', completed: true },
    { time: '17:53:04', action: 'TXN-7F82A91C FLAGGED TO SIDE PANEL', completed: true },
    { time: '17:53:05', action: 'TRACE TOPOLOGY DISCOVERED', completed: true },
    { time: '17:53:06', action: 'INVESTIGATION REPORT AVAILABLE', completed: true },
  ]
};

// Additional pre-configured detected transactions for seamless analyst exploration
export const SECONDARY_DETECTED_TRANSACTIONS: DetectedSuspiciousTransaction[] = [
  {
    transactionId: 'TXN-91AB72C4',
    timestamp: '17:54:11',
    source: 'ACC-VIC-1002',
    sourceLabel: 'ACC-VIC-1002 (Corporate Victim)',
    target: 'ACC-TRX-9281',
    targetLabel: 'ACC-9281 (Primary Mule)',
    amount: 250000,
    formattedAmount: '₹2,50,000',
    type: 'RTGS',
    fraudRiskScore: 82,
    riskLevel: 'HIGH',
    signals: [
      STANDARD_SIGNALS.UNUSUAL_AMOUNT,
      STANDARD_SIGNALS.RAPID_MONEY_MOVEMENT,
    ],
    aiExplanation: 'The transaction received a high-risk score because the transaction value significantly exceeds the observed historical baseline. Additionally, funds moved through connected accounts within a short time period.',
    tracePath: ['ACC-VIC-1002', 'ACC-TRX-9281', 'ACC-INT-7712'],
    connectedEntitiesCount: 18,
    transactionsInTrace: 9,
    totalFlow: '₹3.40L',
    traceDepth: 3,
    scenarioName: 'Unusual Transaction Amount',
    scenarioRun: 2,
    detectionSteps: [
      { time: '17:54:09', action: 'TRANSACTION RECEIVED', completed: true },
      { time: '17:54:10', action: 'TRANSACTION ANALYZED', completed: true },
      { time: '17:54:11', action: 'FRAUD RISK SCORE CALCULATED (82/100)', completed: true },
      { time: '17:54:11', action: 'SUSPICIOUS PATTERN DETECTED: UNUSUAL AMOUNT', completed: true },
      { time: '17:54:11', action: 'TXN-91AB72C4 FLAGGED TO SIDE PANEL', completed: true },
      { time: '17:54:12', action: 'TRACE TOPOLOGY DISCOVERED', completed: true },
      { time: '17:54:13', action: 'INVESTIGATION REPORT AVAILABLE', completed: true },
    ]
  },
  {
    transactionId: 'TXN-9E11F504',
    timestamp: '17:50:22',
    source: 'ACC-INT-1109',
    sourceLabel: 'ACC-1109 (Transit Node C)',
    target: 'WAL-EXC-9902',
    targetLabel: 'WAL-EXC-9902 (Crypto Gateway)',
    amount: 450000,
    formattedAmount: '₹4,50,000',
    type: 'RTGS',
    fraudRiskScore: 92,
    riskLevel: 'CRITICAL',
    signals: [
      STANDARD_SIGNALS.UNHOSTED_GATEWAY,
      STANDARD_SIGNALS.UNUSUAL_AMOUNT,
      STANDARD_SIGNALS.RAPID_MONEY_MOVEMENT,
    ],
    aiExplanation: 'The transaction received a high-risk score because settlement was routed toward an unhosted digital asset gateway, and transaction value significantly exceeds the observed baseline. Additionally, funds moved rapidly through connected accounts.',
    tracePath: ['ACC-TRX-9281', 'ACC-INT-7712', 'ACC-INT-1109', 'WAL-EXC-9902'],
    connectedEntitiesCount: 31,
    transactionsInTrace: 19,
    totalFlow: '₹7.65L',
    traceDepth: 4,
    scenarioName: 'High-Risk Gateway Settlement',
    scenarioRun: 4,
    detectionSteps: [
      { time: '17:50:20', action: 'TRANSACTION RECEIVED', completed: true },
      { time: '17:50:21', action: 'TRANSACTION ANALYZED', completed: true },
      { time: '17:50:22', action: 'FRAUD RISK SCORE CALCULATED (92/100)', completed: true },
      { time: '17:50:22', action: 'SUSPICIOUS PATTERN DETECTED: UNHOSTED GATEWAY', completed: true },
      { time: '17:50:22', action: 'TXN-9E11F504 FLAGGED TO SIDE PANEL', completed: true },
      { time: '17:50:23', action: 'TRACE TOPOLOGY DISCOVERED', completed: true },
      { time: '17:50:24', action: 'INVESTIGATION REPORT AVAILABLE', completed: true },
    ]
  }
];

// Canonical list of detected transactions
export const CANONICAL_DETECTED_TRANSACTIONS: DetectedSuspiciousTransaction[] = [
  PRIMARY_DETECTED_TRANSACTION,
  ...SECONDARY_DETECTED_TRANSACTIONS
];

// Create a DetectedSuspiciousTransaction from a live stream event
export function createDetectedFromStreamEvent(
  streamEntry: {
    id: string;
    time: string;
    source: string;
    sourceLabel?: string;
    target: string;
    targetLabel?: string;
    type: TransactionType;
    amount: string;
    numericAmount?: number;
    risk: RiskLevel;
  },
  nodes: EntityNode[]
): DetectedSuspiciousTransaction {
  const nodeMap = new Map(nodes.map(n => [n.id, n]));
  const src = nodeMap.get(streamEntry.source);
  const tgt = nodeMap.get(streamEntry.target);

  const signals: DetectionSignal[] = [
    STANDARD_SIGNALS.RAPID_MONEY_MOVEMENT,
    STANDARD_SIGNALS.UNUSUAL_AMOUNT,
  ];

  if (src && tgt && src.clusterId !== tgt.clusterId) {
    signals.push(STANDARD_SIGNALS.UNRELATED_ACCOUNT);
  }

  const numAmount = streamEntry.numericAmount || 185000;
  const score = streamEntry.risk === 'CRITICAL' ? 88 : streamEntry.risk === 'HIGH' ? 74 : 52;
  const time = streamEntry.time.slice(0, 8);
  const txId = streamEntry.id.startsWith('TXN-') ? streamEntry.id : `TXN-${streamEntry.id.replace(/[^A-Za-z0-9]/g, '').slice(-8).toUpperCase()}`;

  const tracePath = [streamEntry.source, streamEntry.target];
  if (tgt && tgt.clusterId) {
    const nextHop = nodes.find(n => n.clusterId === tgt.clusterId && n.id !== tgt.id);
    if (nextHop) tracePath.push(nextHop.id);
  }

  return {
    transactionId: txId,
    timestamp: time,
    source: streamEntry.source,
    sourceLabel: streamEntry.sourceLabel,
    target: streamEntry.target,
    targetLabel: streamEntry.targetLabel,
    amount: numAmount,
    formattedAmount: streamEntry.amount,
    type: streamEntry.type,
    fraudRiskScore: score,
    riskLevel: streamEntry.risk,
    signals,
    aiExplanation: generateAiRiskExplanation(signals),
    tracePath,
    connectedEntitiesCount: (src?.transactionCount || 6) + (tgt?.transactionCount || 8),
    transactionsInTrace: 14,
    totalFlow: formatINR(numAmount * 2.5),
    traceDepth: tracePath.length,
    scenarioName: signals[0]?.name || 'Suspicious Anomaly',
    detectionSteps: [
      { time, action: 'TRANSACTION RECEIVED', completed: true },
      { time, action: 'TRANSACTION ANALYZED', completed: true },
      { time, action: 'RISK SCORE CALCULATED', completed: true },
      { time, action: 'SUSPICIOUS PATTERN DETECTED', completed: true },
      { time, action: `${txId} FLAGGED`, completed: true },
      { time, action: 'TRACE GENERATED', completed: true },
      { time, action: 'INVESTIGATION REPORT AVAILABLE', completed: true },
    ]
  };
}

// Generate report dossier for an entity from inspector
export function generateReportForEntity(
  entity: EntityNode,
  allEdges: TransactionEdge[],
  allNodes: EntityNode[]
): DetectedSuspiciousTransaction {
  const edge = allEdges.find(e => e.source === entity.id || e.target === entity.id) || allEdges[0];
  const detected = analyzeTransactionForDetection(edge, allNodes, allEdges);
  
  // Set entity's own score
  detected.fraudRiskScore = entity.riskScore;
  detected.riskLevel = entity.risk;
  detected.connectedEntitiesCount = entity.transactionCount * 2;
  return detected;
}

// Helper to determine risk level & band based on 0-100 score
export function getRiskBand(score: number): {
  level: RiskLevel;
  rangeLabel: string;
  badgeClass: string;
  textClass: string;
  summaryLabel: string;
} {
  if (score >= 80) {
    return {
      level: 'CRITICAL',
      rangeLabel: '80–100 CRITICAL',
      badgeClass: 'bg-red-950/80 text-red-300 border-red-700 shadow-[0_0_12px_rgba(239,68,68,0.4)]',
      textClass: 'text-red-400',
      summaryLabel: 'CRITICAL RISK — IMMEDIATE REVIEW REQUIRED',
    };
  }
  if (score >= 60) {
    return {
      level: 'HIGH',
      rangeLabel: '60–79 HIGH',
      badgeClass: 'bg-amber-950/80 text-amber-300 border-amber-700 shadow-[0_0_12px_rgba(245,158,11,0.3)]',
      textClass: 'text-amber-400',
      summaryLabel: 'HIGH RISK — REQUIRES REVIEW',
    };
  }
  if (score >= 30) {
    return {
      level: 'MEDIUM',
      rangeLabel: '30–59 MEDIUM',
      badgeClass: 'bg-yellow-950/70 text-yellow-300 border-yellow-700',
      textClass: 'text-yellow-400',
      summaryLabel: 'MEDIUM RISK — ELEVATED ANOMALY',
    };
  }
  return {
    level: 'LOW',
    rangeLabel: '0–29 LOW',
    badgeClass: 'bg-emerald-950/70 text-emerald-300 border-emerald-700',
    textClass: 'text-emerald-400',
    summaryLabel: 'LOW RISK — ROUTINE BASELINE',
  };
}

// Analyze any transaction edge into a detected suspicious transaction
export function analyzeTransactionForDetection(
  edge: TransactionEdge,
  nodes: EntityNode[],
  allEdges: TransactionEdge[]
): DetectedSuspiciousTransaction {
  const nodeMap = new Map(nodes.map(n => [n.id, n]));
  const src = nodeMap.get(edge.source);
  const tgt = nodeMap.get(edge.target);

  const signals: DetectionSignal[] = [];
  let score = 50;

  // Signal 1: Unusual amount
  if (edge.amount >= 200000) {
    signals.push(STANDARD_SIGNALS.UNUSUAL_AMOUNT);
    score += 24;
  }

  // Signal 2: Rapid money movement
  if (edge.type === 'IMPS' || edge.type === 'UPI' || (src && src.transactionCount > 10)) {
    signals.push(STANDARD_SIGNALS.RAPID_MONEY_MOVEMENT);
    score += 18;
  }

  // Signal 3: Unrelated account or cross-cluster
  if (src && tgt && src.clusterId !== tgt.clusterId) {
    signals.push(STANDARD_SIGNALS.UNRELATED_ACCOUNT);
    score += 15;
  }

  // Signal 4: Critical target / gateway
  if (tgt && (tgt.type === 'EXCHANGE' || tgt.type === 'ATM_CASHOUT')) {
    signals.push(STANDARD_SIGNALS.UNHOSTED_GATEWAY);
    score += 22;
  }

  // Cap score at 96 for dynamic transactions
  const finalScore = Math.min(96, Math.max(35, score));
  const band = getRiskBand(finalScore);

  // Compute local trace
  const tracePath = [edge.source, edge.target];
  const nextHop = allEdges.find(e => e.source === edge.target && e.target !== edge.source);
  if (nextHop) tracePath.push(nextHop.target);

  const time = edge.timestamp.includes(':') ? edge.timestamp.slice(0, 8) : '14:08:52';

  return {
    transactionId: edge.id.startsWith('TXN-') ? edge.id : `TXN-${edge.id.replace(/[^A-Za-z0-9]/g, '').slice(-8).toUpperCase()}`,
    timestamp: time,
    source: edge.source,
    sourceLabel: src?.label,
    target: edge.target,
    targetLabel: tgt?.label,
    amount: edge.amount,
    formattedAmount: edge.formattedAmount,
    type: edge.type,
    fraudRiskScore: finalScore,
    riskLevel: band.level,
    signals: signals.length > 0 ? signals : [STANDARD_SIGNALS.UNUSUAL_AMOUNT, STANDARD_SIGNALS.RAPID_MONEY_MOVEMENT],
    aiExplanation: generateAiRiskExplanation(signals.length > 0 ? signals : [STANDARD_SIGNALS.UNUSUAL_AMOUNT, STANDARD_SIGNALS.RAPID_MONEY_MOVEMENT]),
    tracePath,
    connectedEntitiesCount: (src?.transactionCount || 5) + (tgt?.transactionCount || 7),
    transactionsInTrace: 12,
    totalFlow: formatINR(edge.amount * 2.2),
    traceDepth: tracePath.length,
    scenarioName: signals[0]?.name || 'Flagged Anomaly',
    detectionSteps: [
      { time, action: 'TRANSACTION RECEIVED', completed: true },
      { time, action: 'TRANSACTION ANALYZED', completed: true },
      { time, action: `RISK SCORE CALCULATED (${finalScore}/100)`, completed: true },
      { time, action: 'SUSPICIOUS PATTERN DETECTED', completed: true },
      { time, action: `${edge.id} FLAGGED`, completed: true },
      { time, action: 'TRACE GENERATED', completed: true },
      { time, action: 'INVESTIGATION REPORT AVAILABLE', completed: true },
    ]
  };
}

// Generate the formal Investigation Report data
export function generateInvestigationReport(
  tx: DetectedSuspiciousTransaction
): InvestigationReportData {
  return {
    transactionId: tx.transactionId,
    detectionTimestamp: tx.timestamp,
    fraudRiskScore: tx.fraudRiskScore,
    riskLevel: tx.riskLevel,
    sender: tx.source,
    senderLabel: tx.sourceLabel,
    receiver: tx.target,
    receiverLabel: tx.targetLabel,
    amount: tx.formattedAmount,
    transactionType: tx.type,
    timestamp: tx.timestamp,
    signals: tx.signals,
    traceNodes: tx.tracePath,
    connectedEntitiesCount: tx.connectedEntitiesCount,
    transactionsCount: tx.transactionsInTrace,
    totalFlow: tx.totalFlow,
    traceDepth: tx.traceDepth,
    aiExplanation: tx.aiExplanation || generateAiRiskExplanation(tx.signals),
    systemConclusion: 'Suspicious transaction activity detected based on configured risk indicators. Further review is recommended.',
    generatedAt: new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
    analystRef: 'FORENSICS-ANALYST-UNIT-4'
  };
}
