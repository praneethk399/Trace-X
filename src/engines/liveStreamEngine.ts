/**
 * TraceX — Live Transaction Database Stream Engine
 * Realistic live ingestion stream with ~60s fraud detection cycle
 */

import { 
  StreamEvent, 
  DetectedSuspiciousTransaction, 
  DetectionSignal, 
  RiskLevel,
  TransactionType,
  EntityNode,
  TransactionEdge
} from '../types/forensics';
import { 
  STANDARD_SIGNALS, 
  calculateFraudScore, 
  generateAiRiskExplanation 
} from './detectionEngine';
import { formatINR } from '../data/mockForensics';

// Normal observed transaction amount range: ₹2,000 - ₹15,000
const NORMAL_ACCOUNTS = [
  { id: 'ACC-9281', label: 'ACC-9281 (Merchant Op)' },
  { id: 'ACC-7712', label: 'ACC-7712 (Layering Hub)' },
  { id: 'ACC-4428', label: 'ACC-4428 (Clearing Bridge)' },
  { id: 'ACC-9912', label: 'ACC-9912 (Sub-Treasury)' },
  { id: 'ACC-1182', label: 'ACC-1182 (Retail Gateway)' },
  { id: 'ACC-3310', label: 'ACC-3310 (Corporate Payroll)' },
  { id: 'ACC-5520', label: 'ACC-5520 (Retail Settlement)' },
  { id: 'ACC-8831', label: 'ACC-8831 (Commercial Acct)' },
];

const TX_TYPES: TransactionType[] = ['UPI', 'IMPS', 'NEFT', 'CARD'];

export interface StreamTelemetry {
  status: 'CONNECTED' | 'STREAMING' | 'IDLE';
  transactionsPerSec: number;
  totalAnalyzed: number;
  totalSuspicious: number;
  lastDetectionTime: string | null;
  currentDemoSeconds: number;
  targetDetectionSeconds: number;
}

// Generate a random normal transaction
export function generateNormalTransaction(sequence: number): StreamEvent {
  const fromIdx = Math.floor(Math.random() * NORMAL_ACCOUNTS.length);
  let toIdx = (fromIdx + 1 + Math.floor(Math.random() * (NORMAL_ACCOUNTS.length - 1))) % NORMAL_ACCOUNTS.length;
  
  const fromAcc = NORMAL_ACCOUNTS[fromIdx];
  const toAcc = NORMAL_ACCOUNTS[toIdx];
  
  // Normal amount ₹2,000–₹15,000 rounded to 100
  const amount = Math.floor(2000 + Math.random() * 13000);
  const roundedAmount = Math.round(amount / 100) * 100;
  const txType = TX_TYPES[Math.floor(Math.random() * TX_TYPES.length)];
  
  const now = new Date();
  const timeStr = now.toTimeString().slice(0, 8);
  
  const hexPart = Math.random().toString(16).substring(2, 6).toUpperCase();
  const txId = `TXN-${String(sequence).padStart(4, '0')}-${hexPart}`;
  
  // Normal risk score between 6 and 24
  const riskScore = Math.floor(8 + Math.random() * 16);
  
  return {
    id: txId,
    time: timeStr,
    source: fromAcc.id,
    sourceLabel: fromAcc.label,
    target: toAcc.id,
    targetLabel: toAcc.label,
    type: txType,
    amount: formatINR(roundedAmount),
    numericAmount: roundedAmount,
    risk: 'LOW',
    riskScore,
    status: 'NORMAL',
    detectionSignals: [],
    detected: false,
    hash: `0x${Math.random().toString(16).slice(2, 10)}`,
    isNew: true
  };
}

// Suspicious Scenario Builder based on Section 4 of prompt
export function buildSuspiciousScenario(
  demoRunIndex: number,
  sequence: number,
  nodes: EntityNode[],
  edges: TransactionEdge[]
): {
  streamEvent: StreamEvent;
  detectedTx: DetectedSuspiciousTransaction;
  scenarioName: string;
} {
  const now = new Date();
  const timeStr = now.toTimeString().slice(0, 8);
  const run = (demoRunIndex % 4) + 1;

  let txId = '';
  let source = 'ACC-TRX-9281';
  let sourceLabel = 'ACC-9281 (Primary Layering Node)';
  let target = 'ACC-INT-7712';
  let targetLabel = 'ACC-7712 (Transit Hub)';
  let amount = 250000;
  let txType: TransactionType = 'IMPS';
  let signals: DetectionSignal[] = [];
  let scenarioName = '';

  switch (run) {
    case 1:
      // Scenario A: RAPID MONEY MOVEMENT (ACC-9281 -> ACC-7712 -> ACC-4428 within short period)
      txId = 'TXN-7F82A91C';
      source = 'ACC-TRX-9281';
      sourceLabel = 'ACC-9281 (Primary Mule)';
      target = 'ACC-INT-7712';
      targetLabel = 'ACC-7712 (Transit Intermediary)';
      amount = 50000;
      txType = 'IMPS';
      scenarioName = 'Rapid Money Movement';
      signals = [
        STANDARD_SIGNALS.RAPID_MONEY_MOVEMENT,
        STANDARD_SIGNALS.UNRELATED_ACCOUNT,
      ];
      break;

    case 2:
      // Scenario B: UNUSUAL TRANSACTION AMOUNT (₹2,50,000 incoming vs ₹2k-₹15k baseline)
      txId = 'TXN-91AB72C4';
      source = 'ACC-VIC-1002';
      sourceLabel = 'ACC-VIC-1002 (Corporate Victim)';
      target = 'ACC-TRX-9281';
      targetLabel = 'ACC-9281 (Primary Mule)';
      amount = 250000;
      txType = 'RTGS';
      scenarioName = 'Unusual Transaction Amount';
      signals = [
        STANDARD_SIGNALS.UNUSUAL_AMOUNT,
        STANDARD_SIGNALS.RAPID_MONEY_MOVEMENT,
      ];
      break;

    case 3:
      // Scenario C: UNRELATED ACCOUNT (Sudden link between disjoint clusters)
      txId = 'TXN-38CD55E1';
      source = 'ACC-INT-4428';
      sourceLabel = 'ACC-4428 (Bridge Acct)';
      target = 'ACC-SUB-1182';
      targetLabel = 'ACC-1182 (Unrelated Off-Chain Node)';
      amount = 185000;
      txType = 'NEFT';
      scenarioName = 'Unrelated Account';
      signals = [
        STANDARD_SIGNALS.UNRELATED_ACCOUNT,
        STANDARD_SIGNALS.UNUSUAL_AMOUNT,
      ];
      break;

    case 4:
    default:
      // Scenario D: MULTIPLE COMBINED INDICATORS
      txId = 'TXN-6E99B417';
      source = 'ACC-INT-1109';
      sourceLabel = 'ACC-1109 (Transit Node C)';
      target = 'WAL-EXC-9902';
      targetLabel = 'WAL-EXC-9902 (Crypto Gateway)';
      amount = 450000;
      txType = 'RTGS';
      scenarioName = 'Multiple Combined Indicators';
      signals = [
        STANDARD_SIGNALS.RAPID_MONEY_MOVEMENT,
        STANDARD_SIGNALS.UNUSUAL_AMOUNT,
        STANDARD_SIGNALS.UNRELATED_ACCOUNT,
        STANDARD_SIGNALS.UNHOSTED_GATEWAY
      ];
      break;
  }

  // Calculate deterministic score based on prompt Section 15
  const fraudRiskScore = calculateFraudScore(signals, 2);
  const riskLevel: RiskLevel = fraudRiskScore >= 80 ? 'CRITICAL' : 'HIGH';
  const aiExplanation = generateAiRiskExplanation(signals);

  const tracePath = [source, target];
  const nextHop = edges.find(e => e.source === target && e.target !== source);
  if (nextHop) tracePath.push(nextHop.target);

  const streamEvent: StreamEvent = {
    id: txId,
    time: timeStr,
    source,
    sourceLabel,
    target,
    targetLabel,
    type: txType,
    amount: formatINR(amount),
    numericAmount: amount,
    risk: riskLevel,
    riskScore: fraudRiskScore,
    status: 'ALERT GENERATED',
    detectionSignals: signals.map(s => s.name),
    detected: true,
    hash: `0x${Math.random().toString(16).slice(2, 10)}`,
    isNew: true,
    scenarioRun: run
  };

  const detectedTx: DetectedSuspiciousTransaction = {
    transactionId: txId,
    timestamp: timeStr,
    source,
    sourceLabel,
    target,
    targetLabel,
    amount,
    formattedAmount: formatINR(amount),
    type: txType,
    fraudRiskScore,
    riskLevel,
    signals,
    aiExplanation,
    tracePath,
    connectedEntitiesCount: 14 + (run * 3),
    transactionsInTrace: 8 + run,
    totalFlow: formatINR(amount * 1.8),
    traceDepth: tracePath.length,
    scenarioName,
    scenarioRun: run,
    detectionSteps: [
      { time: timeStr, action: 'TRANSACTION RECEIVED', completed: true },
      { time: timeStr, action: 'TRANSACTION ANALYZED', completed: true },
      { time: timeStr, action: `FRAUD RISK SCORE CALCULATED (${fraudRiskScore}/100)`, completed: true },
      { time: timeStr, action: `SUSPICIOUS PATTERN DETECTED: ${signals[0].name.toUpperCase()}`, completed: true },
      { time: timeStr, action: `${txId} FLAGGED TO INVESTIGATION STACK`, completed: true },
      { time: timeStr, action: 'TRANSACTION TRACE DISCOVERED', completed: true },
      { time: timeStr, action: 'INVESTIGATION REPORT GENERATED', completed: true }
    ]
  };

  return { streamEvent, detectedTx, scenarioName };
}
