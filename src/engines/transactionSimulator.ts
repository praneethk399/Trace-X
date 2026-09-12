/**
 * TraceX — Transaction Simulator
 * Realistic transaction generation with fraud scenario injection:
 * - Normal transactions
 * - High-value transactions
 * - Rapid transfers
 * - Fan-in/fan-out patterns
 * - Layering
 * - Circular transactions
 * - Mule-account networks
 * - Dormancy bursts
 * 
 * @license Apache-2.0
 */

import {
  TransactionEdge,
  EntityNode,
  StreamEvent,
  RiskLevel,
  TransactionType
} from '../types/forensics';
import { formatINR } from '../data/mockForensics';

// ============================================================================
// TYPES
// ============================================================================

export interface SimulatorConfig {
  transactionRate: number; // transactions per second
  accountCount: number;
  normalAmountRange: [number, number];
  suspiciousPercentage: number;
  activeScenario: FraudScenario | null;
  scenarioInjectionTime: number; // seconds from start
}

export type FraudScenario =
  | 'NORMAL'
  | 'RAPID_MONEY_MOVEMENT'
  | 'FAN_IN'
  | 'FAN_OUT'
  | 'LAYERING'
  | 'CIRCULAR'
  | 'MULE_HUB'
  | 'DORMANCY_BURST'
  | 'ALL_SCENARIOS';

export interface SimulationState {
  isRunning: boolean;
  startTime: number;
  transactionCount: number;
  suspiciousCount: number;
  currentScenario: FraudScenario | null;
  scenarioInjected: boolean;
  accounts: SimulatedAccount[];
  transactions: TransactionEdge[];
}

export interface SimulatedAccount {
  id: string;
  label: string;
  type: 'NORMAL' | 'MULE' | 'SOURCE' | 'DESTINATION' | 'INTERMEDIARY';
  risk: RiskLevel;
  balance: number;
  transactionCount: number;
  lastActivity: number;
  dormant: boolean;
  dormantDays: number;
}

// ============================================================================
// SIMULATOR CONFIGURATION
// ============================================================================

const DEFAULT_CONFIG: SimulatorConfig = {
  transactionRate: 2, // 2 transactions per second
  accountCount: 50,
  normalAmountRange: [1000, 50000],
  suspiciousPercentage: 15,
  activeScenario: null,
  scenarioInjectionTime: 30
};

let currentState: SimulationState = {
  isRunning: false,
  startTime: 0,
  transactionCount: 0,
  suspiciousCount: 0,
  currentScenario: null,
  scenarioInjected: false,
  accounts: [],
  transactions: []
};

// ============================================================================
// ACCOUNT GENERATION
// ============================================================================

function generateAccounts(count: number): SimulatedAccount[] {
  const accounts: SimulatedAccount[] = [];
  
  for (let i = 0; i < count; i++) {
    const isMule = i < count * 0.1; // 10% mule accounts
    const isSource = i >= count * 0.1 && i < count * 0.15; // 5% source accounts
    const isDestination = i >= count * 0.15 && i < count * 0.2; // 5% destination accounts
    const isIntermediary = i >= count * 0.2 && i < count * 0.3; // 10% intermediary accounts
    
    let type: SimulatedAccount['type'] = 'NORMAL';
    let risk: RiskLevel = 'LOW';
    
    if (isMule) {
      type = 'MULE';
      risk = 'HIGH';
    } else if (isSource) {
      type = 'SOURCE';
      risk = 'MEDIUM';
    } else if (isDestination) {
      type = 'DESTINATION';
      risk = 'MEDIUM';
    } else if (isIntermediary) {
      type = 'INTERMEDIARY';
      risk = 'MEDIUM';
    }
    
    accounts.push({
      id: `ACC-${String(i + 1).padStart(4, '0')}`,
      label: `Account ${i + 1} (${type})`,
      type,
      risk,
      balance: Math.floor(10000 + Math.random() * 1000000),
      transactionCount: 0,
      lastActivity: Date.now(),
      dormant: Math.random() > 0.9, // 10% dormant accounts
      dormantDays: Math.floor(Math.random() * 60)
    });
  }
  
  return accounts;
}

// ============================================================================
// TRANSACTION GENERATION
// ============================================================================

function generateNormalTransaction(accounts: SimulatedAccount[]): TransactionEdge {
  // Pick two random normal accounts
  const normalAccounts = accounts.filter(a => a.type === 'NORMAL' || a.type === 'SOURCE');
  const source = normalAccounts[Math.floor(Math.random() * normalAccounts.length)];
  let target = normalAccounts[Math.floor(Math.random() * normalAccounts.length)];
  
  while (target.id === source.id) {
    target = normalAccounts[Math.floor(Math.random() * normalAccounts.length)];
  }
  
  const amount = Math.floor(
    DEFAULT_CONFIG.normalAmountRange[0] + 
    Math.random() * (DEFAULT_CONFIG.normalAmountRange[1] - DEFAULT_CONFIG.normalAmountRange[0])
  );
  
  const types: TransactionType[] = ['UPI', 'IMPS', 'NEFT', 'CARD'];
  const type = types[Math.floor(Math.random() * types.length)];
  
  const now = new Date();
  const timeStr = now.toTimeString().slice(0, 8);
  
  return {
    id: `TXN-${Date.now()}-${Math.random().toString(16).slice(2, 6).toUpperCase()}`,
    source: source.id,
    target: target.id,
    type,
    amount,
    formattedAmount: formatINR(amount),
    timestamp: timeStr,
    risk: 'LOW',
    flowStatus: 'SETTLED',
    hash: `0x${Math.random().toString(16).slice(2, 10)}`
  };
}

function generateRapidMovementTransaction(accounts: SimulatedAccount[]): TransactionEdge {
  // Rapid movement: mule account sends quickly
  const muleAccounts = accounts.filter(a => a.type === 'MULE');
  const source = muleAccounts[Math.floor(Math.random() * muleAccounts.length)];
  
  // Send to multiple destinations quickly
  const destinations = accounts.filter(a => a.type === 'DESTINATION' || a.type === 'NORMAL');
  const target = destinations[Math.floor(Math.random() * destinations.length)];
  
  const amount = Math.floor(50000 + Math.random() * 200000);
  
  const now = new Date();
  const timeStr = now.toTimeString().slice(0, 8);
  
  return {
    id: `TXN-${Date.now()}-RAPID`,
    source: source.id,
    target: target.id,
    type: 'IMPS',
    amount,
    formattedAmount: formatINR(amount),
    timestamp: timeStr,
    risk: 'HIGH',
    flowStatus: 'IN_TRANSIT',
    hash: `0x${Math.random().toString(16).slice(2, 10)}`,
    suspiciousPattern: 'Rapid money movement detected'
  };
}

function generateFanInTransaction(accounts: SimulatedAccount[]): TransactionEdge {
  // Multiple accounts send to one mule
  const muleAccounts = accounts.filter(a => a.type === 'MULE');
  const mule = muleAccounts[Math.floor(Math.random() * muleAccounts.length)];
  
  const sources = accounts.filter(a => a.type === 'NORMAL' || a.type === 'SOURCE');
  const source = sources[Math.floor(Math.random() * sources.length)];
  
  const amount = Math.floor(10000 + Math.random() * 100000);
  
  const now = new Date();
  const timeStr = now.toTimeString().slice(0, 8);
  
  return {
    id: `TXN-${Date.now()}-FANIN`,
    source: source.id,
    target: mule.id,
    type: 'NEFT',
    amount,
    formattedAmount: formatINR(amount),
    timestamp: timeStr,
    risk: 'MEDIUM',
    flowStatus: 'SETTLED',
    hash: `0x${Math.random().toString(16).slice(2, 10)}`,
    suspiciousPattern: 'Fan-in pattern detected'
  };
}

function generateFanOutTransaction(accounts: SimulatedAccount[]): TransactionEdge {
  // Mule sends to multiple accounts
  const muleAccounts = accounts.filter(a => a.type === 'MULE');
  const mule = muleAccounts[Math.floor(Math.random() * muleAccounts.length)];
  
  const destinations = accounts.filter(a => a.type === 'DESTINATION' || a.type === 'NORMAL');
  const target = destinations[Math.floor(Math.random() * destinations.length)];
  
  const amount = Math.floor(20000 + Math.random() * 150000);
  
  const now = new Date();
  const timeStr = now.toTimeString().slice(0, 8);
  
  return {
    id: `TXN-${Date.now()}-FANOUT`,
    source: mule.id,
    target: target.id,
    type: 'UPI',
    amount,
    formattedAmount: formatINR(amount),
    timestamp: timeStr,
    risk: 'HIGH',
    flowStatus: 'IN_TRANSIT',
    hash: `0x${Math.random().toString(16).slice(2, 10)}`,
    suspiciousPattern: 'Fan-out pattern detected'
  };
}

function generateLayeringTransaction(accounts: SimulatedAccount[]): TransactionEdge {
  // A → B → C pattern
  const source = accounts[Math.floor(Math.random() * accounts.length)];
  const intermediary = accounts.filter(a => a.type === 'INTERMEDIARY');
  const target = intermediary[Math.floor(Math.random() * intermediary.length)];
  
  const amount = Math.floor(100000 + Math.random() * 500000);
  
  const now = new Date();
  const timeStr = now.toTimeString().slice(0, 8);
  
  return {
    id: `TXN-${Date.now()}-LAYER`,
    source: source.id,
    target: target.id,
    type: 'RTGS',
    amount,
    formattedAmount: formatINR(amount),
    timestamp: timeStr,
    risk: 'HIGH',
    flowStatus: 'FLAGGED',
    hash: `0x${Math.random().toString(16).slice(2, 10)}`,
    suspiciousPattern: 'Layering pattern detected'
  };
}

function generateCircularTransaction(accounts: SimulatedAccount[]): TransactionEdge {
  // A → B → C → A
  const muleAccounts = accounts.filter(a => a.type === 'MULE');
  const source = muleAccounts[Math.floor(Math.random() * muleAccounts.length)];
  const target = accounts[Math.floor(Math.random() * accounts.length)];
  
  const amount = Math.floor(50000 + Math.random() * 300000);
  
  const now = new Date();
  const timeStr = now.toTimeString().slice(0, 8);
  
  return {
    id: `TXN-${Date.now()}-CIRC`,
    source: source.id,
    target: target.id,
    type: 'IMPS',
    amount,
    formattedAmount: formatINR(amount),
    timestamp: timeStr,
    risk: 'CRITICAL',
    flowStatus: 'FLAGGED',
    hash: `0x${Math.random().toString(16).slice(2, 10)}`,
    suspiciousPattern: 'Circular transfer detected'
  };
}

function generateDormancyBurstTransaction(accounts: SimulatedAccount[]): TransactionEdge {
  // Dormant account suddenly active
  const dormantAccounts = accounts.filter(a => a.dormant);
  const source = dormantAccounts[Math.floor(Math.random() * dormantAccounts.length)];
  
  const target = accounts[Math.floor(Math.random() * accounts.length)];
  
  const amount = Math.floor(200000 + Math.random() * 800000);
  
  const now = new Date();
  const timeStr = now.toTimeString().slice(0, 8);
  
  // Mark account as active
  source.dormant = false;
  source.lastActivity = Date.now();
  
  return {
    id: `TXN-${Date.now()}-DORM`,
    source: source.id,
    target: target.id,
    type: 'RTGS',
    amount,
    formattedAmount: formatINR(amount),
    timestamp: timeStr,
    risk: 'CRITICAL',
    flowStatus: 'FLAGGED',
    hash: `0x${Math.random().toString(16).slice(2, 10)}`,
    suspiciousPattern: 'Dormancy burst detected'
  };
}

// ============================================================================
// SCENARIO MANAGEMENT
// ============================================================================

export function setScenario(scenario: FraudScenario): void {
  currentState.currentScenario = scenario;
  currentState.scenarioInjected = false;
}

export function injectScenario(
  scenario: FraudScenario,
  accounts: SimulatedAccount[]
): TransactionEdge[] {
  const transactions: TransactionEdge[] = [];
  const now = Date.now();
  
  switch (scenario) {
    case 'RAPID_MONEY_MOVEMENT':
      // Generate 5 rapid transactions
      for (let i = 0; i < 5; i++) {
        transactions.push(generateRapidMovementTransaction(accounts));
      }
      break;
      
    case 'FAN_IN':
      // Generate 4 fan-in transactions to same mule
      for (let i = 0; i < 4; i++) {
        transactions.push(generateFanInTransaction(accounts));
      }
      break;
      
    case 'FAN_OUT':
      // Generate 4 fan-out transactions from same mule
      for (let i = 0; i < 4; i++) {
        transactions.push(generateFanOutTransaction(accounts));
      }
      break;
      
    case 'LAYERING':
      // Generate 3 layering transactions
      for (let i = 0; i < 3; i++) {
        transactions.push(generateLayeringTransaction(accounts));
      }
      break;
      
    case 'CIRCULAR':
      // Generate circular flow
      for (let i = 0; i < 3; i++) {
        transactions.push(generateCircularTransaction(accounts));
      }
      break;
      
    case 'MULE_HUB':
      // Generate multiple patterns around a mule
      transactions.push(generateFanInTransaction(accounts));
      transactions.push(generateFanInTransaction(accounts));
      transactions.push(generateFanOutTransaction(accounts));
      transactions.push(generateFanOutTransaction(accounts));
      break;
      
    case 'DORMANCY_BURST':
      // Generate dormancy burst
      for (let i = 0; i < 5; i++) {
        transactions.push(generateDormancyBurstTransaction(accounts));
      }
      break;
      
    case 'ALL_SCENARIOS':
      // Generate one of each
      transactions.push(generateRapidMovementTransaction(accounts));
      transactions.push(generateFanInTransaction(accounts));
      transactions.push(generateFanOutTransaction(accounts));
      transactions.push(generateLayeringTransaction(accounts));
      transactions.push(generateCircularTransaction(accounts));
      transactions.push(generateDormancyBurstTransaction(accounts));
      break;
      
    default:
      // Normal transaction
      transactions.push(generateNormalTransaction(accounts));
  }
  
  currentState.scenarioInjected = true;
  return transactions;
}

// ============================================================================
// SIMULATION CONTROL
// ============================================================================

export function startSimulation(config: Partial<SimulatorConfig> = {}): SimulationState {
  const fullConfig = { ...DEFAULT_CONFIG, ...config };
  
  currentState = {
    isRunning: true,
    startTime: Date.now(),
    transactionCount: 0,
    suspiciousCount: 0,
    currentScenario: fullConfig.activeScenario,
    scenarioInjected: false,
    accounts: generateAccounts(fullConfig.accountCount),
    transactions: []
  };
  
  return currentState;
}

export function stopSimulation(): SimulationState {
  currentState.isRunning = false;
  return currentState;
}

export function pauseSimulation(): SimulationState {
  currentState.isRunning = false;
  return currentState;
}

export function resumeSimulation(): SimulationState {
  currentState.isRunning = true;
  return currentState;
}

export function resetSimulation(): SimulationState {
  currentState = {
    isRunning: false,
    startTime: 0,
    transactionCount: 0,
    suspiciousCount: 0,
    currentScenario: null,
    scenarioInjected: false,
    accounts: [],
    transactions: []
  };
  
  return currentState;
}

export function getSimulationState(): SimulationState {
  return { ...currentState };
}

// ============================================================================
// TRANSACTION GENERATION
// ============================================================================

export function generateNextTransaction(): TransactionEdge | null {
  if (!currentState.isRunning) return null;
  
  // Check if it's time to inject scenario
  const elapsedSeconds = (Date.now() - currentState.startTime) / 1000;
  if (
    currentState.currentScenario &&
    !currentState.scenarioInjected &&
    elapsedSeconds >= DEFAULT_CONFIG.scenarioInjectionTime
  ) {
    const injected = injectScenario(currentState.currentScenario, currentState.accounts);
    if (injected.length > 0) {
      currentState.transactions.push(...injected);
      currentState.transactionCount += injected.length;
      currentState.suspiciousCount += injected.filter(t => t.risk !== 'LOW').length;
      return injected[0];
    }
  }
  
  // Generate normal or suspicious transaction
  const isSuspicious = Math.random() * 100 < DEFAULT_CONFIG.suspiciousPercentage;
  
  let transaction: TransactionEdge;
  if (isSuspicious) {
    // Generate suspicious transaction
    const muleAccounts = currentState.accounts.filter(a => a.type === 'MULE');
    if (muleAccounts.length > 0) {
      transaction = generateRapidMovementTransaction(currentState.accounts);
    } else {
      transaction = generateNormalTransaction(currentState.accounts);
    }
  } else {
    transaction = generateNormalTransaction(currentState.accounts);
  }
  
  currentState.transactions.push(transaction);
  currentState.transactionCount++;
  
  if (transaction.risk !== 'LOW') {
    currentState.suspiciousCount++;
  }
  
  // Update account activity
  const sourceAccount = currentState.accounts.find(a => a.id === transaction.source);
  const targetAccount = currentState.accounts.find(a => a.id === transaction.target);
  
  if (sourceAccount) {
    sourceAccount.transactionCount++;
    sourceAccount.lastActivity = Date.now();
    sourceAccount.balance -= transaction.amount;
  }
  
  if (targetAccount) {
    targetAccount.transactionCount++;
    targetAccount.lastActivity = Date.now();
    targetAccount.balance += transaction.amount;
  }
  
  return transaction;
}

export function generateStreamEvent(transaction: TransactionEdge): StreamEvent {
  const sourceAccount = currentState.accounts.find(a => a.id === transaction.source);
  const targetAccount = currentState.accounts.find(a => a.id === transaction.target);
  
  return {
    id: transaction.id,
    time: transaction.timestamp,
    source: transaction.source,
    target: transaction.target,
    sourceLabel: sourceAccount?.label,
    targetLabel: targetAccount?.label,
    type: transaction.type,
    amount: transaction.formattedAmount,
    numericAmount: transaction.amount,
    risk: transaction.risk,
    riskScore: transaction.risk === 'CRITICAL' ? 85 : 
               transaction.risk === 'HIGH' ? 68 : 
               transaction.risk === 'MEDIUM' ? 45 : 20,
    status: transaction.risk !== 'LOW' ? 'ALERT GENERATED' : 'ASSESSED',
    detectionSignals: transaction.suspiciousPattern ? [transaction.suspiciousPattern] : [],
    detected: transaction.risk !== 'LOW',
    hash: transaction.hash,
    isNew: true
  };
}

// ============================================================================
// STATISTICS
// ============================================================================

export function getSimulationStats(): {
  totalTransactions: number;
  suspiciousTransactions: number;
  normalTransactions: number;
  suspiciousPercentage: number;
  averageAmount: number;
  transactionsByType: Record<TransactionType, number>;
  transactionsByRisk: Record<RiskLevel, number>;
  activeAccounts: number;
  dormantAccounts: number;
  elapsedSeconds: number;
} {
  const transactions = currentState.transactions;
  const totalTransactions = transactions.length;
  const suspiciousTransactions = transactions.filter(t => t.risk !== 'LOW').length;
  const normalTransactions = totalTransactions - suspiciousTransactions;
  
  const suspiciousPercentage = totalTransactions > 0 ? 
    (suspiciousTransactions / totalTransactions) * 100 : 0;
  
  const averageAmount = totalTransactions > 0 ?
    transactions.reduce((sum, t) => sum + t.amount, 0) / totalTransactions : 0;
  
  const transactionsByType: Record<TransactionType, number> = {
    'UPI': 0,
    'IMPS': 0,
    'NEFT': 0,
    'RTGS': 0,
    'CARD': 0
  };
  
  const transactionsByRisk: Record<RiskLevel, number> = {
    'LOW': 0,
    'MEDIUM': 0,
    'HIGH': 0,
    'CRITICAL': 0
  };
  
  transactions.forEach(t => {
    transactionsByType[t.type]++;
    transactionsByRisk[t.risk]++;
  });
  
  const activeAccounts = currentState.accounts.filter(a => !a.dormant).length;
  const dormantAccounts = currentState.accounts.filter(a => a.dormant).length;
  
  const elapsedSeconds = currentState.isRunning ? 
    (Date.now() - currentState.startTime) / 1000 : 0;
  
  return {
    totalTransactions,
    suspiciousTransactions,
    normalTransactions,
    suspiciousPercentage,
    averageAmount,
    transactionsByType,
    transactionsByRisk,
    activeAccounts,
    dormantAccounts,
    elapsedSeconds
  };
}

// ============================================================================
// SCENARIO UTILITIES
// ============================================================================

export function getAvailableScenarios(): { id: FraudScenario; name: string; description: string }[] {
  return [
    { id: 'NORMAL', name: 'Normal Activity', description: 'Standard transaction patterns' },
    { id: 'RAPID_MONEY_MOVEMENT', name: 'Rapid Money Movement', description: 'Quick succession of transfers' },
    { id: 'FAN_IN', name: 'Fan-In Pattern', description: 'Multiple accounts sending to one' },
    { id: 'FAN_OUT', name: 'Fan-Out Pattern', description: 'One account sending to many' },
    { id: 'LAYERING', name: 'Layering', description: 'A → B → C fund flow' },
    { id: 'CIRCULAR', name: 'Circular Transfer', description: 'A → B → C → A cycle' },
    { id: 'MULE_HUB', name: 'Mule Hub', description: 'Central mule receiving and distributing' },
    { id: 'DORMANCY_BURST', name: 'Dormancy Burst', description: 'Inactive account suddenly active' },
    { id: 'ALL_SCENARIOS', name: 'All Scenarios', description: 'Demonstrate all fraud patterns' }
  ];
}

export function formatSimulationDuration(seconds: number): string {
  const mins = Math.floor(seconds / 60);
  const secs = Math.floor(seconds % 60);
  return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
}