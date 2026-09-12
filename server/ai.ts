/**
 * TraceX — AI Risk Explanation (Gemini via @google/genai)
 * =======================================================
 * Produces analyst-readable explanations of why a transaction was flagged.
 * Falls back to the deterministic explanation generator in the detection
 * engine whenever the API key is missing or the call fails, so the endpoint
 * always answers.
 *
 * @license Apache-2.0
 */

import { GoogleGenAI } from '@google/genai';

import {
  DetectedSuspiciousTransaction,
  DetectionSignal,
} from '../src/types/forensics';
import { generateAiRiskExplanation } from '../src/engines/detectionEngine';
import { formatINR } from '../src/data/mockForensics';

const GEMINI_API_KEY = process.env.GEMINI_API_KEY || '';
const MODEL = 'gemini-2.0-flash';

let client: GoogleGenAI | null = null;

function getClient(): GoogleGenAI | null {
  if (!GEMINI_API_KEY) return null;
  if (!client) {
    try {
      client = new GoogleGenAI({ apiKey: GEMINI_API_KEY });
    } catch {
      client = null;
    }
  }
  return client;
}

export function aiAvailable(): boolean {
  return Boolean(getClient());
}

function buildPrompt(tx: DetectedSuspiciousTransaction): string {
  const signalLines = tx.signals
    .map(s => `- ${s.name} (${s.severity}, weight ${s.weight}): ${s.description}`)
    .join('\n');

  return [
    'You are a financial-crime forensic analyst writing a concise risk explanation for a flagged transaction.',
    'Rules:',
    '- 2 to 4 sentences, factual, no hedging, no markdown, no bullet lists.',
    '- Reference ONLY the evidence below; never invent details.',
    '- Mention the amount, the transaction type, and the specific signals that fired.',
    '',
    `Transaction ID: ${tx.transactionId}`,
    `Timestamp: ${tx.timestamp}`,
    `Route: ${tx.source} -> ${tx.target}`,
    `Amount: ${tx.formattedAmount} (${tx.amount} INR)`,
    `Type: ${tx.type}`,
    `Risk score: ${tx.fraudRiskScore}/100 (${tx.riskLevel})`,
    '',
    'Detected signals:',
    signalLines,
    '',
    'Write the explanation now.',
  ].join('\n');
}

/**
 * Generates an AI explanation. Returns `{ text, source: 'ai' | 'fallback' }`.
 * Never throws — failures degrade to the deterministic explanation.
 */
export async function explainRisk(tx: DetectedSuspiciousTransaction): Promise<{ text: string; source: 'ai' | 'fallback' }> {
  const fallback = () => ({ text: generateAiRiskExplanation(tx.signals), source: 'fallback' as const });

  const ai = getClient();
  if (!ai) return fallback();

  try {
    const response = await ai.models.generateContent({
      model: MODEL,
      contents: buildPrompt(tx),
      config: { temperature: 0.2, maxOutputTokens: 220 },
    });
    const text = (response.text ?? '').trim();
    if (!text) return fallback();
    return { text, source: 'ai' };
  } catch {
    return fallback();
  }
}

/**
 * Builds the DetectedSuspiciousTransaction-like payload the /api/analyze/tx
 * and /api/report endpoints need, from a PipelineResult + context. Kept here
 * so both routes construct identical reports.
 */
export function buildDetectedFromPipeline(
  result: {
    transactionId: string;
    timestamp: string;
    source: string;
    target: string;
    amount: number;
    risk: string;
    riskScore: number;
    signals: DetectionSignal[];
    detectedPatterns: string[];
  },
  context: { sourceLabel?: string; targetLabel?: string; tracePath: string[] }
): DetectedSuspiciousTransaction {
  const signals = result.signals.length
    ? result.signals
    : ([
        { id: 'SIG-UNA', name: 'Unusual Transaction Amount', severity: 'HIGH' as const, description: 'Amount exceeds observed baseline', weight: 30 },
      ] as DetectionSignal[]);

  const level = result.risk as DetectedSuspiciousTransaction['riskLevel'];
  return {
    transactionId: result.transactionId,
    timestamp: result.timestamp,
    source: result.source,
    sourceLabel: context.sourceLabel,
    target: result.target,
    targetLabel: context.targetLabel,
    amount: result.amount,
    formattedAmount: formatINR(result.amount),
    type: 'IMPS',
    fraudRiskScore: result.riskScore,
    riskLevel: level,
    signals,
    aiExplanation: generateAiRiskExplanation(signals),
    tracePath: context.tracePath,
    connectedEntitiesCount: context.tracePath.length,
    transactionsInTrace: context.tracePath.length,
    totalFlow: formatINR(result.amount),
    traceDepth: context.tracePath.length,
    scenarioName: result.detectedPatterns[0] ?? 'Flagged Anomaly',
    detectionSteps: [
      { time: result.timestamp, action: 'TRANSACTION RECEIVED', completed: true },
      { time: result.timestamp, action: 'TRANSACTION ANALYZED', completed: true },
      { time: result.timestamp, action: `RISK SCORE CALCULATED (${result.riskScore}/100)`, completed: true },
      { time: result.timestamp, action: 'SUSPICIOUS PATTERN DETECTED', completed: true },
      { time: result.timestamp, action: `${result.transactionId} FLAGGED`, completed: true },
      { time: result.timestamp, action: 'TRACE GENERATED', completed: true },
      { time: result.timestamp, action: 'INVESTIGATION REPORT AVAILABLE', completed: true },
    ],
  };
}
