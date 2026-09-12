/**
 * TraceX — Analysis Worker (runs on a worker thread)
 * ==================================================
 * Executes CPU-heavy forensic analysis away from the server event loop:
 *   - analyzeAllAccounts     → mule detection over a subset of accounts
 *   - analyzeTransactionBatch → full pipeline scoring for a batch of edges
 *   - graphIntelligence      → clusters, fan analysis, cycles, risk propagation
 *
 * The heavy engine modules are imported statically — Node loads them once per
 * worker and reuses them across messages, so per-task cost is just the compute.
 *
 * @license Apache-2.0
 */

import { parentPort, workerData } from 'node:worker_threads';

import {
  AnalysisRequest,
  AnalysisResponse,
  WorkerPayload,
} from './parallel';
import { analyzeAllAccounts, analyzeTransactionForMule } from '../src/engines/muleDetection';
import { processBatch } from '../src/engines/transactionPipeline';
import {
  detectSuspiciousClusters,
  analyzeFanPatterns,
  detectCircularFlows,
  propagateRisks,
  findSuspiciousPaths,
  calculateNetworkMetrics,
} from '../src/engines/graphIntelligence';

if (!parentPort) {
  throw new Error('analysisWorker must be started as a worker thread');
}

const port = parentPort;

async function handle(request: AnalysisRequest): Promise<WorkerPayload> {
  switch (request.type) {
    case 'analyzeAllAccounts': {
      const results = analyzeAllAccounts(request.edges, request.nodes);
      return { kind: 'muleResults', results };
    }

    case 'analyzeTransactionBatch': {
      const batch = request.batch ?? [];
      const results = processBatch(batch, request.edges, request.nodes);
      return { kind: 'pipelineResults', results };
    }

    case 'graphIntelligence': {
      const clusters = detectSuspiciousClusters(request.nodes, request.edges);
      const { fanIn, fanOut } = analyzeFanPatterns(request.nodes, request.edges);
      const circularFlows = detectCircularFlows(request.nodes, request.edges);
      const riskPropagatedNodes = propagateRisks(request.nodes, request.edges);
      const suspiciousPaths = findSuspiciousPaths(request.nodes, request.edges);
      const networkMetrics = calculateNetworkMetrics(request.nodes, request.edges);
      return {
        kind: 'graphAnalysis',
        payload: {
          clusters,
          fanInAnalysis: fanIn,
          fanOutAnalysis: fanOut,
          circularFlows,
          riskPropagatedNodes,
          suspiciousPaths,
          networkMetrics,
        },
      };
    }

    default:
      throw new Error(`Unknown analysis task type: ${(request as { type: string }).type}`);
  }
}

port.on('message', (request: AnalysisRequest) => {
  handle(request)
    .then((payload) => {
      const response: AnalysisResponse = { id: request.id, ok: true, type: request.type, payload };
      port.postMessage(response);
    })
    .catch((err: Error) => {
      const response: AnalysisResponse = { id: request.id, ok: false, error: err.message };
      port.postMessage(response);
    });
});

// Worker-thread smoke check when launched directly.
if (workerData && (workerData as { selfTest?: boolean }).selfTest) {
  void handle({
    id: 0,
    type: 'analyzeAllAccounts',
    nodes: [],
    edges: [],
  }).then(() => process.exit(0));
}
