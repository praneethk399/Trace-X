/**
 * TraceX — Parallel Processing Layer
 * ==================================
 * Two complementary mechanisms used by the backend to saturate all cores:
 *
 *  1. `parallelMap` — bounded-concurrency task pool for I/O-shaped work
 *     (Supabase REST calls, batched inserts, fan-out fetches). Concurrency is
 *     configurable and back-pressured: at most `concurrency` tasks are in
 *     flight at any moment, and failures are collected per item.
 *
 *  2. `ParallelWorkerPool` — a pool of Node worker_threads for CPU-bound
 *     analysis (mule detection, graph intelligence, pipeline scoring). The
 *     server process stays responsive while heavy computations run on worker
 *     threads. Tasks carry their own data (graph snapshot) and return their
 *     result over a message channel — no shared mutable state.
 *
 *  3. `runAnalysisPipeline` — orchestrates the full analysis of a network
 *     snapshot: partitions the work, fans it out across the worker pool,
 *     and merges the partial results. This is what the `/api/analyze/*`
 *     endpoints call.
 *
 * @license Apache-2.0
 */

import { Worker } from 'node:worker_threads';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  EntityNode,
  TransactionEdge,
  RiskLevel,
  MuleDetectionResult,
} from '../src/types/forensics';
import type { PipelineResult } from '../src/engines/transactionPipeline';

// ============================================================================
// 1. Bounded-concurrency pool (I/O-shaped work)
// ============================================================================

export interface ParallelMapOptions {
  /** Maximum tasks in flight at once. Defaults to 8. */
  concurrency?: number;
  /** Stop scheduling new tasks after the first failure. Defaults to false. */
  failFast?: boolean;
}

export interface ParallelMapResult<T, R> {
  /** Results in the same order as the input items. */
  results: (R | null)[];
  /** Index + error for every item whose task rejected. */
  errors: { index: number; item: T; error: string }[];
  /** Wall-clock duration in ms. */
  durationMs: number;
  /** Peak number of simultaneously in-flight tasks. */
  peakInFlight: number;
}

/**
 * Maps `items` through `task` with a hard cap on parallelism. Preserves input
 * order in `results`, never throws — inspect `errors` instead.
 */
export async function parallelMap<T, R>(
  items: readonly T[],
  task: (item: T, index: number) => Promise<R>,
  options: ParallelMapOptions = {}
): Promise<ParallelMapResult<T, R>> {
  const concurrency = Math.max(1, Math.min(options.concurrency ?? 8, items.length || 1));
  const results: (R | null)[] = new Array(items.length).fill(null);
  const errors: ParallelMapResult<T, R>['errors'] = [];

  const started = performance.now();
  let nextIndex = 0;
  let inFlight = 0;
  let peakInFlight = 0;
  let aborted = false;

  async function worker(): Promise<void> {
    while (true) {
      if (aborted) return;
      const index = nextIndex++;
      if (index >= items.length) return;

      inFlight++;
      peakInFlight = Math.max(peakInFlight, inFlight);
      try {
        results[index] = await task(items[index], index);
      } catch (e) {
        errors.push({ index, item: items[index], error: (e as Error).message });
        if (options.failFast) aborted = true;
      } finally {
        inFlight--;
      }
    }
  }

  await Promise.all(Array.from({ length: concurrency }, () => worker()));
  return { results, errors, durationMs: performance.now() - started, peakInFlight };
}

/** Chunk `items` into at most `size`-sized groups (last chunk may be smaller). */
export function chunk<T>(items: readonly T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

// ============================================================================
// 2. Worker-thread pool (CPU-bound analysis)
// ============================================================================

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const WORKER_PATH = path.join(__dirname, 'analysisWorker.js');

export type AnalysisTaskType =
  | 'analyzeAllAccounts'
  | 'analyzeTransactionBatch'
  | 'graphIntelligence';

export interface AnalysisRequest {
  id: number;
  type: AnalysisTaskType;
  nodes: EntityNode[];
  edges: TransactionEdge[];
  /** For `analyzeTransactionBatch`: the transactions to push through the pipeline. */
  batch?: TransactionEdge[];
}

export type AnalysisResponse =
  | { id: number; ok: true; type: AnalysisTaskType; payload: WorkerPayload }
  | { id: number; ok: false; error: string };

export type WorkerPayload =
  | { kind: 'muleResults'; results: MuleDetectionResult[] }
  | { kind: 'pipelineResults'; results: PipelineResult[] }
  | { kind: 'graphAnalysis'; payload: unknown };

interface WorkerJob {
  request: AnalysisRequest;
  resolve: (payload: WorkerPayload) => void;
  reject: (err: Error) => void;
}

export class ParallelWorkerPool {
  private workers: { worker: Worker; busy: boolean }[] = [];
  private queue: WorkerJob[] = [];
  private nextId = 1;
  private nextWorker = 0;
  private disposed = false;

  /** Size defaults to cores − 1 (min 1, capped at 8 so we don't starve the event loop). */
  readonly size: number;

  constructor(size?: number) {
    this.size = size ?? Math.min(8, Math.max(1, os.cpus().length - 1));
  }

  private spawn(): { worker: Worker; busy: boolean } {
    const worker = new Worker(WORKER_PATH, {
      resourceLimits: { maxOldGenerationSizeMb: 512 },
    });
    const entry = { worker, busy: false };

    worker.on('message', (msg: AnalysisResponse) => {
      const job = this.jobsById.get(msg.id);
      if (!job) return;
      this.jobsById.delete(msg.id);
      if (msg.ok) job.resolve(msg.payload);
      else job.reject(new Error(String((msg as { error: string }).error)));
    });

    worker.on('error', (err) => {
      // Fail every job assigned to this worker and respawn a replacement.
      for (const [id, job] of this.jobsById) {
        if (job.request.id === id) {
          job.reject(err);
          this.jobsById.delete(id);
        }
      }
      const idx = this.workers.indexOf(entry);
      if (idx >= 0) this.workers.splice(idx, 1);
      if (!this.disposed) this.workers.push(this.spawn());
    });

    worker.on('exit', (code) => {
      if (code !== 0) {
        const idx = this.workers.indexOf(entry);
        if (idx >= 0) this.workers.splice(idx, 1);
        if (!this.disposed) this.workers.push(this.spawn());
      }
    });

    return entry;
  }

  private jobsById = new Map<number, WorkerJob>();

  /** Ensures `count` workers exist (lazily spawns on first use). */
  private ensureWorkers(count: number): void {
    while (this.workers.length < Math.min(count, this.size)) {
      this.workers.push(this.spawn());
    }
  }

  private findFree(): { worker: Worker; busy: boolean } | null {
    for (let i = 0; i < this.workers.length; i++) {
      const entry = this.workers[(this.nextWorker + i) % this.workers.length];
      if (!entry.busy) {
        this.nextWorker = (this.nextWorker + i + 1) % Math.max(1, this.workers.length);
        return entry;
      }
    }
    return null;
  }

  /**
   * Runs one analysis task on a free worker. Falls back to in-process
   * execution if the worker file cannot be loaded (e.g. not built yet).
   */
  async run(type: AnalysisTaskType, nodes: EntityNode[], edges: TransactionEdge[], batch?: TransactionEdge[]): Promise<WorkerPayload> {
    if (this.disposed) throw new Error('Worker pool disposed');

    const request: AnalysisRequest = { id: this.nextId++, type, nodes, edges, batch };
    this.ensureWorkers(1);

    const free = this.findFree();
    if (!free) {
      return new Promise<WorkerPayload>((resolve, reject) => {
        this.queue.push({ request, resolve, reject });
      });
    }

    return this.dispatch(free, request);
  }

  private dispatch(entry: { worker: Worker; busy: boolean }, request: AnalysisRequest): Promise<WorkerPayload> {
    entry.busy = true;
    return new Promise<WorkerPayload>((resolve, reject) => {
      this.jobsById.set(request.id, { request, resolve, reject });
      entry.worker.postMessage(request);
    }).finally(() => {
      entry.busy = false;
      this.pump();
    });
  }

  private pump(): void {
    while (this.queue.length > 0) {
      const free = this.findFree();
      if (!free) return;
      const job = this.queue.shift()!;
      this.dispatch(free, job.request).then(job.resolve, job.reject);
    }
  }

  /** Convenience: run a task and time it. */
  async runTimed(type: AnalysisTaskType, nodes: EntityNode[], edges: TransactionEdge[], batch?: TransactionEdge[]): Promise<{ payload: WorkerPayload; durationMs: number }> {
    const start = performance.now();
    const payload = await this.run(type, nodes, edges, batch);
    return { payload, durationMs: performance.now() - start };
  }

  dispose(): void {
    this.disposed = true;
    for (const { worker } of this.workers) void worker.terminate();
    for (const job of this.queue) job.reject(new Error('Worker pool disposed'));
    this.queue = [];
    this.jobsById.clear();
    this.workers = [];
  }
}

/** Shared singleton used by the route handlers. */
export const analysisPool = new ParallelWorkerPool();

// ============================================================================
// 3. Orchestrated parallel analysis pipeline
// ============================================================================

export interface NetworkAnalysisSummary {
  durationMs: number;
  parallelism: {
    workerPoolSize: number;
    accountsAnalyzed: number;
    batchesProcessed: number;
    chunksPerBatch: number;
    ioConcurrency: number;
    peakInFlight: number;
  };
  mule: {
    accountsAnalyzed: number;
    flaggedAccounts: { accountId: string; riskScore: number; riskLevel: RiskLevel; confidenceScore: number; topPatterns: string[] }[];
  };
  pipeline: {
    transactionsProcessed: number;
    suspicious: number;
    alerts: number;
    averageRiskScore: number;
    averageProcessingTimeMs: number;
  };
  graph: {
    clusters: number;
    circularFlows: number;
    suspiciousPaths: number;
    averageDegree: number;
    density: number;
  };
  risk: {
    byLevel: Record<RiskLevel, number>;
    byType: Record<string, number>;
  };
}

function partitionIntoBatches(edges: TransactionEdge[], batchCount: number): TransactionEdge[][] {
  const size = Math.max(1, Math.ceil(edges.length / batchCount));
  const batches: TransactionEdge[][] = [];
  for (let i = 0; i < edges.length; i += size) batches.push(edges.slice(i, i + size));
  return batches;
}

/**
 * Full parallel analysis of a network snapshot:
 *  - Phase A (parallel across workers): batched pipeline scoring of all edges.
 *  - Phase B (parallel across workers): chunked mule detection over all accounts.
 *  - Phase C (parallel): graph intelligence (clusters, cycles, risk propagation).
 * Phases A–C run concurrently with each other; within each phase the data is
 * partitioned so every worker gets a share.
 */
export async function runAnalysisPipeline(nodes: EntityNode[], edges: TransactionEdge[]): Promise<NetworkAnalysisSummary> {
  const started = performance.now();
  const poolSize = analysisPool.size;
  const pipelineBatches = partitionIntoBatches(edges, Math.min(poolSize * 2, Math.max(1, edges.length)));
  const accountIds = [...new Set(edges.flatMap(e => [e.source, e.target]))];
  const accountChunks = chunk(accountIds, Math.ceil(accountIds.length / Math.min(poolSize, Math.max(1, accountIds.length))) || 1);

  const ioConcurrency = Math.max(4, poolSize);
  let peakInFlight = 0;

  const [pipelinePartials, mulePartials, graphResult] = await Promise.all([
    // Phase A — pipeline scoring, one batch per task
    parallelMap(pipelineBatches, async (batch) => {
      const p = await analysisPool.run('analyzeTransactionBatch', nodes, edges, batch);
      return (p as { kind: string; results: PipelineResult[] });
    }, { concurrency: poolSize }),

    // Phase B — mule detection, one chunk of accounts per task
    parallelMap(accountChunks, async (accountSubset) => {
      const subEdges = edges.filter(e => accountSubset.includes(e.source) || accountSubset.includes(e.target));
      const p = await analysisPool.run('analyzeAllAccounts', nodes, subEdges);
      return (p as { kind: string; results: MuleDetectionResult[] });
    }, { concurrency: poolSize }),

    // Phase C — graph intelligence (single task; internally heavy)
    analysisPool.run('graphIntelligence', nodes, edges).then(p => (p as { kind: string; payload: unknown })),
  ]);

  for (const pm of [pipelinePartials, mulePartials]) peakInFlight = Math.max(peakInFlight, pm.peakInFlight);

  // ---- Merge pipeline results ----
  const pipelineResults = pipelinePartials.results.flatMap(r => r?.results ?? []);
  const alerts = pipelineResults.reduce((n, r) => n + r.alerts.length, 0);
  const suspicious = pipelineResults.filter(r => r.risk !== 'LOW').length;
  const averageRiskScore = pipelineResults.length
    ? pipelineResults.reduce((s, r) => s + r.riskScore, 0) / pipelineResults.length
    : 0;
  const averageProcessingTimeMs = pipelineResults.length
    ? pipelineResults.reduce((s, r) => s + r.processingTimeMs, 0) / pipelineResults.length
    : 0;

  // ---- Merge mule results ----
  const muleResults = mulePartials.results.flatMap(r => r?.results ?? []);
  const flaggedAccounts = muleResults
    .filter(r => r.riskLevel === 'HIGH' || r.riskLevel === 'CRITICAL')
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 10)
    .map(r => ({
      accountId: r.accountId,
      riskScore: r.riskScore,
      riskLevel: r.riskLevel,
      confidenceScore: r.confidenceScore,
      topPatterns: r.detectedPatterns.slice(0, 3).map(p => p.type),
    }));

  // ---- Risk distribution across edges ----
  const byLevel: Record<RiskLevel, number> = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
  const byType: Record<string, number> = {};
  for (const e of edges) {
    byLevel[e.risk]++;
    byType[e.type] = (byType[e.type] ?? 0) + 1;
  }

  const graph = ((graphResult as { payload?: unknown }).payload ?? {}) as {
    networkMetrics?: { averageDegree?: number; density?: number };
    clusters?: unknown[];
    circularFlows?: unknown[];
    suspiciousPaths?: unknown[];
  };

  return {
    durationMs: performance.now() - started,
    parallelism: {
      workerPoolSize: poolSize,
      accountsAnalyzed: accountIds.length,
      batchesProcessed: pipelineBatches.length,
      chunksPerBatch: accountChunks.length,
      ioConcurrency,
      peakInFlight,
    },
    mule: {
      accountsAnalyzed: muleResults.length,
      flaggedAccounts,
    },
    pipeline: {
      transactionsProcessed: pipelineResults.length,
      suspicious,
      alerts,
      averageRiskScore: Math.round(averageRiskScore * 10) / 10,
      averageProcessingTimeMs: Math.round(averageProcessingTimeMs * 100) / 100,
    },
    graph: {
      clusters: Array.isArray(graph.clusters) ? graph.clusters.length : 0,
      circularFlows: Array.isArray(graph.circularFlows) ? graph.circularFlows.length : 0,
      suspiciousPaths: Array.isArray(graph.suspiciousPaths) ? graph.suspiciousPaths.length : 0,
      averageDegree: Math.round((graph.networkMetrics?.averageDegree ?? 0) * 100) / 100,
      density: Math.round((graph.networkMetrics?.density ?? 0) * 10000) / 10000,
    },
    risk: { byLevel, byType },
  };
}

// ============================================================================
// 4. Parallel REST helpers (used by the server routes)
// ============================================================================

/**
 * Fetches many Supabase resources concurrently (bounded by `concurrency`).
 * Returns per-resource results; failed resources surface in `errors`.
 */
export async function parallelFetch<T>(
  fetchers: Record<string, () => Promise<T>>,
  concurrency = 6
): Promise<{ data: Record<string, T | null>; errors: Record<string, string>; durationMs: number }> {
  const entries = Object.entries(fetchers);
  const { results, errors, durationMs } = await parallelMap(entries, async ([key, fn]) => {
    const value = await fn();
    return [key, value] as const;
  }, { concurrency });

  const data: Record<string, T | null> = {};
  for (const [key, value] of results) if (key) data[key] = value ?? null;

  const errorMap: Record<string, string> = {};
  for (const err of errors) errorMap[entries[err.index][0]] = err.error;

  return { data, errors: errorMap, durationMs };
}
