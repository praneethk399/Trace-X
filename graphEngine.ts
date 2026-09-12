import { EntityNode, TransactionEdge, PathAnalysisResult, FilterState, RiskLevel, TransactionType, StreamEvent } from '../types/forensics';
import { formatINR } from '../data/mockForensics';

// BFS / Shortest path with edge weights for forensic fund tracing
export function calculateTracePath(
  sourceId: string,
  destinationId: string,
  nodes: EntityNode[],
  edges: TransactionEdge[]
): PathAnalysisResult | null {
  if (sourceId === destinationId) return null;

  const nodeMap = new Map<string, EntityNode>(nodes.map(n => [n.id, n]));
  const sourceNode = nodeMap.get(sourceId);
  const destNode = nodeMap.get(destinationId);
  if (!sourceNode || !destNode) return null;

  // Build adjacency list (directed)
  const adj = new Map<string, { targetId: string; edge: TransactionEdge }[]>();
  for (const edge of edges) {
    if (!adj.has(edge.source)) adj.set(edge.source, []);
    adj.get(edge.source)!.push({ targetId: edge.target, edge });
  }

  // BFS search
  interface QueueItem {
    currentId: string;
    path: string[];
    edgesUsed: TransactionEdge[];
  }

  const queue: QueueItem[] = [{ currentId: sourceId, path: [sourceId], edgesUsed: [] }];
  const visited = new Set<string>([sourceId]);

  let foundPath: QueueItem | null = null;

  while (queue.length > 0) {
    const item = queue.shift()!;
    if (item.currentId === destinationId) {
      foundPath = item;
      break;
    }

    const neighbors = adj.get(item.currentId) || [];
    for (const { targetId, edge } of neighbors) {
      if (!visited.has(targetId)) {
        visited.add(targetId);
        queue.push({
          currentId: targetId,
          path: [...item.path, targetId],
          edgesUsed: [...item.edgesUsed, edge]
        });
      }
    }
  }

  // If no direct directed path found, attempt bidirectional path discovery for money laundering rings
  if (!foundPath) {
    const undirectedAdj = new Map<string, { neighborId: string; edge: TransactionEdge }[]>();
    for (const edge of edges) {
      if (!undirectedAdj.has(edge.source)) undirectedAdj.set(edge.source, []);
      if (!undirectedAdj.has(edge.target)) undirectedAdj.set(edge.target, []);
      undirectedAdj.get(edge.source)!.push({ neighborId: edge.target, edge });
      undirectedAdj.get(edge.target)!.push({ neighborId: edge.source, edge });
    }

    const uQueue: QueueItem[] = [{ currentId: sourceId, path: [sourceId], edgesUsed: [] }];
    const uVisited = new Set<string>([sourceId]);

    while (uQueue.length > 0) {
      const item = uQueue.shift()!;
      if (item.currentId === destinationId) {
        foundPath = item;
        break;
      }
      const neighbors = undirectedAdj.get(item.currentId) || [];
      for (const { neighborId, edge } of neighbors) {
        if (!uVisited.has(neighborId)) {
          uVisited.add(neighborId);
          uQueue.push({
            currentId: neighborId,
            path: [...item.path, neighborId],
            edgesUsed: [...item.edgesUsed, edge]
          });
        }
      }
    }
  }

  if (!foundPath) return null;

  const pathNodes = foundPath.path.map(id => nodeMap.get(id)!).filter(Boolean);
  const totalValue = foundPath.edgesUsed.reduce((acc, e) => acc + e.amount, 0);
  const intermediariesCount = Math.max(0, pathNodes.length - 2);

  // Compute composite risk score along the path
  const avgNodeRisk = pathNodes.reduce((acc, n) => acc + n.riskScore, 0) / pathNodes.length;
  const criticalEdges = foundPath.edgesUsed.filter(e => e.risk === 'CRITICAL').length;
  const riskScore = Math.min(100, Math.round(avgNodeRisk * 0.7 + (criticalEdges / Math.max(1, foundPath.edgesUsed.length)) * 30));

  const steps = foundPath.edgesUsed.map((edge, idx) => {
    const from = nodeMap.get(edge.source) || pathNodes[idx];
    const to = nodeMap.get(edge.target) || pathNodes[idx + 1];
    return {
      fromNode: from,
      toNode: to,
      edge,
      amount: edge.amount,
    };
  });

  return {
    sourceId,
    destinationId,
    nodes: pathNodes,
    edges: foundPath.edgesUsed,
    pathLength: pathNodes.length,
    totalValue,
    intermediariesCount,
    riskScore,
    steps,
  };
}

// Calculate degree centrality and network metrics for nodes
export function calculateNetworkMetrics(nodes: EntityNode[], edges: TransactionEdge[]) {
  const degreeMap = new Map<string, { inDegree: number; outDegree: number; totalVolume: number }>();
  
  for (const node of nodes) {
    degreeMap.set(node.id, { inDegree: 0, outDegree: 0, totalVolume: 0 });
  }

  for (const edge of edges) {
    const src = degreeMap.get(edge.source);
    if (src) {
      src.outDegree += 1;
      src.totalVolume += edge.amount;
    }
    const tgt = degreeMap.get(edge.target);
    if (tgt) {
      tgt.inDegree += 1;
      tgt.totalVolume += edge.amount;
    }
  }

  return degreeMap;
}

// Filter nodes and edges according to filter state
export function applyFilters(
  nodes: EntityNode[],
  edges: TransactionEdge[],
  filters: FilterState
): { filteredNodes: EntityNode[]; filteredEdges: TransactionEdge[] } {
  const query = filters.searchQuery.trim().toLowerCase();

  const filteredNodes = nodes.filter(node => {
    // Risk filter
    if (filters.risk !== 'ALL' && node.risk !== filters.risk) {
      return false;
    }
    // Entity Type filter
    if (filters.entityType !== 'ALL' && node.type !== filters.entityType) {
      return false;
    }
    // Only Flagged
    if (filters.onlyFlagged && node.status !== 'FLAGGED' && node.status !== 'REVIEW_REQUIRED' && node.status !== 'UNDER_SURVEILLANCE') {
      return false;
    }
    // Search query
    if (query) {
      const matchesId = node.id.toLowerCase().includes(query);
      const matchesLabel = node.label.toLowerCase().includes(query);
      const matchesHolder = node.accountHolder?.toLowerCase().includes(query) ?? false;
      const matchesBank = node.bankName?.toLowerCase().includes(query) ?? false;
      const matchesTag = node.tags.some(t => t.toLowerCase().includes(query));
      const matchesCluster = node.clusterName.toLowerCase().includes(query);
      if (!matchesId && !matchesLabel && !matchesHolder && !matchesBank && !matchesTag && !matchesCluster) {
        return false;
      }
    }
    return true;
  });

  const validNodeIds = new Set(filteredNodes.map(n => n.id));

  const filteredEdges = edges.filter(edge => {
    // Must connect valid nodes
    if (!validNodeIds.has(edge.source) || !validNodeIds.has(edge.target)) {
      return false;
    }
    // Transaction type filter
    if (filters.txType !== 'ALL' && edge.type !== filters.txType) {
      return false;
    }
    // Search query on edge
    if (query) {
      const matchesHash = edge.hash.toLowerCase().includes(query);
      const matchesAmount = edge.formattedAmount.toLowerCase().includes(query);
      const matchesSource = edge.source.toLowerCase().includes(query);
      const matchesTarget = edge.target.toLowerCase().includes(query);
      // If nodes matched query, edge can remain, or if edge fields match
      if (!matchesHash && !matchesAmount && !matchesSource && !matchesTarget) {
        // still ok if both endpoints are in validNodeIds
      }
    }
    return true;
  });

  return { filteredNodes, filteredEdges };
}

// Generate next simulated live transaction for DEMO MODE
export function generateSimulatedTransaction(
  nodes: EntityNode[],
  sequence: number
): { edge: TransactionEdge; streamEntry: StreamEvent } {
  // Pick active mule or intermediary nodes
  const activeNodes = nodes.filter(n => n.risk === 'CRITICAL' || n.risk === 'HIGH' || n.type === 'MULE' || n.type === 'INTERMEDIARY');
  const sourceNode = activeNodes[Math.floor(Math.random() * activeNodes.length)] || nodes[0];
  
  // Pick target node
  const otherNodes = nodes.filter(n => n.id !== sourceNode.id);
  const targetNode = otherNodes[Math.floor(Math.random() * otherNodes.length)] || nodes[1];

  const types: TransactionType[] = ['IMPS', 'UPI', 'NEFT', 'RTGS', 'CARD'];
  const type = types[Math.floor(Math.random() * types.length)];
  
  // Random amount between 4,500 and 1,800,000
  const isHighValue = Math.random() > 0.6;
  const amount = isHighValue 
    ? Math.round(150000 + Math.random() * 2500000) 
    : Math.round(3500 + Math.random() * 45000);

  const now = new Date();
  const timeStr = `${now.toTimeString().split(' ')[0]}.${String(now.getMilliseconds()).padStart(3, '0').slice(0, 2)}`;
  const formattedAmt = formatINR(amount);
  const risk: RiskLevel = amount > 1000000 ? 'CRITICAL' : amount > 250000 ? 'HIGH' : 'MEDIUM';

  const edge: TransactionEdge = {
    id: `TX-LIVE-${sequence}`,
    source: sourceNode.id,
    target: targetNode.id,
    type,
    amount,
    formattedAmount: formattedAmt,
    timestamp: timeStr,
    risk,
    flowStatus: 'IN_TRANSIT',
    hash: `0x${Math.random().toString(16).substring(2, 10)}${Math.random().toString(16).substring(2, 10)}`,
    suspiciousPattern: 'High-frequency live transfer stream detected by engine'
  };

  const streamEntry: StreamEvent = {
    id: edge.id,
    time: timeStr,
    source: sourceNode.id,
    target: targetNode.id,
    sourceLabel: sourceNode.label,
    targetLabel: targetNode.label,
    type,
    amount: formattedAmt,
    numericAmount: amount,
    risk,
    riskScore: risk === 'CRITICAL' ? 85 : risk === 'HIGH' ? 68 : 45,
    status: 'SUSPICIOUS',
    hash: edge.hash,
    isNew: true,
  };

  return { edge, streamEntry };
}
