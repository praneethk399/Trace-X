/**
 * TraceX — Graph Intelligence Engine
 * Advanced graph analysis for mule-account detection:
 * - Suspicious cluster detection
 * - Fan-in/fan-out analysis
 * - Circular flow detection
 * - Risk propagation
 * - Connected account discovery
 * 
 * @license Apache-2.0
 */

import {
  EntityNode,
  TransactionEdge,
  RiskLevel,
  PathAnalysisResult
} from '../types/forensics';

// ============================================================================
// TYPES
// ============================================================================

export interface GraphAnalysisResult {
  clusters: SuspiciousCluster[];
  fanInAnalysis: FanAnalysis[];
  fanOutAnalysis: FanAnalysis[];
  circularFlows: CircularFlow[];
  riskPropagatedNodes: RiskPropagatedNode[];
  suspiciousPaths: SuspiciousPath[];
  networkMetrics: NetworkMetrics;
}

export interface SuspiciousCluster {
  id: string;
  name: string;
  nodes: string[];
  riskScore: number;
  internalVolume: number;
  externalConnections: number;
  pattern: 'FAN_IN' | 'FAN_OUT' | 'CIRCULAR' | 'LAYERING' | 'MIXED';
  confidence: number;
}

export interface FanAnalysis {
  hubNodeId: string;
  hubNodeLabel: string;
  connectedNodes: string[];
  type: 'FAN_IN' | 'FAN_OUT';
  degree: number;
  totalVolume: number;
  riskScore: number;
  confidence: number;
}

export interface CircularFlow {
  nodes: string[];
  edges: string[];
  totalAmount: number;
  riskScore: number;
  hopCount: number;
}

export interface RiskPropagatedNode {
  nodeId: string;
  originalRisk: number;
  propagatedRisk: number;
  riskIncrease: number;
  propagationSource: string[];
  propagationPaths: number;
}

export interface SuspiciousPath {
  path: string[];
  totalAmount: number;
  riskScore: number;
  hopCount: number;
  pattern: string;
}

export interface NetworkMetrics {
  totalNodes: number;
  totalEdges: number;
  averageDegree: number;
  density: number;
  clusteringCoefficient: number;
  averagePathLength: number;
}

// ============================================================================
// CLUSTER DETECTION
// ============================================================================

export function detectSuspiciousClusters(
  nodes: EntityNode[],
  edges: TransactionEdge[]
): SuspiciousCluster[] {
  const clusters: SuspiciousCluster[] = [];
  const visited = new Set<string>();
  
  // Build adjacency map
  const adjacency = buildAdjacencyMap(edges);
  
  // Find connected components using DFS
  nodes.forEach(node => {
    if (!visited.has(node.id)) {
      const cluster = findConnectedComponent(node.id, adjacency, nodes, edges, visited);
      if (cluster && cluster.nodes.length >= 3) {
        clusters.push(cluster);
      }
    }
  });
  
  // Analyze each cluster for suspicious patterns
  return clusters.map(c => analyzeClusterSuspicion(c, edges, nodes));
}

function buildAdjacencyMap(edges: TransactionEdge[]): Map<string, string[]> {
  const adj = new Map<string, string[]>();
  
  edges.forEach(edge => {
    if (!adj.has(edge.source)) adj.set(edge.source, []);
    if (!adj.has(edge.target)) adj.set(edge.target, []);
    adj.get(edge.source)!.push(edge.target);
    adj.get(edge.target)!.push(edge.source);
  });
  
  return adj;
}

function findConnectedComponent(
  startId: string,
  adjacency: Map<string, string[]>,
  nodes: EntityNode[],
  edges: TransactionEdge[],
  visited: Set<string>
): SuspiciousCluster | null {
  const component: string[] = [];
  const stack = [startId];
  
  while (stack.length > 0) {
    const nodeId = stack.pop()!;
    if (visited.has(nodeId)) continue;
    
    visited.add(nodeId);
    component.push(nodeId);
    
    const neighbors = adjacency.get(nodeId) || [];
    neighbors.forEach(neighbor => {
      if (!visited.has(neighbor)) {
        stack.push(neighbor);
      }
    });
  }
  
  if (component.length < 3) return null;
  
  // Calculate cluster metrics
  const internalEdges = edges.filter(e => 
    component.includes(e.source) && component.includes(e.target)
  );
  const externalEdges = edges.filter(e => 
    (component.includes(e.source) && !component.includes(e.target)) ||
    (!component.includes(e.source) && component.includes(e.target))
  );
  
  const internalVolume = internalEdges.reduce((sum, e) => sum + e.amount, 0);
  const externalConnections = new Set([
    ...externalEdges.map(e => component.includes(e.source) ? e.target : e.source)
  ]).size;
  
  return {
    id: `CLUSTER-${component[0]}`,
    name: `Cluster ${component[0]}`,
    nodes: component,
    riskScore: 0,
    internalVolume,
    externalConnections,
    pattern: 'MIXED',
    confidence: 0
  };
}

function analyzeClusterSuspicion(
  cluster: SuspiciousCluster,
  edges: TransactionEdge[],
  nodes: EntityNode[]
): SuspiciousCluster {
  const internalEdges = edges.filter(e => 
    cluster.nodes.includes(e.source) && cluster.nodes.includes(e.target)
  );
  
  // Analyze flow patterns
  const fanInNodes = new Set<string>();
  const fanOutNodes = new Set<string>();
  const circularNodes = new Set<string>();
  
  cluster.nodes.forEach(nodeId => {
    const incoming = internalEdges.filter(e => e.target === nodeId);
    const outgoing = internalEdges.filter(e => e.source === nodeId);
    
    if (incoming.length >= 3) fanInNodes.add(nodeId);
    if (outgoing.length >= 3) fanOutNodes.add(nodeId);
  });
  
  // Detect circular flows within cluster
  const hasCircular = detectCircularWithinCluster(cluster.nodes, internalEdges);
  
  // Determine dominant pattern
  let pattern: SuspiciousCluster['pattern'] = 'MIXED';
  if (fanInNodes.size > fanOutNodes.size && !hasCircular) pattern = 'FAN_IN';
  else if (fanOutNodes.size > fanInNodes.size && !hasCircular) pattern = 'FAN_OUT';
  else if (hasCircular) pattern = 'CIRCULAR';
  else if (internalEdges.length > cluster.nodes.length * 1.5) pattern = 'LAYERING';
  
  // Calculate risk score
  const nodeRiskScores = cluster.nodes.map(id => {
    const node = nodes.find(n => n.id === id);
    return node?.riskScore || 0;
  });
  
  const avgNodeRisk = nodeRiskScores.reduce((a, b) => a + b, 0) / nodeRiskScores.length;
  const maxNodeRisk = Math.max(...nodeRiskScores);
  
  const riskScore = Math.min(100, Math.round(
    avgNodeRisk * 0.4 +
    maxNodeRisk * 0.3 +
    (cluster.externalConnections * 5) +
    (internalEdges.length * 2)
  ));
  
  const confidence = Math.min(90, 50 + (cluster.nodes.length * 3) + (internalEdges.length * 2));
  
  return {
    ...cluster,
    riskScore,
    pattern,
    confidence
  };
}

function detectCircularWithinCluster(nodes: string[], edges: TransactionEdge[]): boolean {
  // DFS to detect cycles
  const adjacency = new Map<string, string[]>();
  edges.forEach(e => {
    if (!adjacency.has(e.source)) adjacency.set(e.source, []);
    adjacency.get(e.source)!.push(e.target);
  });
  
  const visited = new Set<string>();
  const recursionStack = new Set<string>();
  
  const hasCycle = (node: string): boolean => {
    visited.add(node);
    recursionStack.add(node);
    
    const neighbors = adjacency.get(node) || [];
    for (const neighbor of neighbors) {
      if (nodes.includes(neighbor)) {
        if (!visited.has(neighbor)) {
          if (hasCycle(neighbor)) return true;
        } else if (recursionStack.has(neighbor)) {
          return true;
        }
      }
    }
    
    recursionStack.delete(node);
    return false;
  };
  
  for (const node of nodes) {
    if (!visited.has(node)) {
      if (hasCycle(node)) return true;
    }
  }
  
  return false;
}

// ============================================================================
// FAN-IN / FAN-OUT ANALYSIS
// ============================================================================

export function analyzeFanPatterns(
  nodes: EntityNode[],
  edges: TransactionEdge[]
): { fanIn: FanAnalysis[]; fanOut: FanAnalysis[] } {
  const fanIn: FanAnalysis[] = [];
  const fanOut: FanAnalysis[] = [];
  
  nodes.forEach(node => {
    // Fan-in: multiple accounts sending to this node
    const incomingEdges = edges.filter(e => e.target === node.id);
    const uniqueSenders = [...new Set(incomingEdges.map(e => e.source))];
    
    if (uniqueSenders.length >= 3) {
      const totalVolume = incomingEdges.reduce((sum, e) => sum + e.amount, 0);
      const confidence = Math.min(90, 50 + uniqueSenders.length * 5);
      
      fanIn.push({
        hubNodeId: node.id,
        hubNodeLabel: node.label,
        connectedNodes: uniqueSenders,
        type: 'FAN_IN',
        degree: uniqueSenders.length,
        totalVolume,
        riskScore: Math.min(100, node.riskScore + uniqueSenders.length * 5),
        confidence
      });
    }
    
    // Fan-out: this node sending to multiple accounts
    const outgoingEdges = edges.filter(e => e.source === node.id);
    const uniqueRecipients = [...new Set(outgoingEdges.map(e => e.target))];
    
    if (uniqueRecipients.length >= 3) {
      const totalVolume = outgoingEdges.reduce((sum, e) => sum + e.amount, 0);
      const confidence = Math.min(90, 50 + uniqueRecipients.length * 5);
      
      fanOut.push({
        hubNodeId: node.id,
        hubNodeLabel: node.label,
        connectedNodes: uniqueRecipients,
        type: 'FAN_OUT',
        degree: uniqueRecipients.length,
        totalVolume,
        riskScore: Math.min(100, node.riskScore + uniqueRecipients.length * 5),
        confidence
      });
    }
  });
  
  return { fanIn, fanOut };
}

// ============================================================================
// CIRCULAR FLOW DETECTION
// ============================================================================

export function detectCircularFlows(
  nodes: EntityNode[],
  edges: TransactionEdge[]
): CircularFlow[] {
  const circularFlows: CircularFlow[] = [];
  const visited = new Set<string>();
  
  // Build directed adjacency map
  const adjacency = new Map<string, { target: string; edge: TransactionEdge }[]>();
  edges.forEach(edge => {
    if (!adjacency.has(edge.source)) adjacency.set(edge.source, []);
    adjacency.get(edge.source)!.push({ target: edge.target, edge });
  });
  
  // DFS to find cycles
  const findCycles = (startNode: string, currentNode: string, path: string[], edgesUsed: TransactionEdge[]) => {
    if (path.length > 8) return; // Limit depth
    
    const neighbors = adjacency.get(currentNode) || [];
    
    for (const { target, edge } of neighbors) {
      if (target === startNode && path.length >= 3) {
        // Found a cycle
        circularFlows.push({
          nodes: [...path, target],
          edges: edgesUsed.map(e => e.id),
          totalAmount: edgesUsed.reduce((sum, e) => sum + e.amount, 0),
          riskScore: calculateCircularRisk(path, nodes, edgesUsed),
          hopCount: path.length
        });
      } else if (!visited.has(target) && !path.includes(target)) {
        visited.add(target);
        findCycles(startNode, target, [...path, target], [...edgesUsed, edge]);
        visited.delete(target);
      }
    }
  };
  
  // Start DFS from each node
  nodes.forEach(node => {
    visited.clear();
    visited.add(node.id);
    findCycles(node.id, node.id, [node.id], []);
  });
  
  // Deduplicate and limit results
  return deduplicateCircularFlows(circularFlows).slice(0, 20);
}

function calculateCircularRisk(path: string[], nodes: EntityNode[], edges: TransactionEdge[]): number {
  const nodeRiskScores = path.map(id => {
    const node = nodes.find(n => n.id === id);
    return node?.riskScore || 0;
  });
  
  const avgNodeRisk = nodeRiskScores.reduce((a, b) => a + b, 0) / nodeRiskScores.length;
  const maxNodeRisk = Math.max(...nodeRiskScores);
  
  const totalAmount = edges.reduce((sum, e) => sum + e.amount, 0);
  const amountFactor = totalAmount > 500000 ? 20 : totalAmount > 100000 ? 10 : 0;
  
  return Math.min(100, Math.round(avgNodeRisk * 0.5 + maxNodeRisk * 0.3 + amountFactor));
}

function deduplicateCircularFlows(flows: CircularFlow[]): CircularFlow[] {
  const seen = new Set<string>();
  const unique: CircularFlow[] = [];
  
  flows.forEach(flow => {
    // Create a canonical key for the cycle
    const minNode = flow.nodes.slice(0, -1).reduce((min, n) => n < min ? n : min);
    const startIdx = flow.nodes.indexOf(minNode);
    const canonical = [...flow.nodes.slice(startIdx), ...flow.nodes.slice(1, startIdx)].join(',');
    
    if (!seen.has(canonical)) {
      seen.add(canonical);
      unique.push(flow);
    }
  });
  
  return unique;
}

// ============================================================================
// RISK PROPAGATION
// ============================================================================

export function propagateRisks(
  nodes: EntityNode[],
  edges: TransactionEdge[],
  propagationFactor: number = 0.3
): RiskPropagatedNode[] {
  const results: RiskPropagatedNode[] = [];
  const adjacency = buildAdjacencyMap(edges);
  
  nodes.forEach(node => {
    const neighbors = adjacency.get(node.id) || [];
    const suspiciousNeighbors = neighbors.filter(neighborId => {
      const neighbor = nodes.find(n => n.id === neighborId);
      return neighbor && (neighbor.risk === 'HIGH' || neighbor.risk === 'CRITICAL');
    });
    
    if (suspiciousNeighbors.length === 0) return;
    
    // Calculate propagated risk
    let propagatedRisk = node.riskScore;
    const propagationPaths = suspiciousNeighbors.length;
    
    suspiciousNeighbors.forEach(neighborId => {
      const neighbor = nodes.find(n => n.id === neighborId);
      if (neighbor) {
        // Risk propagates based on connection strength and neighbor risk
        const connectionStrength = calculateConnectionStrength(node.id, neighborId, edges);
        const neighborContribution = neighbor.riskScore * propagationFactor * connectionStrength;
        propagatedRisk += neighborContribution;
      }
    });
    
    const riskIncrease = propagatedRisk - node.riskScore;
    
    if (riskIncrease > 5) { // Only report significant risk increases
      results.push({
        nodeId: node.id,
        originalRisk: node.riskScore,
        propagatedRisk: Math.min(100, Math.round(propagatedRisk)),
        riskIncrease: Math.round(riskIncrease),
        propagationSource: suspiciousNeighbors,
        propagationPaths
      });
    }
  });
  
  return results.sort((a, b) => b.riskIncrease - a.riskIncrease);
}

function calculateConnectionStrength(node1: string, node2: string, edges: TransactionEdge[]): number {
  const connectingEdges = edges.filter(e => 
    (e.source === node1 && e.target === node2) ||
    (e.source === node2 && e.target === node1)
  );
  
  if (connectingEdges.length === 0) return 0;
  
  // Strength based on number of transactions and volume
  const totalVolume = connectingEdges.reduce((sum, e) => sum + e.amount, 0);
  const volumeFactor = Math.min(1, totalVolume / 1000000); // Normalize to 1M
  
  return Math.min(1, connectingEdges.length * 0.2 + volumeFactor * 0.5);
}

// ============================================================================
// SUSPICIOUS PATH DETECTION
// ============================================================================

export function findSuspiciousPaths(
  nodes: EntityNode[],
  edges: TransactionEdge[]
): SuspiciousPath[] {
  const paths: SuspiciousPath[] = [];
  
  // Build adjacency map with weights
  const adjacency = new Map<string, { target: string; edge: TransactionEdge }[]>();
  edges.forEach(edge => {
    if (!adjacency.has(edge.source)) adjacency.set(edge.source, []);
    adjacency.get(edge.source)!.push({ target: edge.target, edge });
  });
  
  // Find paths from high-risk nodes
  const highRiskNodes = nodes.filter(n => n.risk === 'HIGH' || n.risk === 'CRITICAL');
  
  highRiskNodes.forEach(startNode => {
    const visited = new Set<string>();
    const dfs = (current: string, path: string[], totalAmount: number, riskScore: number) => {
      if (path.length > 6) return; // Limit depth
      
      const neighbors = adjacency.get(current) || [];
      
      for (const { target, edge } of neighbors) {
        if (!visited.has(target)) {
          visited.add(target);
          
          const targetNode = nodes.find(n => n.id === target);
          const newRisk = Math.max(riskScore, targetNode?.riskScore || 0);
          const newAmount = totalAmount + edge.amount;
          
          if (path.length >= 3) {
            paths.push({
              path: [...path, target],
              totalAmount: newAmount,
              riskScore: newRisk,
              hopCount: path.length,
              pattern: classifyPathPattern([...path, target], edges, nodes)
            });
          }
          
          dfs(target, [...path, target], newAmount, newRisk);
          visited.delete(target);
        }
      }
    };
    
    visited.add(startNode.id);
    dfs(startNode.id, [startNode.id], 0, startNode.riskScore);
  });
  
  // Sort by risk score and return top paths
  return paths.sort((a, b) => b.riskScore - a.riskScore).slice(0, 20);
}

function classifyPathPattern(path: string[], edges: TransactionEdge[], nodes: EntityNode[]): string {
  // Check for layering pattern
  const allDifferentClusters = new Set(path.map(id => {
    const node = nodes.find(n => n.id === id);
    return node?.clusterId;
  })).size === path.length;
  
  if (allDifferentClusters && path.length >= 3) return 'LAYERING';
  
  // Check for fan-out pattern
  const firstNodeEdges = edges.filter(e => e.source === path[0]);
  if (firstNodeEdges.length >= 3) return 'FAN_OUT';
  
  // Check for fan-in pattern
  const lastNodeEdges = edges.filter(e => e.target === path[path.length - 1]);
  if (lastNodeEdges.length >= 3) return 'FAN_IN';
  
  return 'SEQUENTIAL';
}

// ============================================================================
// NETWORK METRICS
// ============================================================================

export function calculateNetworkMetrics(
  nodes: EntityNode[],
  edges: TransactionEdge[]
): NetworkMetrics {
  const totalNodes = nodes.length;
  const totalEdges = edges.length;
  
  // Calculate average degree
  const degreeMap = new Map<string, number>();
  nodes.forEach(n => degreeMap.set(n.id, 0));
  
  edges.forEach(e => {
    degreeMap.set(e.source, (degreeMap.get(e.source) || 0) + 1);
    degreeMap.set(e.target, (degreeMap.get(e.target) || 0) + 1);
  });
  
  const degrees = [...degreeMap.values()];
  const averageDegree = degrees.reduce((a, b) => a + b, 0) / totalNodes;
  
  // Calculate density
  const maxPossibleEdges = totalNodes * (totalNodes - 1);
  const density = maxPossibleEdges > 0 ? totalEdges / maxPossibleEdges : 0;
  
  // Estimate clustering coefficient
  const clusteringCoefficient = estimateClusteringCoefficient(nodes, edges);
  
  // Estimate average path length
  const averagePathLength = estimateAveragePathLength(nodes, edges);
  
  return {
    totalNodes,
    totalEdges,
    averageDegree,
    density,
    clusteringCoefficient,
    averagePathLength
  };
}

function estimateClusteringCoefficient(nodes: EntityNode[], edges: TransactionEdge[]): number {
  // Simplified estimation
  const adjacency = buildAdjacencyMap(edges);
  let totalCoefficient = 0;
  
  nodes.forEach(node => {
    const neighbors = adjacency.get(node.id) || [];
    if (neighbors.length < 2) return;
    
    // Count triangles
    let triangles = 0;
    for (let i = 0; i < neighbors.length; i++) {
      for (let j = i + 1; j < neighbors.length; j++) {
        const node1Neighbors = adjacency.get(neighbors[i]) || [];
        if (node1Neighbors.includes(neighbors[j])) {
          triangles++;
        }
      }
    }
    
    const maxTriangles = (neighbors.length * (neighbors.length - 1)) / 2;
    totalCoefficient += triangles / maxTriangles;
  });
  
  return totalCoefficient / nodes.length;
}

function estimateAveragePathLength(nodes: EntityNode[], edges: TransactionEdge[]): number {
  // Simplified estimation using BFS sampling
  const adjacency = buildAdjacencyMap(edges);
  let totalPathLength = 0;
  let pathCount = 0;
  
  // Sample a subset of nodes
  const sampleSize = Math.min(20, nodes.length);
  const sampledNodes = nodes.slice(0, sampleSize);
  
  sampledNodes.forEach(startNode => {
    const distances = bfsDistances(startNode.id, adjacency);
    const validDistances = Object.values(distances).filter(d => d > 0 && d < Infinity);
    totalPathLength += validDistances.reduce((a, b) => a + b, 0);
    pathCount += validDistances.length;
  });
  
  return pathCount > 0 ? totalPathLength / pathCount : 0;
}

function bfsDistances(start: string, adjacency: Map<string, string[]>): Record<string, number> {
  const distances: Record<string, number> = {};
  const queue = [{ node: start, distance: 0 }];
  const visited = new Set<string>([start]);
  
  while (queue.length > 0) {
    const { node, distance } = queue.shift()!;
    distances[node] = distance;
    
    const neighbors = adjacency.get(node) || [];
    for (const neighbor of neighbors) {
      if (!visited.has(neighbor)) {
        visited.add(neighbor);
        queue.push({ node: neighbor, distance: distance + 1 });
      }
    }
  }
  
  return distances;
}

// ============================================================================
// MAIN ANALYSIS FUNCTION
// ============================================================================

export function performFullGraphAnalysis(
  nodes: EntityNode[],
  edges: TransactionEdge[]
): GraphAnalysisResult {
  const clusters = detectSuspiciousClusters(nodes, edges);
  const { fanIn, fanOut } = analyzeFanPatterns(nodes, edges);
  const circularFlows = detectCircularFlows(nodes, edges);
  const riskPropagatedNodes = propagateRisks(nodes, edges);
  const suspiciousPaths = findSuspiciousPaths(nodes, edges);
  const networkMetrics = calculateNetworkMetrics(nodes, edges);
  
  return {
    clusters,
    fanInAnalysis: fanIn,
    fanOutAnalysis: fanOut,
    circularFlows,
    riskPropagatedNodes,
    suspiciousPaths,
    networkMetrics
  };
}