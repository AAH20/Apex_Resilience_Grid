"""Failure propagation modeling, critical node identification, and resilience metrics."""

import math
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class PropagationConfig:
    """Configuration for failure propagation simulation."""
    threshold: float = 0.5
    propagation_probability: float = 1.0
    recovery_rate: float = 0.0
    max_steps: int = 100


@dataclass
class PropagationTrace:
    """Trace of a failure propagation simulation."""
    origin: str
    steps: List[Set[str]] = field(default_factory=list)
    total_steps: int = 0
    final_failed: Set[str] = field(default_factory=set)
    peak_concurrent_failures: int = 0


@dataclass
class CriticalityScore:
    """Criticality score for a node."""
    node_id: str
    blast_radius: int = 0
    betweenness: float = 0.0
    pagerank: float = 0.0
    vulnerability_index: float = 0.0
    rank: int = 0


@dataclass
class ResilienceReport:
    """Comprehensive resilience report."""
    robustness_index: float = 1.0
    redundancy_ratio: float = 0.0
    fragmentation_index: float = 0.0
    overall_score: float = 1.0
    mean_time_to_failure: float = 0.0


class FailurePropagationModel:
    """Models failure propagation across the grid."""

    def __init__(self, analyzer, config=None):
        self.analyzer = analyzer
        self.config = config or PropagationConfig()

    def _build_propagation_graph(self):
        """Build propagation adjacency (who fails when a node fails)."""
        threshold = self.config.threshold
        dependents = {}
        strong_deps = {}
        for from_node, deps in self.analyzer.dependencies.items():
            strong_deps[from_node] = [d.to_node for d in deps if d.weight >= threshold]
            for dep in deps:
                if dep.weight >= threshold:
                    dependents.setdefault(dep.to_node, []).append(from_node)
        return dependents, strong_deps

    def simulate(self, origin):
        """Simulate failure propagation from an origin node."""
        if origin not in self.analyzer.nodes:
            return PropagationTrace(
                origin=origin,
                steps=[{origin}],
                total_steps=1,
                final_failed={origin},
                peak_concurrent_failures=1,
            )

        dependents, strong_deps = self._build_propagation_graph()
        prob = self.config.propagation_probability

        failed = {origin}
        steps = [{origin}]
        queue = [origin]
        failed_dep_count = {nid: 0 for nid in self.analyzer.nodes}

        while queue and len(steps) < self.config.max_steps:
            current = queue.pop(0)
            new_failures = set()
            for dependent in dependents.get(current, []):
                if dependent not in failed:
                    failed_dep_count[dependent] += 1
                    if (len(strong_deps[dependent]) > 0
                            and failed_dep_count[dependent] >= len(strong_deps[dependent])):
                        if prob >= 1.0 or random.random() < prob:
                            failed.add(dependent)
                            new_failures.add(dependent)
                            queue.append(dependent)
            if new_failures:
                steps.append(new_failures)

        # Recovery
        if self.config.recovery_rate > 0:
            recovered = set()
            for node in list(failed):
                if node != origin and random.random() < self.config.recovery_rate:
                    recovered.add(node)
            failed -= recovered

        peak = max((len(s) for s in steps), default=0)

        return PropagationTrace(
            origin=origin,
            steps=steps,
            total_steps=len(steps),
            final_failed=failed,
            peak_concurrent_failures=peak,
        )

    def simulate_multiple(self, origins):
        """Simulate failure propagation from multiple origins."""
        all_failed = set()
        all_steps = []
        for origin in origins:
            trace = self.simulate(origin)
            all_failed.update(trace.final_failed)
            all_steps.extend(trace.steps)

        peak = max((len(s) for s in all_steps), default=0)

        return PropagationTrace(
            origin=",".join(origins),
            steps=all_steps,
            total_steps=len(all_steps),
            final_failed=all_failed,
            peak_concurrent_failures=peak,
        )

    def monte_carlo(self, origin, iterations=100):
        """Run Monte Carlo simulation for statistical analysis."""
        blast_radii = []
        for _ in range(iterations):
            trace = self.simulate(origin)
            blast_radii.append(len(trace.final_failed))

        n = len(blast_radii)
        mean = sum(blast_radii) / n
        variance = sum((x - mean) ** 2 for x in blast_radii) / n
        std = math.sqrt(variance)

        return {
            "mean_blast_radius": mean,
            "std_blast_radius": std,
            "min_blast_radius": min(blast_radii),
            "max_blast_radius": max(blast_radii),
            "failure_probability": sum(1 for r in blast_radii if r > 1) / n,
        }


class CriticalNodeIdentifier:
    """Identifies critical nodes in the grid."""

    def __init__(self, analyzer):
        self.analyzer = analyzer

    def _build_undirected_adjacency(self):
        """Build undirected adjacency for centrality computation."""
        adj = {nid: set() for nid in self.analyzer.nodes}
        for from_node, deps in self.analyzer.dependencies.items():
            for dep in deps:
                adj[from_node].add(dep.to_node)
                adj[dep.to_node].add(from_node)
        return adj

    def betweenness_centrality(self):
        """Compute betweenness centrality using Brandes' algorithm."""
        adj = self._build_undirected_adjacency()
        nodes = list(self.analyzer.nodes.keys())
        bc = {n: 0.0 for n in nodes}

        for s in nodes:
            # BFS
            dist = {n: -1 for n in nodes}
            sigma = {n: 0.0 for n in nodes}
            pred = {n: [] for n in nodes}
            dist[s] = 0
            sigma[s] = 1.0
            queue = [s]
            order = []

            while queue:
                v = queue.pop(0)
                order.append(v)
                for w in adj[v]:
                    if dist[w] < 0:
                        dist[w] = dist[v] + 1
                        queue.append(w)
                    if dist[w] == dist[v] + 1:
                        sigma[w] += sigma[v]
                        pred[w].append(v)

            # Accumulation
            delta = {n: 0.0 for n in nodes}
            for w in reversed(order):
                for v in pred[w]:
                    delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w])
                if w != s:
                    bc[w] += delta[w]

        # Normalize
        n = len(nodes)
        if n > 2:
            scale = 1.0 / ((n - 1) * (n - 2))
            for v in bc:
                bc[v] *= scale

        return bc

    def pagerank(self, damping=0.85, iterations=100):
        """Compute PageRank for each node."""
        adj = self._build_undirected_adjacency()
        nodes = list(self.analyzer.nodes.keys())
        n = len(nodes)
        if n == 0:
            return {}

        pr = {node: 1.0 / n for node in nodes}

        for _ in range(iterations):
            new_pr = {}
            for node in nodes:
                rank = (1.0 - damping) / n
                for other in nodes:
                    if node in adj[other] and len(adj[other]) > 0:
                        rank += damping * pr[other] / len(adj[other])
                new_pr[node] = rank
            pr = new_pr

        return pr

    def identify(self, top_k=None):
        """Identify and rank critical nodes."""
        if not self.analyzer.nodes:
            return []

        bc = self.betweenness_centrality()
        pr = self.pagerank()

        scores = []
        for node_id in self.analyzer.nodes:
            result = self.analyzer.simulate_failure(node_id)
            blast_radius = result.blast_radius

            max_bc = max(bc.values()) if bc else 1.0
            max_pr = max(pr.values()) if pr else 1.0

            norm_bc = bc[node_id] / max_bc if max_bc > 0 else 0.0
            norm_pr = pr[node_id] / max_pr if max_pr > 0 else 0.0
            norm_br = blast_radius / len(self.analyzer.nodes)

            vulnerability = 0.4 * norm_br + 0.3 * norm_bc + 0.3 * norm_pr

            scores.append(CriticalityScore(
                node_id=node_id,
                blast_radius=blast_radius,
                betweenness=bc[node_id],
                pagerank=pr[node_id],
                vulnerability_index=vulnerability,
            ))

        scores.sort(key=lambda s: -s.vulnerability_index)

        for i, score in enumerate(scores):
            score.rank = i + 1

        if top_k is not None:
            scores = scores[:top_k]

        return scores


class ResilienceMetrics:
    """Computes resilience metrics for the grid."""

    def __init__(self, analyzer):
        self.analyzer = analyzer

    def robustness_index(self):
        """Robustness index: 1.0 = fully robust, 0.0 = fragile."""
        if not self.analyzer.nodes:
            return 1.0

        total_blast = 0
        for node_id in self.analyzer.nodes:
            result = self.analyzer.simulate_failure(node_id)
            total_blast += result.blast_radius

        avg_blast = total_blast / len(self.analyzer.nodes)
        n = len(self.analyzer.nodes)
        if n <= 1:
            return 1.0

        robustness = 1.0 - (avg_blast - 1.0) / (n - 1.0)
        return max(0.0, min(1.0, robustness))

    def redundancy_ratio(self):
        """Redundancy ratio: fraction of nodes with multiple dependencies."""
        if not self.analyzer.nodes:
            return 0.0

        redundant_count = 0
        for node_id in self.analyzer.nodes:
            deps = self.analyzer.dependencies.get(node_id, [])
            strong_deps = [d for d in deps if d.weight >= 0.5]
            if len(strong_deps) >= 2:
                redundant_count += 1

        return redundant_count / len(self.analyzer.nodes)

    def fragmentation_index(self):
        """Fragmentation index: measures how fragmented the network is."""
        if not self.analyzer.nodes:
            return 0.0

        adj = {nid: set() for nid in self.analyzer.nodes}
        for from_node, deps in self.analyzer.dependencies.items():
            for dep in deps:
                adj[from_node].add(dep.to_node)
                adj[dep.to_node].add(from_node)

        visited = set()
        components = 0

        for node in self.analyzer.nodes:
            if node not in visited:
                components += 1
                queue = [node]
                visited.add(node)
                while queue:
                    current = queue.pop(0)
                    for neighbor in adj[current]:
                        if neighbor not in visited:
                            visited.add(neighbor)
                            queue.append(neighbor)

        n = len(self.analyzer.nodes)
        if n <= 1:
            return 0.0

        return (components - 1.0) / (n - 1.0)

    def compute(self):
        """Compute comprehensive resilience report."""
        if not self.analyzer.nodes:
            return ResilienceReport(
                robustness_index=1.0,
                redundancy_ratio=0.0,
                fragmentation_index=0.0,
                overall_score=1.0,
                mean_time_to_failure=0.0,
            )

        ri = self.robustness_index()
        rr = self.redundancy_ratio()
        fi = self.fragmentation_index()

        overall = 0.5 * ri + 0.3 * rr + 0.2 * (1.0 - fi)
        overall = max(0.0, min(1.0, overall))

        total_blast = 0
        for node_id in self.analyzer.nodes:
            result = self.analyzer.simulate_failure(node_id)
            total_blast += result.blast_radius

        avg_blast = total_blast / len(self.analyzer.nodes)
        mttf = 1.0 / avg_blast if avg_blast > 0 else 1.0

        return ResilienceReport(
            robustness_index=ri,
            redundancy_ratio=rr,
            fragmentation_index=fi,
            overall_score=overall,
            mean_time_to_failure=mttf,
        )
