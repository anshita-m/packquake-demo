// Pure helpers for progressive disclosure over the full GET /graph payload
// (Apps + ~1,300+ packages). Rendering everything at once settles into an
// illegible hairball, so: apps are always visible, and packages only
// become visible once revealed by a click (see App.jsx). All three
// functions here operate on plain data (no cytoscape, no React) so they're
// cheap to unit test.

import { riskScoreToStyle } from "./colorScale";

export const TOP_PACKAGES_PER_APP = 20;

// Real data note: our Phase 2 SBOM parser marks DEPENDS_ON edges as
// direct=true for every package in an app whenever the scanner (observed:
// Syft on npm projects) never linked its root to any declared dependency --
// i.e. `direct` doesn't reliably narrow things down to "the small set of
// packages actually listed in package.json/requirements.txt". So instead of
// showing every direct=true package for an app (up to ~470 of them), an
// app-click reveals only its top N direct packages by risk_score.
export function topDirectPackagesForApp(graphData, appId, limit = TOP_PACKAGES_PER_APP) {
  const nodeById = new Map(graphData.nodes.map((n) => [n.id, n]));
  return graphData.edges
    .filter((e) => e.type === "DEPENDS_ON" && e.from === appId && e.direct)
    .map((e) => nodeById.get(e.to))
    .filter(Boolean)
    .sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0))
    .slice(0, limit)
    .map((n) => n.id);
}

// A package's direct REQUIRES neighbors, both directions (who it requires,
// and who requires it) -- one hop per click, so the graph grows
// incrementally and stays legible rather than dumping a full transitive
// closure on a single click.
export function requiresNeighbors(graphData, packageId) {
  const neighbors = new Set();
  for (const e of graphData.edges) {
    if (e.type !== "REQUIRES") continue;
    if (e.from === packageId) neighbors.add(e.to);
    if (e.to === packageId) neighbors.add(e.from);
  }
  return [...neighbors];
}

// Builds cytoscape elements (nodes + edges) for whatever subset of the
// graph is currently visible: all Application nodes, plus packages in
// `visiblePackageIds`, plus every edge from the full dataset whose both
// endpoints are visible (so revealing a node never leaves a dangling edge,
// and never draws an edge to something not shown).
export function buildElements(graphData, visiblePackageIds) {
  if (!graphData) return [];

  const appIds = graphData.nodes.filter((n) => n.type === "application").map((n) => n.id);
  const visibleIds = new Set([...appIds, ...visiblePackageIds]);

  const nodes = graphData.nodes
    .filter((n) => visibleIds.has(n.id))
    .map((n) => {
      if (n.type === "application") {
        return { data: { id: n.id, type: "application", name: n.name } };
      }
      const { size, color } = riskScoreToStyle(n.risk_score);
      return {
        data: {
          id: n.id,
          type: "package",
          name: n.name,
          version: n.version,
          ecosystem: n.ecosystem,
          risk_score: n.risk_score,
          size,
          color,
        },
      };
    });

  const edges = graphData.edges
    .filter((e) => visibleIds.has(e.from) && visibleIds.has(e.to))
    .map((e) => ({
      data: {
        id: `${e.from}=>${e.to}`,
        source: e.from,
        target: e.to,
        edgeType: e.type,
        direct: e.direct,
        depth: e.depth,
        blocks_propagation: e.blocks_propagation,
      },
    }));

  return [...nodes, ...edges];
}

// How many REQUIRES-hops each compromised package sits from the package
// that was actually simulated (`startId`), derived from `simulate_compromise`'s
// `trace` (a list of {from, to} edges in storage direction: `from` requires
// `to`). Propagation runs the opposite way -- from a compromised dependency
// out to whatever requires it -- so this walks the trace backwards from
// `startId`. Used to render risk propagation as a fading wave (closer =
// more intensely highlighted) instead of a flat compromised/not binary.
export function computeHopDistances(startId, trace) {
  const distances = new Map([[startId, 0]]);
  if (!trace || trace.length === 0) return distances;

  const propagatesTo = new Map(); // dependency -> [dependents that requires it]
  for (const step of trace) {
    const list = propagatesTo.get(step.to) ?? [];
    list.push(step.from);
    propagatesTo.set(step.to, list);
  }

  const queue = [startId];
  while (queue.length > 0) {
    const current = queue.shift();
    const currentDistance = distances.get(current);
    for (const dependent of propagatesTo.get(current) ?? []) {
      if (!distances.has(dependent)) {
        distances.set(dependent, currentDistance + 1);
        queue.push(dependent);
      }
    }
  }
  return distances;
}

// All package betweenness_centrality / risk_score values across the WHOLE
// graph (not just what's currently visible) -- used once to compute
// percentile context ("more central than 92% of packages") for whichever
// single package is selected, without a separate API call.
export function allPackageStats(graphData) {
  if (!graphData) return { centralities: [], riskScores: [] };
  const packages = graphData.nodes.filter((n) => n.type === "package");
  return {
    centralities: packages.map((n) => n.betweenness_centrality).filter((v) => v != null),
    riskScores: packages.map((n) => n.risk_score).filter((v) => v != null),
  };
}
