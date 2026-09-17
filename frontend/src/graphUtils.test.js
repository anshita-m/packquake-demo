import { describe, expect, it } from "vitest";
import { allPackageStats, buildElements, computeHopDistances, requiresNeighbors, topDirectPackagesForApp } from "./graphUtils";

const GRAPH = {
  nodes: [
    { id: "app1", type: "application", name: "app1" },
    { id: "npm:a@1.0.0", type: "package", name: "a", version: "1.0.0", ecosystem: "npm", risk_score: 0.9 },
    { id: "npm:b@1.0.0", type: "package", name: "b", version: "1.0.0", ecosystem: "npm", risk_score: 0.1 },
    { id: "npm:c@1.0.0", type: "package", name: "c", version: "1.0.0", ecosystem: "npm", risk_score: 0.5 },
  ],
  edges: [
    { from: "app1", to: "npm:a@1.0.0", type: "DEPENDS_ON", direct: true, depth: 1 },
    { from: "app1", to: "npm:b@1.0.0", type: "DEPENDS_ON", direct: true, depth: 1 },
    { from: "app1", to: "npm:c@1.0.0", type: "DEPENDS_ON", direct: false, depth: 2 },
    { from: "npm:a@1.0.0", to: "npm:c@1.0.0", type: "REQUIRES" },
  ],
};

describe("topDirectPackagesForApp", () => {
  it("returns only direct=true packages, sorted by risk_score descending", () => {
    const result = topDirectPackagesForApp(GRAPH, "app1");
    expect(result).toEqual(["npm:a@1.0.0", "npm:b@1.0.0"]); // c is direct=false, excluded
  });

  it("respects the limit", () => {
    const result = topDirectPackagesForApp(GRAPH, "app1", 1);
    expect(result).toEqual(["npm:a@1.0.0"]); // highest risk_score
  });
});

describe("requiresNeighbors", () => {
  it("finds both outgoing and incoming REQUIRES edges", () => {
    expect(requiresNeighbors(GRAPH, "npm:a@1.0.0")).toEqual(["npm:c@1.0.0"]);
    expect(requiresNeighbors(GRAPH, "npm:c@1.0.0")).toEqual(["npm:a@1.0.0"]);
  });

  it("returns an empty array for a package with no REQUIRES edges", () => {
    expect(requiresNeighbors(GRAPH, "npm:b@1.0.0")).toEqual([]);
  });
});

describe("buildElements", () => {
  it("always includes application nodes regardless of visiblePackageIds", () => {
    const elements = buildElements(GRAPH, new Set());
    const ids = elements.map((el) => el.data.id);
    expect(ids).toContain("app1");
  });

  it("only includes packages that are in visiblePackageIds", () => {
    const elements = buildElements(GRAPH, new Set(["npm:a@1.0.0"]));
    const packageIds = elements.filter((el) => el.data.type === "package").map((el) => el.data.id);
    expect(packageIds).toEqual(["npm:a@1.0.0"]);
  });

  it("only includes edges whose both endpoints are visible", () => {
    const elements = buildElements(GRAPH, new Set(["npm:a@1.0.0"]));
    const edges = elements.filter((el) => el.data.source);
    // app1->a is included (both visible); a->c is NOT (c not visible)
    expect(edges).toHaveLength(1);
    expect(edges[0].data.source).toBe("app1");
    expect(edges[0].data.target).toBe("npm:a@1.0.0");
  });

  it("bakes size and color onto package nodes from risk_score", () => {
    const elements = buildElements(GRAPH, new Set(["npm:a@1.0.0"]));
    const aNode = elements.find((el) => el.data.id === "npm:a@1.0.0");
    expect(typeof aNode.data.size).toBe("number");
    expect(typeof aNode.data.color).toBe("string");
  });

  it("revealing both endpoints shows the connecting edge too", () => {
    const elements = buildElements(GRAPH, new Set(["npm:a@1.0.0", "npm:c@1.0.0"]));
    const edges = elements.filter((el) => el.data.source);
    const requiresEdge = edges.find((e) => e.data.edgeType === "REQUIRES");
    expect(requiresEdge).toBeDefined();
  });
});

describe("computeHopDistances", () => {
  // trace entries are {from, to} in storage direction (from requires to);
  // propagation runs the other way, from `to` out to `from`.
  const TRACE = [
    { from: "b", to: "a" }, // b requires a -- a compromised propagates to b
    { from: "c", to: "b" }, // c requires b -- propagates on to c
    { from: "d", to: "b" }, // d also requires b -- sibling of c, same distance
  ];

  it("gives the start package distance 0", () => {
    expect(computeHopDistances("a", TRACE).get("a")).toBe(0);
  });

  it("gives directly-propagated packages distance 1", () => {
    expect(computeHopDistances("a", TRACE).get("b")).toBe(1);
  });

  it("gives further packages increasing distance", () => {
    const distances = computeHopDistances("a", TRACE);
    expect(distances.get("c")).toBe(2);
    expect(distances.get("d")).toBe(2);
  });

  it("returns just the start at distance 0 when there's no trace", () => {
    const distances = computeHopDistances("a", []);
    expect(distances.size).toBe(1);
    expect(distances.get("a")).toBe(0);
  });

  it("doesn't include packages the compromise never reaches", () => {
    const distances = computeHopDistances("a", TRACE);
    expect(distances.has("unrelated")).toBe(false);
  });
});

describe("allPackageStats", () => {
  const GRAPH_WITH_CENTRALITY = {
    nodes: [
      { id: "app1", type: "application", name: "app1" },
      { id: "npm:a@1.0.0", type: "package", name: "a", risk_score: 0.9, betweenness_centrality: 0.0006 },
      { id: "npm:b@1.0.0", type: "package", name: "b", risk_score: 0.1, betweenness_centrality: 0 },
      { id: "npm:c@1.0.0", type: "package", name: "c", risk_score: 0.5, betweenness_centrality: null },
    ],
    edges: [],
  };

  it("collects risk_score and betweenness_centrality across every package, ignoring apps", () => {
    const stats = allPackageStats(GRAPH_WITH_CENTRALITY);
    expect(stats.riskScores).toEqual([0.9, 0.1, 0.5]);
  });

  it("filters out null/missing centrality values rather than including them as 0", () => {
    const stats = allPackageStats(GRAPH_WITH_CENTRALITY);
    expect(stats.centralities).toEqual([0.0006, 0]); // the null one dropped, the real 0 kept
  });

  it("returns empty arrays when there's no graph yet", () => {
    expect(allPackageStats(null)).toEqual({ centralities: [], riskScores: [] });
  });
});
