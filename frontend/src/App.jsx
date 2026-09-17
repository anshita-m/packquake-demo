import { useCallback, useEffect, useMemo, useState } from "react";
import GraphView from "./components/GraphView";
import ReasoningPanel from "./components/ReasoningPanel";
import MitigationTable from "./components/MitigationTable";
import { getGraph, getMitigations, getPackage, simulate } from "./api";
import { topDirectPackagesForApp, requiresNeighbors, allPackageStats } from "./graphUtils";
import "./App.css";

export default function App() {
  const [graphData, setGraphData] = useState(null);
  const [mitigations, setMitigations] = useState([]);
  const [loadError, setLoadError] = useState(null);

  // Which apps are currently "expanded" (their top packages revealed).
  // Clicking an expanded app again removes it from this set, closing its
  // packages back up -- that's what makes apps closable. Kept separate
  // from packages revealed by clicking directly into the dependency graph
  // (below), so closing an app doesn't yank away a package someone
  // deliberately drilled into.
  const [expandedAppIds, setExpandedAppIds] = useState(() => new Set());

  // Packages revealed by clicking a package node itself (plus its one-hop
  // REQUIRES neighbors) -- persists independently of app expand/collapse.
  const [manuallyRevealedIds, setManuallyRevealedIds] = useState(() => new Set());

  // The actual visible-package set is derived, not stored: union of every
  // still-expanded app's top packages and everything manually revealed.
  // Collapsing an app just drops it from expandedAppIds and this recomputes
  // -- a package still shows if another expanded app also reveals it, or if
  // it was manually revealed, with no separate bookkeeping needed.
  const visiblePackageIds = useMemo(() => {
    const ids = new Set(manuallyRevealedIds);
    if (graphData) {
      for (const appId of expandedAppIds) {
        for (const pkgId of topDirectPackagesForApp(graphData, appId)) ids.add(pkgId);
      }
    }
    return ids;
  }, [graphData, expandedAppIds, manuallyRevealedIds]);

  // The one piece of "currently selected package" state that drives all
  // three panels together -- the reasoning drawer, the graph highlight, and
  // the mitigation table row.
  const [selectedPackageId, setSelectedPackageId] = useState(null);

  const [packageDetail, setPackageDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState(null);

  const [simulateResult, setSimulateResult] = useState(null);
  const [simulateError, setSimulateError] = useState(null);

  useEffect(() => {
    Promise.all([getGraph(), getMitigations()])
      .then(([graph, mitigationsResponse]) => {
        setGraphData(graph);
        setMitigations(mitigationsResponse.mitigations);
      })
      .catch((err) => setLoadError(err.message ?? String(err)));
  }, []);

  // Toggle: clicking a collapsed app expands it, clicking an already-expanded
  // app closes it back up.
  const handleToggleApp = useCallback((appId) => {
    setExpandedAppIds((prev) => {
      const next = new Set(prev);
      if (next.has(appId)) next.delete(appId);
      else next.add(appId);
      return next;
    });
  }, []);

  const handleSelectPackage = useCallback(
    (packageId) => {
      setSelectedPackageId(packageId);
      if (!graphData) return;
      // Replace, not merge: merging kept every previously-selected
      // package's neighbors around forever, so clicking through several
      // packages in a row kept adding more and more REQUIRES edges to the
      // view (every one of them still "both endpoints visible") until the
      // graph was an unreadable tangle. Each selection now shows only its
      // own immediate neighborhood -- still-expanded apps' packages stay
      // visible regardless, since those live in expandedAppIds, not here.
      const neighbors = requiresNeighbors(graphData, packageId);
      setManuallyRevealedIds(new Set([packageId, ...neighbors]));
    },
    [graphData],
  );

  const handleCloseDrawer = useCallback(() => setSelectedPackageId(null), []);

  // Reset button: collapse every expanded app and clear manually-revealed
  // packages, back to the empty starting graph.
  const handleResetGraph = useCallback(() => {
    setExpandedAppIds(new Set());
    setManuallyRevealedIds(new Set());
    setSelectedPackageId(null);
  }, []);

  // The two calls Phase 5/6-7 already expose, fired in parallel (two
  // independent effects on the same dependency, not chained).
  useEffect(() => {
    if (!selectedPackageId) {
      setPackageDetail(null);
      setDetailError(null);
      return;
    }
    let cancelled = false;
    setDetailLoading(true);
    setDetailError(null);
    getPackage(selectedPackageId)
      .then((detail) => {
        if (!cancelled) setPackageDetail(detail);
      })
      .catch((err) => {
        if (!cancelled) setDetailError(err.message ?? String(err));
      })
      .finally(() => {
        if (!cancelled) setDetailLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedPackageId]);

  useEffect(() => {
    if (!selectedPackageId) {
      setSimulateResult(null);
      setSimulateError(null);
      return;
    }
    // Clear the previous package's result immediately, before the new
    // fetch resolves -- otherwise the graph briefly highlights the OLD
    // package's compromised/trace edges while the new one is marked
    // "selected", which is exactly the flash of mismatched purple lines
    // that made clicking through packages look glitchy.
    setSimulateResult(null);
    let cancelled = false;
    simulate(selectedPackageId)
      .then((result) => {
        if (!cancelled) setSimulateResult(result);
      })
      .catch((err) => {
        if (!cancelled) {
          setSimulateResult(null);
          setSimulateError(err.message ?? String(err));
        }
      });
    return () => {
      cancelled = true;
    };
  }, [selectedPackageId]);

  // Whole-graph centrality/risk-score distributions, computed once, so the
  // reasoning drawer can say "higher than 82% of packages" instead of a
  // bare (often-tiny) float. No extra API call -- GET /graph already has
  // every package's numbers.
  const stats = useMemo(() => allPackageStats(graphData), [graphData]);

  if (loadError) {
    return (
      <div className="app-error">
        <h2>Couldn't load data from the API</h2>
        <p>{loadError}</p>
        <p className="note">Is the backend running (uvicorn graph_builder.api:app) and reachable?</p>
      </div>
    );
  }

  return (
    <div className="app-layout">
      <header className="app-header">
        <h1>
          PACKQUAKE
          <span className="app-tagline">Ecosystem Dependency Risk Analysis</span>
        </h1>
        {!graphData && <span className="loading-badge">Loading graph…</span>}
        {simulateError && <span className="error-badge">Simulation failed: {simulateError}</span>}
      </header>

      <main className="app-main">
        <section className="graph-section">
          <GraphView
            graphData={graphData}
            visiblePackageIds={visiblePackageIds}
            expandedAppIds={expandedAppIds}
            selectedPackageId={selectedPackageId}
            simulateResult={simulateResult}
            onSelectPackage={handleSelectPackage}
            onToggleApp={handleToggleApp}
            onResetGraph={handleResetGraph}
          />
        </section>

        <section className="mitigation-section">
          <MitigationTable mitigations={mitigations} selectedPackageId={selectedPackageId} onSelectRow={handleSelectPackage} />
        </section>
      </main>

      {selectedPackageId && (
        // No backdrop here on purpose: a full-viewport overlay was
        // swallowing every click/scroll/drag over the graph while the
        // drawer was open, making the graph unusable to pan or zoom
        // whenever a package was selected. The drawer's own × button
        // closes it instead.
        <ReasoningPanel
          packageDetail={packageDetail}
          loading={detailLoading}
          error={detailError}
          selectedPackageId={selectedPackageId}
          allStats={stats}
          onClose={handleCloseDrawer}
        />
      )}
    </div>
  );
}
