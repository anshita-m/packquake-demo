import { useCallback, useEffect, useMemo, useRef } from "react";
import CytoscapeComponent from "react-cytoscapejs";
import { buildElements, computeHopDistances } from "../graphUtils";
import { LEGEND_GRADIENT_STOPS } from "../colorScale";
import "./GraphView.css";

// "Compromised"/"selected" highlights use blue/violet -- deliberately
// nowhere near the OrRd (pale-yellow -> red) risk-score fill scale, so a
// highlighted node's border is never mistaken for "this is red because
// it's high-risk" vs. "this is outlined because it's selected/compromised".
const SELECTED_COLOR = "#1565c0";
const COMPROMISED_COLOR = "#6a1b9a";
const EXPANDED_APP_COLOR = "#2563eb";

const MIN_ZOOM = 0.15;
const MAX_ZOOM = 3;
const ZOOM_STEP = 1.25; // per click of the +/- toolbar buttons
const WHEEL_ZOOM_SENSITIVITY = 0.0026; // per unit of wheel deltaY
const MAX_WHEEL_STEP = 1.22; // clamp so a single wheel event can't jump far

// How far selecting a package is allowed to zoom in/out relative to
// wherever the view already was, so the "zoom into that area" focus
// animation reads as a tasteful nudge, not a jarring lurch to a tiny
// 1-2 node close-up.
const FOCUS_MAX_RELATIVE_ZOOM = 1.35;
const FOCUS_MIN_RELATIVE_ZOOM = 0.75;
const FOCUS_MAX_ABSOLUTE_ZOOM = 1.7;

const STYLESHEET = [
  {
    selector: "node[type = 'application']",
    style: {
      "background-color": "#1e293b",
      shape: "round-rectangle",
      width: 150,
      height: 58,
      label: "data(name)",
      color: "#fff",
      "text-valign": "center",
      "text-halign": "center",
      "font-size": 12,
      "font-weight": 600,
      "text-wrap": "wrap",
      "text-max-width": "136px",
      "border-width": 2,
      "border-color": "#1e293b",
    },
  },
  // An expanded app gets a bright ring so it's obvious which apps are
  // currently "open" (and therefore closable by clicking them again).
  {
    selector: "node[type = 'application'].expanded",
    style: {
      "border-width": 4,
      "border-color": EXPANDED_APP_COLOR,
      "background-color": "#1e3a5f",
    },
  },
  {
    selector: "node[type = 'package']",
    style: {
      "background-color": "data(color)",
      width: "data(size)",
      height: "data(size)",
      shape: "ellipse",
      "border-width": 1.5,
      // Cytoscape's border-color doesn't parse an 8-digit alpha hex --
      // opaque color + separate border-opacity is the supported way to get
      // the same subtle dark outline.
      "border-color": "#000000",
      "border-opacity": 0.13,
      // Package names are always visible now (previously hover-only) --
      // the user explicitly wants to be able to read names at a glance,
      // and with bigger nodes + a roomier cose layout there's space for it.
      // Truncated with an ellipsis at a fixed width rather than left to run
      // as long as the name needs: an untruncated long name (scoped npm
      // packages especially) could run past a neighboring node and overlap
      // its label, reading as garbled/doubled-up text.
      label: "data(name)",
      "font-size": 12,
      "font-weight": 600,
      color: "#1d2939",
      "text-valign": "bottom",
      "text-margin-y": 4,
      "text-background-color": "#fff",
      "text-background-opacity": 0.9,
      "text-background-padding": "3px",
      "text-wrap": "ellipsis",
      "text-max-width": "92px",
    },
  },
  {
    selector: "edge[edgeType = 'DEPENDS_ON']",
    style: {
      "line-color": "#b8c0cc",
      "target-arrow-color": "#b8c0cc",
      "target-arrow-shape": "triangle",
      "curve-style": "bezier",
      width: 1.75,
      "arrow-scale": 0.8,
    },
  },
  // REQUIRES (package -> package) is the "dependency" relationship the user
  // wants clearly marked, separately from DEPENDS_ON (app -> package) --
  // solid vs. dashed, plus a distinct color, rather than a faint dotted
  // line that barely reads at a glance.
  {
    selector: "edge[edgeType = 'REQUIRES']",
    style: {
      "line-color": "#8a94a6",
      "line-style": "dashed",
      "target-arrow-shape": "vee",
      "target-arrow-color": "#8a94a6",
      "curve-style": "bezier",
      width: 2,
      "arrow-scale": 0.9,
    },
  },
  // Highlight overlays -- border/glow only, layered on top of the
  // risk-score fill color, never replacing it.
  {
    selector: "node.selected",
    style: {
      "font-size": 12,
      "font-weight": 700,
      "border-width": 4,
      "border-color": SELECTED_COLOR,
      "overlay-color": SELECTED_COLOR,
      "overlay-opacity": 0.25,
      "overlay-padding": 6,
      "z-index": 30,
    },
  },
  // Risk propagation: compromised packages are tiered by hop distance from
  // the simulated package (data(hopDistance), set in the highlight effect
  // below) -- closer packages get a thicker, more opaque ring, so "risk
  // transmission" reads as a fading wave outward rather than a flat
  // yes/no highlight. The label stays the plain name (inherited from the
  // base package style, same ellipsis/max-width) rather than a longer
  // "name · N hops away" string -- swapping to a longer label after the
  // layout had already spaced nodes for the short one is what made
  // neighboring labels visually overlap/garble together.
  {
    selector: "node.compromised",
    style: {
      "font-weight": 700,
      "border-color": COMPROMISED_COLOR,
      "border-style": "solid",
      "z-index": 25,
    },
  },
  {
    selector: "node.compromised[hopDistance <= 1]",
    style: { "border-width": 6, "overlay-color": COMPROMISED_COLOR, "overlay-opacity": 0.28, "overlay-padding": 8 },
  },
  {
    selector: "node.compromised[hopDistance = 2]",
    style: { "border-width": 4.5, "overlay-color": COMPROMISED_COLOR, "overlay-opacity": 0.18, "overlay-padding": 6 },
  },
  {
    selector: "node.compromised[hopDistance >= 3]",
    style: { "border-width": 3, "overlay-color": COMPROMISED_COLOR, "overlay-opacity": 0.1, "overlay-padding": 4 },
  },
  {
    selector: "edge.trace-edge",
    style: {
      "line-color": COMPROMISED_COLOR,
      "target-arrow-color": COMPROMISED_COLOR,
      "line-style": "dashed",
      "arrow-scale": 1.1,
      "z-index": 999,
    },
  },
  // Trace edges nearer the compromise start are drawn thicker -- the same
  // fading-wave idea applied to the path itself, not just the nodes.
  { selector: "edge.trace-edge[hopDistance <= 1]", style: { width: 5 } },
  { selector: "edge.trace-edge[hopDistance = 2]", style: { width: 3.5 } },
  { selector: "edge.trace-edge[hopDistance >= 3]", style: { width: 2.5 } },
];

export default function GraphView({
  graphData,
  visiblePackageIds,
  expandedAppIds,
  selectedPackageId,
  simulateResult,
  onSelectPackage,
  onToggleApp,
  onResetGraph,
}) {
  const cyRef = useRef(null);
  const handlersRef = useRef({ onSelectPackage, onToggleApp });
  useEffect(() => {
    handlersRef.current = { onSelectPackage, onToggleApp };
  });

  const elements = useMemo(
    () => buildElements(graphData, visiblePackageIds),
    [graphData, visiblePackageIds],
  );

  // A circular/organic force-directed layout (cose) instead of strict
  // breadthfirst rows -- clicking an app clusters its revealed packages
  // around it rather than lining them up underneath.
  const baseLayoutOptions = useMemo(
    () => ({
      name: "cose",
      // Animating the transition (nodes visibly sliding from their default
      // starting spot to cose's computed final layout) is what made the
      // graph look like it was glitching/clustering-then-popping-apart on
      // every reveal -- a screenshot or click mid-transition catches nodes
      // still in flight. Applying the computed layout instantly is more
      // stable, if less smooth.
      animate: false,
      fit: true,
      padding: 50,
      nodeDimensionsIncludeLabels: true,
      idealEdgeLength: 90,
      // App nodes are 150x58 rectangles with no edges between them (each is
      // its own disconnected component pre-expand) -- cose's default
      // repulsion/spacing is tuned for small nodes and left them nearly
      // overlapping. nodeRepulsion pushes any two nodes apart in general;
      // componentSpacing specifically keeps separate disconnected
      // components (each unexpanded app, or each app + its revealed
      // packages) from landing on top of each other.
      nodeRepulsion: 450000,
      edgeElasticity: 100,
      gravity: 60,
      numIter: 1000,
      componentSpacing: 160,
      nodeOverlap: 24,
    }),
    [],
  );

  // The very first layout run needs randomize:true -- with nothing placed
  // yet, `randomize: false` leaves every node at the same default (0,0)
  // starting point, and since apps have no edges to each other, repulsion
  // from a perfectly coincident start never actually separates them (they
  // all render stacked on top of one node). Every run after that uses
  // randomize:false so already-placed nodes stay roughly put as more get
  // revealed, instead of reshuffling the whole graph.
  const hasLaidOutRef = useRef(false);

  // See the focus-zoom effect below -- these anchor the "zoom relative to
  // before this selection" clamp so it doesn't compound across the effect's
  // two firings per click.
  const preSelectZoomRef = useRef(1);
  const lastFocusedPackageRef = useRef(null);

  // A stable function reference (created once, body reads cyRef fresh each
  // call) so registerCy can always removeEventListener the exact same
  // reference before re-adding it. Without this, every time registerCy
  // fired (react-cytoscapejs calls it more than just once at mount) added
  // ANOTHER wheel listener on top of the old ones -- with N stacked
  // listeners, one wheel tick applied the zoom factor N times in a row,
  // which is what made zooming feel wildly too sensitive.
  const handleWheelRef = useRef((evt) => {
    const cy = cyRef.current;
    if (!cy) return;
    if (!(evt.ctrlKey || evt.metaKey)) return;
    evt.preventDefault();
    const rect = cy.container().getBoundingClientRect();
    const renderedPosition = { x: evt.clientX - rect.left, y: evt.clientY - rect.top };
    // Scale with the actual scroll distance instead of applying a flat
    // step per wheel event -- a trackpad fires dozens of small wheel
    // events per second during one gesture, so a fixed per-event step
    // compounded into a huge zoom swing from a single light scroll. This
    // scales gently with deltaY and is clamped so even one large-delta
    // event (some mice/trackpads burst these) can't jump too far.
    const rawFactor = Math.exp(-evt.deltaY * WHEEL_ZOOM_SENSITIVITY);
    const factor = Math.max(1 / MAX_WHEEL_STEP, Math.min(MAX_WHEEL_STEP, rawFactor));
    const level = Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, cy.zoom() * factor));
    cy.zoom({ level, renderedPosition });
  });

  const registerCy = useCallback((cy) => {
    cyRef.current = cy;
    cy.off("tap", "node");
    cy.on("tap", "node", (evt) => {
      const data = evt.target.data();
      if (data.type === "application") {
        handlersRef.current.onToggleApp(data.id);
      } else if (data.type === "package") {
        handlersRef.current.onSelectPackage(data.id);
      }
    });

    // Nicer default cursor affordance.
    cy.off("mouseover", "node");
    cy.off("mouseout", "node");
    cy.on("mouseover", "node", () => {
      cy.container().style.cursor = "pointer";
    });
    cy.on("mouseout", "node", () => {
      cy.container().style.cursor = "default";
    });

    // Plain scroll-to-zoom fights the page's own scroll (the graph fills
    // most of the viewport, so scrolling toward the mitigation table used
    // to zoom the graph instead). Handling wheel-zoom ourselves, gated on
    // Ctrl/Cmd (the same convention as Google Maps/Figma), gives back both:
    // a bare scroll always scrolls the page, and Ctrl/Cmd+scroll zooms the
    // graph in place under the cursor.
    cy.userZoomingEnabled(false);
    const container = cy.container();
    container.removeEventListener("wheel", handleWheelRef.current);
    container.addEventListener("wheel", handleWheelRef.current, { passive: false });
  }, []);

  const zoomBy = useCallback((factor) => {
    const cy = cyRef.current;
    if (!cy) return;
    const rect = cy.container().getBoundingClientRect();
    const level = Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, cy.zoom() * factor));
    cy.zoom({ level, renderedPosition: { x: rect.width / 2, y: rect.height / 2 } });
  }, []);
  const handleZoomIn = useCallback(() => zoomBy(ZOOM_STEP), [zoomBy]);
  const handleZoomOut = useCallback(() => zoomBy(1 / ZOOM_STEP), [zoomBy]);

  // `visiblePackageIds` is rebuilt as a new Set on every selection/highlight
  // change in App.jsx (even ones that don't add any package), which makes
  // `elements` a new array by reference every time too -- without this
  // signature check, every single click re-ran the full cose simulation
  // and reshuffled the whole graph, which is what made clicking anything
  // feel glitchy/hyperactive. Only an actual change in which nodes/edges
  // are visible should trigger a re-layout.
  const elementsSignatureRef = useRef("");
  // Cytoscape doesn't auto-cancel an in-flight animated layout when a new
  // one starts -- stacking two running cose simulations on the same nodes
  // is exactly what caused nodes to overlap/jump earlier, so stop the
  // previous one first.
  const activeLayoutRef = useRef(null);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    // Skip the empty pre-load render (before GET /graph resolves) -- laying
    // out zero nodes shouldn't count as "already laid out" and flip
    // subsequent randomize off before there's anything real to preserve.
    if (elements.length === 0) return;

    const signature = elements.map((el) => el.data.id).sort().join("|");
    if (signature === elementsSignatureRef.current) return;
    elementsSignatureRef.current = signature;

    // Only the very first layout (the initial apps-only graph) auto-fits
    // the viewport. Re-fitting on every later reveal is what made clicking
    // a package feel like it "zoomed into that area" -- it recentered/
    // rescaled the whole view out from under whatever the user was looking
    // at. Later reveals keep the user's current pan/zoom; "Fit view" is
    // there for when they want to see everything again.
    const isFirstLayout = !hasLaidOutRef.current;
    if (activeLayoutRef.current) activeLayoutRef.current.stop();
    const layout = cy.layout({ ...baseLayoutOptions, randomize: isFirstLayout, fit: isFirstLayout });
    activeLayoutRef.current = layout;
    layout.run();
    hasLaidOutRef.current = true;
  }, [elements, baseLayoutOptions]);

  // Which apps are expanded -- toggles the `.expanded` ring so it's visually
  // obvious which apps can be closed by clicking them again.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.nodes("[type = 'application']").removeClass("expanded");
    for (const appId of expandedAppIds ?? []) {
      cy.getElementById(appId).addClass("expanded");
    }
  }, [expandedAppIds, elements]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.elements().removeClass("selected compromised trace-edge");

    // This effect fires twice per click: once immediately (simulateResult
    // still null, so the neighborhood fallback below is used) and again
    // once the simulate() fetch resolves. Both firings need to clamp
    // relative to the SAME "before this selection" zoom -- re-reading
    // cy.zoom() fresh on the second firing would clamp relative to the
    // zoom the first firing just set, and two stacked ~25% adjustments
    // compound into a ~44% one, right back to the "zooms in/out too much"
    // problem. Snapshot the baseline once per actual selection change.
    if (selectedPackageId !== lastFocusedPackageRef.current) {
      preSelectZoomRef.current = cy.zoom();
      lastFocusedPackageRef.current = selectedPackageId;
    }

    // Tracks exactly what should be in view for this selection, so we can
    // zoom/pan to fit just that neighborhood instead of the whole graph.
    let focusCollection = cy.collection();

    if (selectedPackageId) {
      const selectedEle = cy.getElementById(selectedPackageId);
      selectedEle.addClass("selected");
      focusCollection = focusCollection.union(selectedEle);
    }
    if (simulateResult) {
      const hopDistances = computeHopDistances(selectedPackageId, simulateResult.trace);

      for (const pkg of simulateResult.compromised_packages) {
        const hop = hopDistances.get(pkg.id) ?? 1;
        const ele = cy.getElementById(pkg.id).addClass("compromised").data({ hopDistance: hop });
        focusCollection = focusCollection.union(ele);
      }
      for (const step of simulateResult.trace) {
        // The edge id is built in storage direction (dependent=>dependency);
        // propagation reads outward from the dependency, so the edge's
        // "distance from ground zero" is the hop count of its `to` side.
        const hop = hopDistances.get(step.to) ?? 1;
        cy.getElementById(`${step.from}=>${step.to}`).addClass("trace-edge").data({ hopDistance: hop });
      }
    } else if (selectedPackageId) {
      // The compromise simulation hasn't resolved yet -- focus on whatever
      // is already visibly connected (the one-hop REQUIRES neighbors
      // revealed by selecting it) rather than waiting.
      focusCollection = focusCollection.union(cy.getElementById(selectedPackageId).closedNeighborhood());
    }

    // Pan/zoom toward the selected package and everything it affects --
    // this is the "zoom into that area" the user asked for, scoped to the
    // relevant neighborhood rather than the whole graph. A plain `fit`
    // zooms in exactly as far as the bounding box demands, which for a
    // small focus set (a package with only 1-2 dependents) meant zooming
    // in dramatically close -- clamping how far a single selection can
    // zoom relative to where the view already was keeps it a subtle,
    // controlled nudge instead of a jarring close-up. This jumps straight
    // to the target instead of animating (cy.animate's rAF-driven
    // animation never reliably completes in every environment/tab state
    // we've tested this in) -- same call cy.stop() would otherwise guard
    // against isn't needed since there's no animation left to interrupt.
    if (focusCollection.length > 0) {
      const bb = focusCollection.boundingBox();
      const rect = cy.container().getBoundingClientRect();
      const padding = 90;
      const fitZoom = Math.min((rect.width - padding * 2) / bb.w, (rect.height - padding * 2) / bb.h);

      const baselineZoom = preSelectZoomRef.current;
      let targetZoom = Math.min(fitZoom, baselineZoom * FOCUS_MAX_RELATIVE_ZOOM, FOCUS_MAX_ABSOLUTE_ZOOM);
      targetZoom = Math.max(targetZoom, baselineZoom * FOCUS_MIN_RELATIVE_ZOOM);
      targetZoom = Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, targetZoom));

      const center = { x: (bb.x1 + bb.x2) / 2, y: (bb.y1 + bb.y2) / 2 };
      const pan = { x: rect.width / 2 - center.x * targetZoom, y: rect.height / 2 - center.y * targetZoom };

      cy.zoom(targetZoom);
      cy.pan(pan);
    }
  }, [selectedPackageId, simulateResult]);

  const handleResetView = useCallback(() => {
    const cy = cyRef.current;
    if (cy) cy.fit(undefined, 40);
  }, []);

  return (
    <div className="graph-view">
      <CytoscapeComponent
        elements={elements}
        stylesheet={STYLESHEET}
        style={{ width: "100%", height: "100%" }}
        // react-cytoscapejs would otherwise auto-run this layout itself on
        // mount/element changes, racing with the manual cy.layout(...).run()
        // below -- two concurrent cose simulations on the same nodes is what
        // caused every node to collapse onto one coincident point. "preset"
        // here is a no-op (keeps current positions); the effect below is the
        // single place that actually runs cose.
        layout={{ name: "preset" }}
        cy={registerCy}
      />

      {/* The reasoning drawer is a fixed overlay on the right (z-index 100,
          above this toolbar's z-index 10) -- without shifting left here,
          "Fit view"/"Close all" sit directly underneath it and can't be
          clicked while a package is selected. */}
      <div className={`graph-toolbar ${selectedPackageId ? "toolbar-drawer-open" : ""}`}>
        <div className="zoom-btn-group">
          <button type="button" className="graph-btn zoom-btn" onClick={handleZoomOut} aria-label="Zoom out">
            −
          </button>
          <button type="button" className="graph-btn zoom-btn" onClick={handleZoomIn} aria-label="Zoom in">
            +
          </button>
        </div>
        <button type="button" className="graph-btn" onClick={handleResetView}>
          Fit view
        </button>
        {visiblePackageIds.size > 0 && (
          <button type="button" className="graph-btn graph-btn-reset" onClick={onResetGraph}>
            Close all
          </button>
        )}
      </div>

      {graphData && visiblePackageIds.size === 0 && (
        <div className="graph-hint">
          👆 Click an application to reveal its highest-risk packages · use +/− or Ctrl/Cmd+scroll to zoom in and
          read names
        </div>
      )}
      {graphData && visiblePackageIds.size > 0 && (
        <div className="graph-hint">
          Click an expanded app (blue ring) again to close it · click any package to trace its risk · Ctrl/Cmd+scroll
          to zoom
        </div>
      )}

      <div className="graph-legend">
        <div className="legend-row">
          <span className="legend-label">Risk score</span>
          <div
            className="legend-gradient"
            style={{ background: `linear-gradient(to right, ${LEGEND_GRADIENT_STOPS.join(",")})` }}
          />
          <span className="legend-caption">low → high</span>
        </div>
        <div className="legend-row legend-hints">
          <span>● node size = risk score</span>
          <span>
            <span className="legend-swatch selected-swatch" /> selected
          </span>
          <span>
            <span className="legend-swatch compromised-swatch" /> compromised (thicker = closer)
          </span>
          <span className="legend-dashed-line" /> risk propagation path
          <span className="legend-dash-req" /> package requires package
        </div>
      </div>
    </div>
  );
}
