// Shared formatting/stat helpers used by ReasoningPanel, MitigationTable,
// and GraphView, so number/label formatting stays consistent everywhere.

// Real centrality values in this dataset are tiny (max observed ~0.0006
// across 628 packages) -- a flat .toFixed(3) rounds every single one to
// "0.000", which reads as "this is broken/always zero". Scientific
// notation for anything under 0.001 keeps the real value visible.
export function formatSmallNumber(value, digits = 3) {
  if (value == null || Number.isNaN(value)) return "—";
  if (value === 0) return "0";
  if (Math.abs(value) < 0.001) return value.toExponential(1);
  return value.toFixed(digits);
}

export function formatNumber(value, digits = 3) {
  return typeof value === "number" && !Number.isNaN(value) ? value.toFixed(digits) : "—";
}

export function formatPercent(value, digits = 0) {
  return typeof value === "number" && !Number.isNaN(value) ? `${(value * 100).toFixed(digits)}%` : "—";
}

// Where `value` falls among `allValues`, as a 0-1 fraction (1 = highest).
// Used to give tiny/awkward-scale numbers (centrality, risk score) a
// meaningful "higher than X% of packages" reading instead of a bare float.
export function percentileRank(allValues, value) {
  if (value == null || !allValues || allValues.length === 0) return null;
  const sorted = [...allValues].filter((v) => v != null).sort((a, b) => a - b);
  if (sorted.length === 0) return null;
  let countBelow = 0;
  for (const v of sorted) {
    if (v < value) countBelow += 1;
    else break;
  }
  return countBelow / sorted.length;
}

// "higher than 100% of packages" reads oddly in English when something is
// genuinely the single highest value in the dataset -- say so directly
// instead. Same at the bottom of the scale.
//
// Deliberately checks the actual min/max of `allValues`, not a fixed
// percentile threshold on the rank: with N values, the highest non-tied
// rank percentileRank can ever return is (N-1)/N, e.g. 627/628 = 0.9984
// for a 628-package graph -- already below any reasonable-looking
// threshold like 0.999, so a threshold check silently never fires for
// datasets under ~1000 items. Comparing directly against the real min/max
// has no such size dependency.
export function percentilePhrase(allValues, value) {
  const rank = percentileRank(allValues, value);
  if (rank == null) return null;

  const clean = (allValues || []).filter((v) => v != null);
  if (value != null && clean.length > 0) {
    if (value >= Math.max(...clean)) return "the highest in the graph";
    if (value <= Math.min(...clean)) return "the lowest in the graph";
  }

  // Reaching here means `value` is demonstrably NOT the max or min -- but
  // its rank can still round to a misleading "100%" (or "0%") at whole-
  // percent display precision (e.g. rank 0.995 -> "100%"). Clamp the
  // displayed number away from the extremes so it never contradicts the
  // "not the highest/lowest" fact we just established.
  const percentValue = Math.min(99, Math.max(1, Math.round(rank * 100)));
  return `higher than ${percentValue}% of packages`;
}

const RISK_LABELS = [
  [0.75, "Critical"],
  [0.5, "High"],
  [0.25, "Moderate"],
  [0, "Low"],
];

export function riskLabel(riskScore) {
  const score = riskScore ?? 0;
  for (const [threshold, label] of RISK_LABELS) {
    if (score >= threshold) return label;
  }
  return "Low";
}

// Plain-language explanations of the 5 risk-score factors, for the
// reasoning panel. The raw 0-1 normalized numbers stay available (small,
// secondary text) but the sentence is what a non-expert reads first.

export function explainCvss(raw, hasVulns) {
  if (!hasVulns || raw == null) {
    return "No known vulnerabilities on this package, so this doesn't add to its risk score.";
  }
  const cvss10 = raw * 10;
  if (cvss10 >= 9) return `The worst known vulnerability scores ${cvss10.toFixed(1)}/10 -- critical severity, about as bad as it gets.`;
  if (cvss10 >= 7) return `The worst known vulnerability scores ${cvss10.toFixed(1)}/10 -- high severity.`;
  if (cvss10 >= 4) return `The worst known vulnerability scores ${cvss10.toFixed(1)}/10 -- medium severity.`;
  return `The worst known vulnerability scores ${cvss10.toFixed(1)}/10 -- low severity.`;
}

export function explainExploitability(raw, hasVulns) {
  if (!hasVulns || raw == null) {
    return "No known vulnerabilities to exploit.";
  }
  const pct = Math.max(0, Math.min(100, Math.round(raw * 100)));
  if (raw >= 0.5) return `About a ${pct}% chance this gets actively exploited somewhere in the next 30 days -- high real-world attack risk.`;
  if (raw >= 0.1) return `About a ${pct}% chance of active exploitation in the next 30 days -- worth watching.`;
  return `Only about a ${pct}% chance of active exploitation in the next 30 days -- low real-world attack activity right now.`;
}

export function explainBlastRadius(blastRadiusApps) {
  const apps = blastRadiusApps ?? [];
  if (apps.length === 0) {
    return "If compromised, this package isn't known to directly reach any application.";
  }
  return `If compromised, this would directly reach ${apps.length} application${apps.length === 1 ? "" : "s"}: ${apps.join(", ")}.`;
}

export function explainCentrality(raw, percentile) {
  if (!raw) {
    return "This package sits off to the side of the dependency graph -- no other package's shortest path runs through it, so it isn't a structural chokepoint.";
  }
  if (percentile != null && percentile >= 0.9) {
    return "This is one of the most structurally central packages in the whole graph -- an unusually large number of other packages' dependency paths pass through it, so a compromise here could cascade far beyond its direct blast radius.";
  }
  if (percentile != null && percentile >= 0.5) {
    return "This package is more structurally central than most -- several other packages' dependency paths run through it, so a compromise could cascade further than its direct blast radius suggests.";
  }
  return "This package has some structural centrality, but isn't a major chokepoint in the dependency graph.";
}

export function explainRuntimeExposure(raw) {
  if (raw == null) return "No runtime exposure data available for the application(s) using this package.";
  if (raw >= 0.7) return "The application(s) using this package are highly exposed -- internet-facing, with significant traffic -- making a compromise easy for an attacker to reach and exploit.";
  if (raw >= 0.4) return "The application(s) using this package have moderate exposure to external traffic.";
  return "The application(s) using this package have low exposure -- mostly internal, with limited attack surface.";
}

// A short categorical label instead of a raw centrality number/percentile,
// for the structural-facts tiles.
export function centralityRoleLabel(raw, percentile) {
  if (!raw) return "Not a chokepoint";
  if (percentile != null && percentile >= 0.9) return "Major chokepoint";
  if (percentile != null && percentile >= 0.5) return "Moderate chokepoint";
  return "Minor chokepoint";
}

const EFFORT_META = {
  1: { label: "Quick win", color: "#2e7d32" },
  2: { label: "Moderate", color: "#e08600" },
  3: { label: "Major upgrade", color: "#c62828" },
};

export function effortMeta(effort) {
  return EFFORT_META[effort] ?? { label: "Unknown effort", color: "#757575" };
}
