import { describe, expect, it } from "vitest";
import {
  centralityRoleLabel,
  effortMeta,
  explainBlastRadius,
  explainCentrality,
  explainCvss,
  explainExploitability,
  explainRuntimeExposure,
  formatNumber,
  formatPercent,
  formatSmallNumber,
  percentilePhrase,
  percentileRank,
  riskLabel,
} from "./format";

describe("formatSmallNumber", () => {
  it("uses scientific notation for values under 0.001, where a fixed decimal would round to zero", () => {
    expect(formatSmallNumber(0.0006380616562220732)).toBe("6.4e-4");
  });

  it("uses a fixed decimal for values at or above 0.001", () => {
    expect(formatSmallNumber(0.5)).toBe("0.500");
  });

  it("renders exactly zero as a plain 0, not 0e+0", () => {
    expect(formatSmallNumber(0)).toBe("0");
  });

  it("handles null/undefined gracefully", () => {
    expect(formatSmallNumber(null)).toBe("—");
    expect(formatSmallNumber(undefined)).toBe("—");
  });
});

describe("formatNumber / formatPercent", () => {
  it("formats a plain number to fixed decimals", () => {
    expect(formatNumber(0.49260600000000004, 3)).toBe("0.493");
  });

  it("formats a fraction as a percent", () => {
    expect(formatPercent(0.826, 0)).toBe("83%");
  });

  it("both fall back to an em dash for non-numbers", () => {
    expect(formatNumber(null)).toBe("—");
    expect(formatPercent(undefined)).toBe("—");
  });
});

describe("percentileRank", () => {
  it("computes the fraction of values strictly below the target", () => {
    expect(percentileRank([1, 2, 3, 4, 5], 3)).toBeCloseTo(0.4); // 2 of 5 below
  });

  it("returns 0 for the minimum value", () => {
    expect(percentileRank([1, 2, 3], 1)).toBe(0);
  });

  it("returns null when there's nothing to compare against", () => {
    expect(percentileRank([], 5)).toBeNull();
    expect(percentileRank(null, 5)).toBeNull();
  });

  it("returns null for a null/undefined value", () => {
    expect(percentileRank([1, 2, 3], null)).toBeNull();
  });
});

describe("percentilePhrase", () => {
  it("says 'the highest in the graph' for the actual maximum value", () => {
    expect(percentilePhrase([1, 2, 3, 4, 5], 5)).toBe("the highest in the graph");
  });

  it("says 'the lowest in the graph' for the actual minimum value", () => {
    expect(percentilePhrase([1, 2, 3, 4, 5], 1)).toBe("the lowest in the graph");
  });

  it("uses the normal phrasing in between", () => {
    expect(percentilePhrase([1, 2, 3, 4, 5], 3)).toBe("higher than 40% of packages");
  });

  it("returns null when there's no data to compare against", () => {
    expect(percentilePhrase([], 5)).toBeNull();
    expect(percentilePhrase(null, 5)).toBeNull();
  });

  // Regression test: with N=628 (this project's real package count), the
  // true maximum's rank is 627/628 = 0.9984 -- a naive `rank >= 0.999`
  // threshold check silently never fires here, which is exactly the bug
  // this function used to have (it printed "higher than 100% of packages"
  // for the actual #1 highest-risk package in the real graph).
  it("correctly identifies the maximum in a large (628-item) dataset", () => {
    // allValues includes the target itself, same as the real app's
    // allStats.riskScores (every package, including the selected one) --
    // so the max's rank is 627/628 = 0.9984, not a clean 1.0.
    const maxValue = 5;
    const values = [...Array.from({ length: 627 }, (_, i) => i / 627), maxValue];
    expect(percentilePhrase(values, maxValue)).toBe("the highest in the graph");
  });

  // Regression test for a second, related real bug: a value can be
  // demonstrably NOT the maximum (something else in the array is bigger)
  // yet still have a rank that rounds to "100%" at whole-percent display
  // precision (e.g. rank 0.9952 -> Math.round(99.52) -> 100). Found via
  // axios@1.6.2 in the real graph: rank 625/628 = 0.9952, not the max
  // (werkzeug was), but still printed "higher than 100% of packages".
  it("never displays 100% (or 0%) for a value that isn't actually the max/min", () => {
    const values = [...Array.from({ length: 624 }, (_, i) => i / 1000), 0.9952, 5]; // 5 is the true max
    const result = percentilePhrase(values, 0.9952);
    expect(result).not.toContain("100%");
    expect(result).toBe("higher than 99% of packages");
  });

  it("symmetrically never displays 0% for a value that isn't actually the min", () => {
    const values = [-5, 0.0001, ...Array.from({ length: 624 }, (_, i) => 1 + i / 1000)]; // -5 is the true min
    const result = percentilePhrase(values, 0.0001);
    expect(result).not.toContain("0%");
    expect(result).toBe("higher than 1% of packages");
  });
});

describe("riskLabel", () => {
  it("buckets scores into Low/Moderate/High/Critical", () => {
    expect(riskLabel(0.1)).toBe("Low");
    expect(riskLabel(0.3)).toBe("Moderate");
    expect(riskLabel(0.6)).toBe("High");
    expect(riskLabel(0.9)).toBe("Critical");
  });

  it("treats a missing score as Low, not a crash", () => {
    expect(riskLabel(null)).toBe("Low");
  });
});

describe("explainCvss", () => {
  it("names critical severity for a 9.8/10 CVE", () => {
    expect(explainCvss(0.98, true)).toMatch(/9\.8\/10/);
    expect(explainCvss(0.98, true)).toMatch(/critical/i);
  });

  it("says there are no known vulnerabilities when hasVulns is false", () => {
    expect(explainCvss(0, false)).toMatch(/no known vulnerabilities/i);
  });
});

describe("explainExploitability", () => {
  it("flags a high EPSS probability as high real-world attack risk", () => {
    expect(explainExploitability(0.7, true)).toMatch(/70%/);
    expect(explainExploitability(0.7, true)).toMatch(/high real-world attack risk/i);
  });

  it("flags a low EPSS probability as low activity", () => {
    expect(explainExploitability(0.02, true)).toMatch(/low real-world attack activity/i);
  });

  it("says there's nothing to exploit when there are no vulnerabilities", () => {
    expect(explainExploitability(0, false)).toMatch(/no known vulnerabilities/i);
  });
});

describe("explainBlastRadius", () => {
  it("names the affected apps directly", () => {
    expect(explainBlastRadius(["hackathon-starter", "node-realworld"])).toBe(
      "If compromised, this would directly reach 2 applications: hackathon-starter, node-realworld.",
    );
  });

  it("handles zero affected apps as a clear statement, not a bare 0", () => {
    expect(explainBlastRadius([])).toMatch(/isn't known to directly reach any application/i);
  });
});

describe("explainCentrality", () => {
  it("says a zero-centrality package is not a chokepoint", () => {
    expect(explainCentrality(0, null)).toMatch(/not a structural chokepoint|isn't a structural chokepoint/i);
  });

  it("flags a top-percentile package as one of the most central in the graph", () => {
    expect(explainCentrality(0.0006, 0.95)).toMatch(/most structurally central/i);
  });
});

describe("explainRuntimeExposure", () => {
  it("flags high exposure as easy for an attacker to reach", () => {
    expect(explainRuntimeExposure(0.9)).toMatch(/highly exposed/i);
  });

  it("flags low exposure as limited attack surface", () => {
    expect(explainRuntimeExposure(0.1)).toMatch(/low exposure/i);
  });
});

describe("centralityRoleLabel", () => {
  it("labels zero centrality as not a chokepoint", () => {
    expect(centralityRoleLabel(0, null)).toBe("Not a chokepoint");
  });

  it("labels a high-percentile package as a major chokepoint", () => {
    expect(centralityRoleLabel(0.001, 0.95)).toBe("Major chokepoint");
  });

  it("labels a mid-percentile package as a moderate chokepoint", () => {
    expect(centralityRoleLabel(0.0005, 0.6)).toBe("Moderate chokepoint");
  });
});

describe("effortMeta", () => {
  it("maps 1/2/3 to Quick win/Moderate/Major upgrade", () => {
    expect(effortMeta(1).label).toBe("Quick win");
    expect(effortMeta(2).label).toBe("Moderate");
    expect(effortMeta(3).label).toBe("Major upgrade");
  });

  it("has a fallback for a null/unknown effort rather than crashing", () => {
    expect(effortMeta(null).label).toBe("Unknown effort");
  });
});
