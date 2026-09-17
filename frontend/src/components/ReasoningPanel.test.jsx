import { describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import ReasoningPanel from "./ReasoningPanel";

const FULL_DETAIL = {
  id: "npm:lodash@4.17.21",
  name: "lodash",
  version: "4.17.21",
  ecosystem: "npm",
  fan_in: 2,
  depth: 1,
  betweenness_centrality: 0.0006380616562220732,
  blast_radius_apps: ["hackathon-starter", "node-realworld"],
  vulnerabilities: [
    { id: "CVE-2021-23337", id_type: "cve", cvss_score: 7.2, cvss_severity: "HIGH", epss_score: 0.02, epss_percentile: 0.8 },
  ],
  raw_factors: {
    cvss_normalized: 0.72,
    exploitability: 0.02,
    centrality_normalized: 0.0006380616562220732,
    blast_radius_ratio: 0.5,
    runtime_exposure: 0.6,
  },
  weighted_terms: {
    cvss_normalized: 0.144,
    exploitability: 0.004,
    centrality_normalized: 0.000128,
    blast_radius_ratio: 0.1,
    runtime_exposure: 0.12,
  },
  risk_score: 0.388,
};

const STATS = { riskScores: [0.1, 0.2, 0.388, 0.5, 0.9], centralities: [0, 0, 0.0003, 0.0006380616562220732] };

describe("ReasoningPanel", () => {
  it("renders nothing when no package is selected", () => {
    const { container } = render(
      <ReasoningPanel packageDetail={null} loading={false} error={null} selectedPackageId={null} allStats={STATS} onClose={() => {}} />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("shows a loading state while a package is being fetched", () => {
    render(
      <ReasoningPanel packageDetail={null} loading={true} error={null} selectedPackageId="npm:lodash@4.17.21" allStats={STATS} onClose={() => {}} />,
    );
    expect(screen.getByTestId("reasoning-panel")).toHaveTextContent(/loading/i);
  });

  it("shows an error state distinctly from loading", () => {
    render(
      <ReasoningPanel packageDetail={null} loading={false} error="HTTP 500" selectedPackageId="npm:x@1.0.0" allStats={STATS} onClose={() => {}} />,
    );
    expect(screen.getByTestId("reasoning-panel")).toHaveTextContent(/couldn't load/i);
  });

  it("calls onClose when the close button is clicked", () => {
    const onClose = vi.fn();
    render(
      <ReasoningPanel packageDetail={FULL_DETAIL} loading={false} error={null} selectedPackageId={FULL_DETAIL.id} allStats={STATS} onClose={onClose} />,
    );
    fireEvent.click(screen.getByLabelText(/close/i));
    expect(onClose).toHaveBeenCalled();
  });

  it("renders the package identity and risk score", () => {
    render(
      <ReasoningPanel packageDetail={FULL_DETAIL} loading={false} error={null} selectedPackageId={FULL_DETAIL.id} allStats={STATS} onClose={() => {}} />,
    );
    const panel = screen.getByTestId("reasoning-panel");
    expect(panel).toHaveTextContent("lodash");
    expect(panel).toHaveTextContent("@4.17.21");
    expect(panel).toHaveTextContent("npm");
    expect(panel).toHaveTextContent("0.388");
  });

  it("shows percentile context for the risk score, not just the bare number", () => {
    render(
      <ReasoningPanel packageDetail={FULL_DETAIL} loading={false} error={null} selectedPackageId={FULL_DETAIL.id} allStats={STATS} onClose={() => {}} />,
    );
    // 2 of 5 stats values are below 0.388 -> 40th percentile
    expect(screen.getByTestId("reasoning-panel")).toHaveTextContent(/higher than 40% of packages/i);
  });

  it("says 'the highest in the graph' for the actual top package, not '100% of packages'", () => {
    // Regression test for a real bug: with hundreds of packages, the true
    // maximum's percentile rank (e.g. 627/628) never reaches a naive 99.9%
    // threshold, so this used to silently print "higher than 100%".
    const manyStats = { riskScores: [0.1, 0.2, 0.3, FULL_DETAIL.risk_score], centralities: [] };
    render(
      <ReasoningPanel packageDetail={FULL_DETAIL} loading={false} error={null} selectedPackageId={FULL_DETAIL.id} allStats={manyStats} onClose={() => {}} />,
    );
    const panel = screen.getByTestId("reasoning-panel");
    expect(panel).toHaveTextContent(/the highest in the graph/i);
    expect(panel).not.toHaveTextContent(/100%/);
  });

  it("shows a big, prominent 'would affect' banner naming the affected apps", () => {
    render(
      <ReasoningPanel packageDetail={FULL_DETAIL} loading={false} error={null} selectedPackageId={FULL_DETAIL.id} allStats={STATS} onClose={() => {}} />,
    );
    const panel = screen.getByTestId("reasoning-panel");
    const banner = panel.querySelector(".impact-banner");
    expect(banner).not.toBeNull();
    expect(banner).toHaveTextContent("hackathon-starter, node-realworld");
  });

  it("shows a neutral banner when a package has no blast radius", () => {
    const detail = { ...FULL_DETAIL, blast_radius_apps: [] };
    render(<ReasoningPanel packageDetail={detail} loading={false} error={null} selectedPackageId={detail.id} allStats={STATS} onClose={() => {}} />);
    const banner = screen.getByTestId("reasoning-panel").querySelector(".impact-banner");
    expect(banner).toHaveTextContent(/not known to directly affect any application/i);
  });

  it("renders all 5 factors as plain-language explanations, with raw/weighted numbers kept as secondary detail", () => {
    render(
      <ReasoningPanel packageDetail={FULL_DETAIL} loading={false} error={null} selectedPackageId={FULL_DETAIL.id} allStats={STATS} onClose={() => {}} />,
    );
    const list = screen.getByTestId("factor-table");
    expect(list).toHaveTextContent("CVSS severity");
    expect(list).toHaveTextContent("Exploitability (EPSS)");
    expect(list).toHaveTextContent("Structural centrality");
    expect(list).toHaveTextContent("Blast radius");
    expect(list).toHaveTextContent("Runtime exposure");
    // Explanations lead with plain language, not a bare number.
    expect(list).toHaveTextContent(/7\.2\/10 -- high severity/);
    expect(list).toHaveTextContent(/would directly reach 2 applications/i);
    // Raw/weighted numbers are still present, just secondary.
    expect(list).toHaveTextContent("raw 0.720");
    expect(list).toHaveTextContent("weighted 0.1440");
  });

  it("shows tiny centrality values in scientific notation instead of rounding to 0.000", () => {
    render(
      <ReasoningPanel packageDetail={FULL_DETAIL} loading={false} error={null} selectedPackageId={FULL_DETAIL.id} allStats={STATS} onClose={() => {}} />,
    );
    expect(screen.getByTestId("factor-table")).toHaveTextContent("6.4e-4");
  });

  it("lists each vulnerability individually with CVSS and EPSS, not just an aggregated max", () => {
    const detail = {
      ...FULL_DETAIL,
      vulnerabilities: [
        { id: "CVE-2021-23337", id_type: "cve", cvss_score: 7.2, cvss_severity: "HIGH", epss_score: 0.02 },
        { id: "GHSA-abcd-efgh", id_type: "ghsa", cvss_score: 5.0, cvss_severity: "MEDIUM", epss_score: null },
      ],
    };
    render(<ReasoningPanel packageDetail={detail} loading={false} error={null} selectedPackageId={detail.id} allStats={STATS} onClose={() => {}} />);
    const list = screen.getByTestId("vuln-list");
    expect(list).toHaveTextContent("CVE-2021-23337");
    expect(list).toHaveTextContent("7.2");
    expect(list).toHaveTextContent("GHSA-abcd-efgh");
    // GHSA has no CVE, so EPSS is structurally N/A, not "missing"
    expect(list).toHaveTextContent(/N\/A \(no CVE\)/);
  });

  it("labels a genuinely missing CVSS score as not yet scored, not blank or an error", () => {
    const detail = {
      ...FULL_DETAIL,
      vulnerabilities: [{ id: "CVE-2099-00000", id_type: "cve", cvss_score: null, cvss_severity: null, epss_score: 0.01 }],
    };
    render(<ReasoningPanel packageDetail={detail} loading={false} error={null} selectedPackageId={detail.id} allStats={STATS} onClose={() => {}} />);
    expect(screen.getByTestId("vuln-list")).toHaveTextContent(/not yet scored/i);
  });

  it("handles zero vulnerabilities as a clear positive state, not an error", () => {
    const detail = { ...FULL_DETAIL, vulnerabilities: [] };
    render(<ReasoningPanel packageDetail={detail} loading={false} error={null} selectedPackageId={detail.id} allStats={STATS} onClose={() => {}} />);
    // Scoped: the CVSS/exploitability factor explanations also mention "no
    // known vulnerabilities" when there are none, so a plain getByText
    // would match multiple elements -- check the dedicated note instead.
    expect(screen.getByText("✓ No known vulnerabilities.")).toBeInTheDocument();
  });

  it("shows 'no known CVEs' for the CVSS/exploitability factor rows when there are no vulnerabilities, instead of a bare 0", () => {
    const detail = {
      ...FULL_DETAIL,
      vulnerabilities: [],
      raw_factors: { ...FULL_DETAIL.raw_factors, cvss_normalized: 0, exploitability: 0 },
    };
    render(<ReasoningPanel packageDetail={detail} loading={false} error={null} selectedPackageId={detail.id} allStats={STATS} onClose={() => {}} />);
    const noDataCells = screen.getAllByText(/no known CVEs/i);
    expect(noDataCells.length).toBe(2); // cvss_normalized row + exploitability row
  });

  it("handles a package with no computed risk score yet as a normal state", () => {
    const detail = { ...FULL_DETAIL, raw_factors: null, weighted_terms: null, risk_score: null };
    render(<ReasoningPanel packageDetail={detail} loading={false} error={null} selectedPackageId={detail.id} allStats={STATS} onClose={() => {}} />);
    expect(screen.getByText(/no risk score computed yet/i)).toBeInTheDocument();
    expect(screen.queryByTestId("factor-table")).not.toBeInTheDocument();
  });

  it("flags a package with zero centrality as not a structural chokepoint, in plain language", () => {
    const detail = { ...FULL_DETAIL, betweenness_centrality: 0 };
    render(<ReasoningPanel packageDetail={detail} loading={false} error={null} selectedPackageId={detail.id} allStats={STATS} onClose={() => {}} />);
    expect(screen.getByTestId("factor-table")).toHaveTextContent(/isn't a structural chokepoint/i);
  });

  it("shows a categorical structural-role label instead of a raw centrality number in the stat grid", () => {
    const detail = { ...FULL_DETAIL, betweenness_centrality: 0 };
    render(<ReasoningPanel packageDetail={detail} loading={false} error={null} selectedPackageId={detail.id} allStats={STATS} onClose={() => {}} />);
    expect(screen.getByText("Not a chokepoint")).toBeInTheDocument();
  });
});
