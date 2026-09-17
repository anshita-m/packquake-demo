import { describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import MitigationTable from "./MitigationTable";

const MITIGATIONS = [
  {
    package: { name: "werkzeug", version: "0.15.2", ecosystem: "pypi" },
    risk_score_before: 0.49, risk_score_after: 0.18, risk_reduction: 0.31,
    fixed_version: "3.1.6", effort: 3, priority: 0.1025,
    explanation: "critical CVE (CVSS 9.8), internet-facing exposure",
  },
  {
    package: { name: "uwsgi", version: "2.0.18", ecosystem: "pypi" },
    risk_score_before: 0.3, risk_score_after: 0.15, risk_reduction: 0.15,
    fixed_version: "2.0.30", effort: 1, priority: 0.1543,
    explanation: "high CVE (CVSS 7.5), internet-facing exposure",
  },
];

// Deliberately plain textContent matching, not an RTL text query: the
// package cell has nested markup (name + version + ecosystem in separate
// elements), so a text query could match several ancestors at once and
// throw on ambiguity. A row's full textContent has no such issue.
function rowFor(name) {
  const rows = screen.getAllByTestId("mitigation-row");
  return rows.find((r) => r.textContent.includes(name));
}

// The section is collapsed by default (it's secondary to the graph) --
// tests that need to see rows/headers expand it first.
function expand() {
  fireEvent.click(screen.getByRole("button", { name: /mitigation priorities/i }));
}

describe("MitigationTable", () => {
  it("is collapsed by default, showing neither rows nor the empty-state note", () => {
    render(<MitigationTable mitigations={MITIGATIONS} selectedPackageId={null} onSelectRow={() => {}} />);
    expect(screen.queryByTestId("mitigation-row")).not.toBeInTheDocument();
  });

  it("expands to show its rows when the header is clicked", () => {
    render(<MitigationTable mitigations={MITIGATIONS} selectedPackageId={null} onSelectRow={() => {}} />);
    expand();
    expect(screen.getAllByTestId("mitigation-row")).toHaveLength(2);
  });

  it("renders a normal empty state (not an error) when there are no vulnerable packages", () => {
    render(<MitigationTable mitigations={[]} selectedPackageId={null} onSelectRow={() => {}} />);
    expand();
    expect(screen.getByText(/no vulnerable packages/i)).toBeInTheDocument();
  });

  it("renders one row per mitigation, sorted by risk_reduction descending by default", () => {
    render(<MitigationTable mitigations={MITIGATIONS} selectedPackageId={null} onSelectRow={() => {}} />);
    expand();
    const rows = screen.getAllByTestId("mitigation-row");
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent("werkzeug"); // 0.31 > 0.15
    expect(rows[1]).toHaveTextContent("uwsgi");
  });

  it("shows only 5 columns -- no separate raw effort/priority columns cluttering the table", () => {
    render(<MitigationTable mitigations={MITIGATIONS} selectedPackageId={null} onSelectRow={() => {}} />);
    expand();
    const headers = screen.getAllByRole("columnheader").map((h) => h.textContent.trim().toLowerCase());
    expect(headers).toHaveLength(5);
    expect(headers).not.toContain("effort");
    expect(headers).not.toContain("priority");
  });

  it("shows the recommended fix version and an effort badge instead of a bare effort number", () => {
    render(<MitigationTable mitigations={MITIGATIONS} selectedPackageId={null} onSelectRow={() => {}} />);
    expand();
    const werkzeugRow = rowFor("werkzeug");
    expect(werkzeugRow).toHaveTextContent("Upgrade to 3.1.6");
    expect(werkzeugRow).toHaveTextContent("Major upgrade"); // effort 3
    const uwsgiRow = rowFor("uwsgi");
    expect(uwsgiRow).toHaveTextContent("Upgrade to 2.0.30");
    expect(uwsgiRow).toHaveTextContent("Quick win"); // effort 1
  });

  it("re-sorts when the 'Current risk' column header is clicked", () => {
    render(<MitigationTable mitigations={MITIGATIONS} selectedPackageId={null} onSelectRow={() => {}} />);
    expand();
    fireEvent.click(screen.getByText(/current risk/i));
    const rows = screen.getAllByTestId("mitigation-row");
    // risk_score_before: werkzeug 0.49 > uwsgi 0.3 -- descending on first click
    expect(rows[0]).toHaveTextContent("werkzeug");
  });

  it("toggles sort direction when clicking the already-active column header", () => {
    render(<MitigationTable mitigations={MITIGATIONS} selectedPackageId={null} onSelectRow={() => {}} />);
    expand();
    // "If fixed" (risk_reduction) is already the default sort field/desc
    fireEvent.click(screen.getByText(/if fixed/i));
    const rows = screen.getAllByTestId("mitigation-row");
    expect(rows[0]).toHaveTextContent("uwsgi"); // now ascending: 0.15 before 0.31
  });

  it("calls onSelectRow with the package id when a row is clicked", () => {
    const onSelectRow = vi.fn();
    render(<MitigationTable mitigations={MITIGATIONS} selectedPackageId={null} onSelectRow={onSelectRow} />);
    expand();
    fireEvent.click(rowFor("werkzeug"));
    expect(onSelectRow).toHaveBeenCalledWith("pypi:werkzeug@0.15.2");
  });

  it("highlights the row matching selectedPackageId", () => {
    render(<MitigationTable mitigations={MITIGATIONS} selectedPackageId="pypi:uwsgi@2.0.18" onSelectRow={() => {}} />);
    expand();
    expect(rowFor("uwsgi")).toHaveClass("selected-row");
    expect(rowFor("werkzeug")).not.toHaveClass("selected-row");
  });

  it("selecting a package not in the mitigation list highlights nothing, without erroring", () => {
    render(<MitigationTable mitigations={MITIGATIONS} selectedPackageId="npm:clean-package@1.0.0" onSelectRow={() => {}} />);
    expand();
    screen.getAllByTestId("mitigation-row").forEach((r) => expect(r).not.toHaveClass("selected-row"));
  });

  it("shows the explanation text for each row", () => {
    render(<MitigationTable mitigations={MITIGATIONS} selectedPackageId={null} onSelectRow={() => {}} />);
    expand();
    expect(rowFor("werkzeug")).toHaveTextContent(/critical CVE \(CVSS 9\.8\)/);
  });

  it("shows a 'no fix version found' fallback instead of breaking when fixed_version is missing", () => {
    const noFix = [{ ...MITIGATIONS[0], fixed_version: null, effort: null }];
    render(<MitigationTable mitigations={noFix} selectedPackageId={null} onSelectRow={() => {}} />);
    expand();
    expect(rowFor("werkzeug")).toHaveTextContent(/no fix version found/i);
  });

  it("column explanations are hidden by default and appear when the help toggle is clicked", () => {
    render(<MitigationTable mitigations={MITIGATIONS} selectedPackageId={null} onSelectRow={() => {}} />);
    expand();
    expect(screen.queryByText(/weighted blend of CVE severity/i)).not.toBeInTheDocument();
    fireEvent.click(screen.getByText(/what do these mean/i));
    expect(screen.getByText(/weighted blend of CVE severity/i)).toBeInTheDocument();
  });
});
