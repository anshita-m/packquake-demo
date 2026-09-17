import { useEffect, useMemo, useRef, useState } from "react";
import { packageKeyToId } from "../api";
import { effortMeta, formatNumber, riskLabel } from "../format";
import { riskScoreToStyle } from "../colorScale";
import "./MitigationTable.css";

// Order here drives both the header row AND the <td> order below --
// they must stay in sync (current state before the hypothetical
// "if fixed" state reads more naturally too).
const SORTABLE_COLUMNS = [
  ["risk_score_before", "Current risk"],
  ["risk_reduction", "If fixed"],
];

const COLUMN_HELP = [
  ["Package", "The vulnerable package, and the app(s) it's used in."],
  ["Current risk", "Its risk_score right now (0-1): a weighted blend of CVE severity, exploit probability, structural centrality, blast radius, and runtime exposure."],
  ["If fixed", "How much risk_score would drop if every known CVE on this package were resolved -- everything else (centrality, blast radius, exposure) stays the same, since patching a CVE doesn't change who depends on the package."],
  ["Recommended fix", "The lowest version that resolves the worst known CVE, and roughly how disruptive that upgrade is."],
  ["Why", "The 1-2 factors driving this package's risk score the most."],
];

export default function MitigationTable({ mitigations, selectedPackageId, onSelectRow }) {
  const [sortField, setSortField] = useState("risk_reduction");
  const [sortDir, setSortDir] = useState("desc");
  const [showHelp, setShowHelp] = useState(false);
  // Collapsed by default: the dependency graph is the main part of the
  // page, this is a secondary/"extra" section a user opts into expanding.
  const [collapsed, setCollapsed] = useState(true);
  const rowRefs = useRef({});

  const sorted = useMemo(() => {
    const copy = [...mitigations];
    copy.sort((a, b) => {
      const diff = (a[sortField] ?? 0) - (b[sortField] ?? 0);
      return sortDir === "asc" ? diff : -diff;
    });
    return copy;
  }, [mitigations, sortField, sortDir]);

  useEffect(() => {
    const row = selectedPackageId && rowRefs.current[selectedPackageId];
    if (row) {
      row.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  }, [selectedPackageId, sorted]);

  function handleHeaderClick(field) {
    if (field === sortField) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortField(field);
      setSortDir("desc");
    }
  }

  return (
    <div className={`mitigation-table ${collapsed ? "collapsed" : ""}`} data-testid="mitigation-table">
      <div
        className="mitigation-table-header"
        onClick={() => setCollapsed((c) => !c)}
        onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && setCollapsed((c) => !c)}
        role="button"
        tabIndex={0}
        aria-expanded={!collapsed}
      >
        <h2>
          <span className="collapse-chevron">{collapsed ? "▸" : "▾"}</span>
          Mitigation priorities {mitigations.length > 0 && <span className="count-badge">{mitigations.length}</span>}
        </h2>
        <span className="collapse-hint">{collapsed ? "Show" : "Hide"}</span>
      </div>

      {!collapsed && (
        <div className="mitigation-table-body">
          <div className="help-row">
            <button
              type="button"
              className="help-toggle"
              onClick={(e) => {
                e.stopPropagation();
                setShowHelp((s) => !s);
              }}
            >
              {showHelp ? "Hide" : "ⓘ What do these mean?"}
            </button>
          </div>

          {showHelp && (
            <dl className="column-help">
              {COLUMN_HELP.map(([col, text]) => (
                <div key={col} className="column-help-row">
                  <dt>{col}</dt>
                  <dd>{text}</dd>
                </div>
              ))}
            </dl>
          )}

          {mitigations.length === 0 ? (
            <p className="note">No vulnerable packages found.</p>
          ) : (
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Package</th>
                    {SORTABLE_COLUMNS.map(([field, label]) => (
                      <th key={field} className="sortable" onClick={() => handleHeaderClick(field)}>
                        {label}
                        {sortField === field ? (sortDir === "asc" ? " ▲" : " ▼") : ""}
                      </th>
                    ))}
                    <th>Recommended fix</th>
                    <th>Why</th>
                  </tr>
                </thead>
                <tbody>
                  {sorted.map((m) => {
                    const id = packageKeyToId(m.package);
                    const isSelected = id === selectedPackageId;
                    const { color: riskColor } = riskScoreToStyle(m.risk_score_before);
                    const { label: effortLabel, color: effortColor } = effortMeta(m.effort);
                    return (
                      <tr
                        key={id}
                        ref={(el) => {
                          rowRefs.current[id] = el;
                        }}
                        className={isSelected ? "selected-row" : ""}
                        onClick={() => onSelectRow(id)}
                        data-testid="mitigation-row"
                      >
                        <td className="package-cell">
                          <div className="package-name">
                            {m.package.name}
                            <span className="package-version">@{m.package.version}</span>
                          </div>
                          <div className="package-ecosystem">{m.package.ecosystem}</div>
                        </td>
                        <td>
                          <span className="risk-badge" style={{ backgroundColor: riskColor }}>
                            {formatNumber(m.risk_score_before, 2)}
                          </span>
                          <div className="risk-badge-caption">{riskLabel(m.risk_score_before)}</div>
                        </td>
                        <td className="reduction-cell">−{formatNumber(m.risk_reduction, 2)}</td>
                        <td>
                          {m.fixed_version ? (
                            <div className="fix-cell">
                              <div className="fix-version">Upgrade to {m.fixed_version}</div>
                              <span className="effort-badge" style={{ color: effortColor, borderColor: effortColor }}>
                                {effortLabel}
                              </span>
                            </div>
                          ) : (
                            <span className="no-data">no fix version found</span>
                          )}
                        </td>
                        <td className="explanation-cell">{m.explanation}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
