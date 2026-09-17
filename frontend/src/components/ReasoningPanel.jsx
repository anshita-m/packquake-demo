import {
  centralityRoleLabel,
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
} from "../format";
import { riskScoreToStyle } from "../colorScale";
import "./ReasoningPanel.css";

// Order controls display order -- roughly "why is this risky", not the
// arbitrary dict order the API returns. `explain` turns the raw factor into
// a plain-language sentence -- that sentence is the primary content of each
// card now; the raw/weighted numbers are still shown, but small and second.
const FACTOR_ROWS = [
  ["cvss_normalized", "CVSS severity", (ctx) => explainCvss(ctx.raw_factors?.cvss_normalized, ctx.hasVulns)],
  ["exploitability", "Exploitability (EPSS)", (ctx) => explainExploitability(ctx.raw_factors?.exploitability, ctx.hasVulns)],
  ["blast_radius_ratio", "Blast radius", (ctx) => explainBlastRadius(ctx.blast_radius_apps)],
  [
    "centrality_normalized",
    "Structural centrality",
    (ctx) => explainCentrality(ctx.betweenness_centrality, percentileRank(ctx.allStats?.centralities, ctx.betweenness_centrality)),
  ],
  ["runtime_exposure", "Runtime exposure", (ctx) => explainRuntimeExposure(ctx.raw_factors?.runtime_exposure)],
];

function VulnRow({ v }) {
  const cvss = v.cvss_score != null ? `${v.cvss_score.toFixed(1)}${v.cvss_severity ? ` (${v.cvss_severity})` : ""}` : "not yet scored";
  const isCve = v.id_type === "cve";
  const epss = !isCve ? "N/A (no CVE)" : v.epss_score != null ? formatPercent(v.epss_score, 1) : "not yet scored";
  return (
    <li>
      <div className="vuln-id">
        {v.id ?? "unknown id"} <span className="vuln-type-badge">{v.id_type ?? "?"}</span>
      </div>
      <div className="vuln-meta">
        CVSS: <strong>{cvss}</strong> &nbsp;·&nbsp; EPSS: <strong>{epss}</strong>
      </div>
    </li>
  );
}

export default function ReasoningPanel({ packageDetail, loading, error, selectedPackageId, allStats, onClose }) {
  if (!selectedPackageId) return null;

  return (
    <div className="reasoning-drawer" data-testid="reasoning-panel">
      <button type="button" className="drawer-close" onClick={onClose} aria-label="Close">
        ×
      </button>

      {loading && <div className="drawer-status">Loading…</div>}
      {!loading && (error || !packageDetail) && (
        <div className="drawer-status error">Couldn't load details for this package{error ? `: ${error}` : "."}</div>
      )}

      {!loading && packageDetail && !error && (
        <PackageDetailBody packageDetail={packageDetail} allStats={allStats} />
      )}
    </div>
  );
}

function PackageDetailBody({ packageDetail, allStats }) {
  const {
    name,
    version,
    ecosystem,
    risk_score,
    raw_factors,
    weighted_terms,
    vulnerabilities = [],
    blast_radius_apps = [],
    fan_in,
    depth,
    betweenness_centrality,
  } = packageDetail;

  const { color: riskColor } = riskScoreToStyle(risk_score ?? 0);
  const riskPercentile = percentileRank(allStats?.riskScores, risk_score);
  const centralityPercentile = percentileRank(allStats?.centralities, betweenness_centrality);
  const hasVulns = vulnerabilities.length > 0;

  // Every explain() function keys off this shared context object instead of
  // its own long argument list.
  const explainCtx = { raw_factors, hasVulns, blast_radius_apps, betweenness_centrality, allStats };

  // Max possible weighted contribution per factor, for the contribution
  // bars below -- all 5 factors are weighted equally (0.2), so this is the
  // same denominator for every row.
  const maxWeight = 0.2;

  return (
    <div className="drawer-body">
      <div className="drawer-header">
        <h2>
          {name}
          <span className="version-tag">@{version}</span>
        </h2>
        <span className="ecosystem-badge">{ecosystem}</span>
      </div>

      <div className="risk-score-card" style={{ borderColor: riskColor }}>
        <div className="risk-score-value" style={{ color: riskColor }}>
          {formatNumber(risk_score)}
        </div>
        <div className="risk-score-label">
          {riskLabel(risk_score)} risk
          {riskPercentile != null && <span className="dim"> · {percentilePhrase(allStats?.riskScores, risk_score)}</span>}
        </div>
      </div>

      {/* The single most important "what happens if this breaks" fact,
          called out in big text -- previously a small unstyled paragraph
          buried at the bottom of the structural-facts section. */}
      <div className={`impact-banner ${blast_radius_apps.length > 0 ? "impact-active" : "impact-none"}`}>
        {blast_radius_apps.length > 0 ? (
          <>
            <span className="impact-icon">⚠</span>
            <span>
              Would affect <strong>{blast_radius_apps.join(", ")}</strong>
            </span>
          </>
        ) : (
          <span>Not known to directly affect any application.</span>
        )}
      </div>

      <section>
        <h3>What's driving this score</h3>
        {raw_factors ? (
          <ul className="factor-list" data-testid="factor-table">
            {FACTOR_ROWS.map(([key, label, explain]) => {
              const isVulnFactor = key === "cvss_normalized" || key === "exploitability";
              const noVulnData = isVulnFactor && !hasVulns;
              const weighted = weighted_terms?.[key];
              const barPct = weighted != null ? Math.min(100, Math.max(0, (weighted / maxWeight) * 100)) : 0;
              return (
                <li key={key} className="factor-card">
                  <div className="factor-card-top">
                    <span className="factor-label">{label}</span>
                    <span className="factor-raw dim">
                      {noVulnData ? (
                        <span className="no-data">no known CVEs</span>
                      ) : (
                        <>
                          raw {key === "centrality_normalized" ? formatSmallNumber(raw_factors[key]) : formatNumber(raw_factors[key])}
                          {" · weighted "}
                          {formatSmallNumber(weighted, 4)}
                        </>
                      )}
                    </span>
                  </div>
                  <p className="factor-explanation">{explain(explainCtx)}</p>
                  <div className="contribution-bar-track" title={`Contributes ${formatSmallNumber(weighted, 4)} of the 0-1 risk score`}>
                    <div className="contribution-bar-fill" style={{ width: `${noVulnData ? 0 : barPct}%` }} />
                  </div>
                </li>
              );
            })}
          </ul>
        ) : (
          <p className="note">No risk score computed yet for this package.</p>
        )}
      </section>

      <section>
        <h3>Vulnerabilities ({vulnerabilities.length})</h3>
        {vulnerabilities.length === 0 ? (
          <p className="note good">✓ No known vulnerabilities.</p>
        ) : (
          <ul className="vuln-list" data-testid="vuln-list">
            {vulnerabilities.map((v) => (
              <VulnRow key={v.id ?? Math.random()} v={v} />
            ))}
          </ul>
        )}
      </section>

      <section>
        <h3>Structural facts</h3>
        <div className="stat-grid">
          <div className="stat-tile">
            <div className="stat-value">{fan_in ?? "—"}</div>
            <div className="stat-caption">app(s) depend on this (fan-in)</div>
          </div>
          <div className="stat-tile">
            <div className="stat-value">{depth ?? "—"}</div>
            <div className="stat-caption">shortest depth from any app root</div>
          </div>
          <div className="stat-tile">
            <div className="stat-value">{centralityRoleLabel(betweenness_centrality, centralityPercentile)}</div>
            <div className="stat-caption">structural role</div>
          </div>
          <div className="stat-tile">
            <div className="stat-value">{blast_radius_apps.length}</div>
            <div className="stat-caption">app(s) in blast radius</div>
          </div>
        </div>
      </section>
    </div>
  );
}
