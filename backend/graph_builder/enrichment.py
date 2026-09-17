"""Orchestrates OsvClient + NvdClient + EpssClient + vuln_parse.py into a
VulnGraph for every Package in a Graph.

Takes the three clients as constructor-injected dependencies (not imported
directly) so this can be tested with fakes -- no network, no disk -- while
the clients themselves are tested separately against fixture/live data.
"""

from __future__ import annotations

import logging
from dataclasses import replace

from .models import Graph, PackageKey, VulnGraph, Vulnerability
from .vuln_parse import extract_cvss_from_nvd, extract_cvss_from_osv, extract_epss, extract_identity

logger = logging.getLogger(__name__)


def enrich_graph(graph: Graph, osv_client, nvd_client, epss_client) -> VulnGraph:
    packages = sorted(graph.packages, key=lambda p: (p.ecosystem, p.name, p.version))

    stubs_by_package = osv_client.query_vuln_stubs(packages)
    all_vuln_ids = {stub["id"] for stubs in stubs_by_package.values() for stub in stubs}
    details_by_id = osv_client.get_vuln_details(all_vuln_ids)

    vulns: dict[str, Vulnerability] = {}
    affected_by: set[tuple[PackageKey, str]] = set()

    for package, stubs in stubs_by_package.items():
        for stub in stubs:
            detail = details_by_id.get(stub["id"])
            if detail is None:
                continue  # 404 or paginated-away; osv_client already logged it

            cve_id, ghsa_id = extract_identity(detail)
            vuln_key = cve_id or ghsa_id
            if vuln_key is None:
                logger.warning(
                    "OSV vuln %r affecting %s@%s has neither a CVE nor a GHSA "
                    "id; skipping.", stub["id"], package.name, package.version,
                )
                continue

            affected_by.add((package, vuln_key))

            if vuln_key not in vulns:
                cvss = extract_cvss_from_osv(detail)
                vulns[vuln_key] = Vulnerability(
                    vuln_id=vuln_key,
                    id_type="cve" if cve_id else "ghsa",
                    cvss_score=cvss.score if cvss else None,
                    cvss_severity=cvss.severity if cvss else None,
                    cvss_source=cvss.source if cvss else None,
                )
            elif vulns[vuln_key].cvss_score is None:
                # Same CVE, a different OSV id (e.g. a PYSEC twin of a GHSA
                # advisory) might carry CVSS data the first one we saw didn't.
                cvss = extract_cvss_from_osv(detail)
                if cvss:
                    vulns[vuln_key] = replace(
                        vulns[vuln_key], cvss_score=cvss.score, cvss_severity=cvss.severity, cvss_source=cvss.source,
                    )

    _fill_missing_cvss_from_nvd(vulns, nvd_client)
    _fill_epss_scores(vulns, epss_client)

    return VulnGraph(vulnerabilities=vulns, affected_by=affected_by)


def _fill_missing_cvss_from_nvd(vulns: dict[str, Vulnerability], nvd_client) -> None:
    for key, vuln in list(vulns.items()):
        if vuln.cvss_score is not None or vuln.id_type != "cve":
            continue  # GHSA-only vulns have no CVE to look up in NVD
        nvd_response = nvd_client.get_cve(key)
        if not nvd_response:
            continue
        cvss = extract_cvss_from_nvd(nvd_response)
        if cvss:
            vulns[key] = replace(vuln, cvss_score=cvss.score, cvss_severity=cvss.severity, cvss_source=cvss.source)


def _fill_epss_scores(vulns: dict[str, Vulnerability], epss_client) -> None:
    cve_keys = [key for key, v in vulns.items() if v.id_type == "cve"]
    if not cve_keys:
        return
    epss_rows = epss_client.get_scores(cve_keys)
    for key in cve_keys:
        epss = extract_epss(epss_rows.get(key))
        if epss:
            score, percentile = epss
            vulns[key] = replace(vulns[key], epss_score=score, epss_percentile=percentile)
