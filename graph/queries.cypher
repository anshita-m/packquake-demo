// Example / verification queries for the Phase 2 graph.
// Open at http://localhost:7474 after `docker-compose up -d` + a
// `--load-neo4j` run.

// Verify the accepts@1.3.8 fan-in sanity check visually (expect 2 apps:
// hackathon-starter, node-realworld -- a real package naturally shared by
// both Syft scans, not a planted pin).
MATCH (a:Application)-[:DEPENDS_ON]->(p:Package {name: "accepts", version: "1.3.8"})
RETURN a, p;

// Every package a given app depends on, direct vs transitive.
MATCH (a:Application {app_id: "microblog"})-[r:DEPENDS_ON]->(p:Package)
RETURN p.name, p.version, p.ecosystem, r.direct, r.depth
ORDER BY r.depth, p.name;

// Packages shared by 2+ applications (the demo-worthy nodes).
MATCH (a:Application)-[:DEPENDS_ON]->(p:Package)
WITH p, count(DISTINCT a) AS app_count
WHERE app_count > 1
RETURN p.name, p.version, p.ecosystem, app_count
ORDER BY app_count DESC;

// --- Phase 3: vulnerability enrichment ---

// Every known CVE/GHSA affecting a given app's packages, most severe first.
MATCH (a:Application {app_id: "microblog"})-[:DEPENDS_ON]->(p:Package)-[:AFFECTED_BY]->(v:Vulnerability)
RETURN p.name, p.version, v.vuln_id, v.cvss_score, v.cvss_severity, v.epss_score
ORDER BY v.cvss_score DESC;

// Highest blast-radius vulnerabilities: how many apps does each CVE reach
// (through any package that carries it)?
MATCH (a:Application)-[:DEPENDS_ON]->(p:Package)-[:AFFECTED_BY]->(v:Vulnerability)
WITH v, count(DISTINCT a) AS app_count
RETURN v.vuln_id, v.cvss_score, v.epss_score, app_count
ORDER BY app_count DESC, v.cvss_score DESC;

// --- Phase 4: structural metrics ---

// The naturally-shared package's computed metrics.
MATCH (p:Package {name: "accepts", version: "1.3.8"})
RETURN p.name, p.version, p.fan_in, p.depth, p.betweenness_centrality, p.blast_radius_apps;

// Most structurally central packages (highest betweenness) -- the ones
// that, if compromised, sit on the most shortest paths through the shared
// dependency web.
MATCH (p:Package)
RETURN p.name, p.version, p.ecosystem, p.betweenness_centrality, p.fan_in, p.blast_radius_apps
ORDER BY p.betweenness_centrality DESC
LIMIT 10;

// Widest blast radius: packages whose compromise would reach the most apps.
MATCH (p:Package)
RETURN p.name, p.version, p.ecosystem, size(p.blast_radius_apps) AS apps_affected, p.blast_radius_apps
ORDER BY apps_affected DESC
LIMIT 10;

// --- Phase 5: compromise simulation ---

// The actual simulation runs in-memory (python -m graph_builder.propagation_cli
// / graph_builder.compromise_simulation.simulate_compromise), not as a Cypher
// traversal -- these are just for inspecting REQUIRES edges directly.

// Every REQUIRES edge with a blocks_propagation flag set (manually, via
// propagation_cli) -- the mitigations currently modeled.
MATCH (dependent:Package)-[r:REQUIRES]->(dependency:Package)
WHERE r.blocks_propagation = true
RETURN dependent.name, dependent.version, dependency.name, dependency.version;

// Who directly requires a given package (one hop of the reverse walk
// simulate_compromise does in full, transitively, in memory).
MATCH (dependent:Package)-[r:REQUIRES]->(dependency:Package {name: "accepts", version: "1.3.8"})
RETURN dependent.name, dependent.version, r.blocks_propagation;
