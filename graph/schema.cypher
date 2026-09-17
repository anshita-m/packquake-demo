// Run once against a fresh database (graph_builder.neo4j_writer.Neo4jWriter
// also issues these itself, idempotently, before every write).

CREATE CONSTRAINT app_id_unique IF NOT EXISTS
FOR (a:Application) REQUIRE a.app_id IS UNIQUE;

CREATE CONSTRAINT package_key_unique IF NOT EXISTS
FOR (p:Package) REQUIRE (p.name, p.version, p.ecosystem) IS UNIQUE;

CREATE CONSTRAINT vuln_id_unique IF NOT EXISTS
FOR (v:Vulnerability) REQUIRE v.vuln_id IS UNIQUE;
