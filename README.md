# PACKQUAKE

**Ecosystem Dependency Risk Analysis** — parses SBOMs from multiple
applications into one shared Neo4j dependency graph, enriches every
package with real vulnerability data (OSV/NVD/EPSS), scores each one's
risk, simulates how a compromise would propagate through the dependency
graph, and ranks the highest-value patches to apply first. A React +
cytoscape.js frontend lets you explore the graph, click into any package
to see why it's risky, and watch a simulated compromise spread.

## How it works

1. **Parse & merge** — real Syft SBOMs for each app are parsed and merged
   into one shared graph (`Application` / `Package` nodes, `DEPENDS_ON` /
   `REQUIRES` edges), deduping a naturally-shared dependency like
   `accepts@1.3.8` into a single node with edges from every app that uses
   it.
2. **Enrich** — every package is checked against OSV.dev (falling back to
   NVD for CVSS) and FIRST.org's EPSS model, with every response cached to
   disk.
3. **Structural metrics** — fan-in, depth from any app root, betweenness
   centrality, and blast radius (which apps would be affected) are
   computed over the graph with networkx.
4. **Risk scoring** — five factors (CVE severity, exploit probability,
   structural centrality, blast radius, runtime exposure) are combined
   into one weighted `risk_score` per package.
5. **Compromise simulation** — given a starting package, walks the
   dependency graph in reverse to find every package and app that would
   be affected, respecting a manually-settable "blocks propagation" flag
   on individual edges.
6. **Mitigation ranking** — for every package with a known CVE, computes
   how much `risk_score` would drop if it were patched, divides by a
   rough patch-effort estimate, and ranks the result.
7. **API + frontend** — a FastAPI backend exposes all of the above
   read-only; the React frontend renders the graph, a reasoning panel per
   package, and a mitigation priority table.

## Target applications

| app_id | stack | repo |
|---|---|---|
| `hackathon-starter` | Node/Express | github.com/sahat/hackathon-starter |
| `node-realworld` | Node/Express+TS | github.com/gothinkster/node-express-realworld-example-app |
| `microblog` | Python/Flask | github.com/miguelgrinberg/microblog |
| `flack` | Python/Flask+Celery | github.com/miguelgrinberg/flack |

All SBOM/ZAP data under `data/` is real scanner output, not synthetic
fixtures — see [`data/sbom/README.md`](data/sbom/README.md) for
provenance.

## How to run

### Quickest: no Docker, no Neo4j

The repo ships with the real dataset's vulnerability lookups already
cached under `data/` (`osv_cache/`, `nvd_cache/`, `epss_cache/`), so
`NO_NEO4J=1` builds the exact same graph/scores/mitigations directly from
local files — no database, no Docker, no live network calls.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e "backend[dev]"

NO_NEO4J=1 uvicorn graph_builder.api:app --reload
# -> http://localhost:8000/docs for Swagger UI

# in a new terminal
cd frontend
npm install
npm run dev
# -> http://localhost:5173
```

That's the whole thing — clone, install, run those two servers, open the
frontend.

### With Neo4j (persistent graph database)

Only needed if you actually want the graph sitting in Neo4j (e.g. to run
the Cypher queries in [`graph/queries.cypher`](graph/queries.cypher)
yourself, or to re-run the pipeline against different SBOMs).

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e "backend[dev]"

docker-compose up -d

# parse SBOMs, enrich with vuln data, compute structural metrics and risk
# scores -- run from the repo root, cache/data paths default relative to it
python -m graph_builder.cli --sbom-dir data/sbom --load-neo4j
python -m graph_builder.enrich_cli --sbom-dir data/sbom --load-neo4j
python -m graph_builder.metrics_cli
python -m graph_builder.risk_cli

uvicorn graph_builder.api:app --reload    # no NO_NEO4J this time

cd frontend && npm install && npm run dev
```

Mitigation ranking doesn't need a separate load step either way — the API
computes it once at startup from whatever state it loaded. An
`NVD_API_KEY` env var is picked up automatically if set and raises NVD's
rate limit (only relevant if you're re-enriching against live APIs).

**If your checkout's path contains a `#`**, Vite's dev server/build/test
will fail (`#` is a URL fragment delimiter to Vite — a known upstream
limitation, not fixable from config, and a symlink from a `#`-free path
doesn't help since Node resolves it back to the real path). Run
`npm install`/`npm run dev`/`npm test` from a copy of `frontend/` at a
path without one.

## Repo layout

```
backend/    graph_builder Python package (SBOM parsing, graph build, vuln
            enrichment, risk scoring, mitigation ranking, REST API) + tests
frontend/   React + Vite + cytoscape.js UI over the API
data/
  sbom/         real Syft CycloneDX JSON per app
  zap/          real ZAP scan JSON per app
  osv_cache/    cached OSV API responses
  nvd_cache/    cached NVD API responses
  epss_cache/   cached FIRST.org EPSS scores
graph/      Cypher schema + example queries
```

## Tests

```bash
cd backend && python -m pytest        # no live DB/network needed
cd frontend && npm test               # Vitest + React Testing Library
```

Two backend tests are marked `live` and skipped by default since they hit
a real Neo4j instance:

```bash
python -m pytest -m live tests/integration/test_neo4j_integration.py -v
python -m pytest -m live tests/integration/test_api_live.py -v
```
