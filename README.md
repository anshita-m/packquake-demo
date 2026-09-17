# Ecosystem Dependency Risk Analysis System

Parses SBOMs from multiple applications into one shared Neo4j dependency
graph, enriches it with vulnerability data, and simulates supply-chain
compromise blast radius.

## Target applications

| app_id | stack | repo |
|---|---|---|
| `hackathon-starter` | Node/Express | github.com/sahat/hackathon-starter |
| `node-realworld` | Node/Express+TS | github.com/gothinkster/node-express-realworld-example-app |
| `microblog` | Python/Flask | github.com/miguelgrinberg/microblog |
| `flack` | Python/Flask+Celery | github.com/miguelgrinberg/flack |

`data/sbom/` holds real Syft-generated SBOMs (not planted data) -- see
[`data/sbom/README.md`](data/sbom/README.md) for provenance and the two
real-world Syft quirks the parser handles. `accepts@1.3.8` (npm) is a
package genuinely, naturally shared by `hackathon-starter` and
`node-realworld`'s real dependency trees, and is what the sanity checks and
CLI spotlights use to demonstrate fan-in/centrality/blast-radius. There's
currently no equivalent shared package between the two Python apps
(`microblog`/`flack`'s real pins don't overlap) -- see
`backend/graph_builder/cli.py`'s `SANITY_CHECKS` comment.

## Repo layout

```
backend/    graph_builder Python package (SBOM parsing/graph build + vuln enrichment + REST API) + tests
frontend/   React + Vite + cytoscape.js UI over the Phase 8 API
data/
  sbom/         one real Syft CycloneDX JSON per app, named <app_id>.json
  zap/          real ZAP scan JSON per app (not yet consumed by any phase)
  osv_cache/    cached OSV API responses (per package, per vuln id)
  nvd_cache/    cached NVD API responses (per CVE)
  epss_cache/   cached FIRST.org EPSS scores (per CVE)
graph/      Cypher schema + example queries
```

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e "backend[dev]"
```

## Phase 2: parse SBOMs, build the shared graph

```bash
# Parse only, print counts, run sanity checks
python -m graph_builder.cli --sbom-dir data/sbom

# Also load into Neo4j
docker-compose up -d
python -m graph_builder.cli --sbom-dir data/sbom --load-neo4j
```

Then open http://localhost:7474 (neo4j/password) and run the queries in
[`graph/queries.cypher`](graph/queries.cypher), e.g.:

```cypher
MATCH (a:Application)-[:DEPENDS_ON]->(p:Package {name:"accepts", version:"1.3.8"})
RETURN a, p
```

`data/sbom/*.json` are **real Syft output** (see
[`data/sbom/README.md`](data/sbom/README.md) for provenance). An earlier
synthetic placeholder generator,
[`scripts/generate_fixture_sboms.py`](scripts/generate_fixture_sboms.py),
is kept around for reference but is no longer the active data source.

## Phase 3: vulnerability enrichment

Queries OSV.dev (batched), falls back to NVD only when OSV has no CVSS,
pulls EPSS scores from FIRST.org (batched), and caches every raw response to
disk so re-runs while iterating on later phases don't hit these APIs live.

```bash
# Enrich every package, print counts + cache hit/miss stats
python -m graph_builder.enrich_cli --sbom-dir data/sbom

# Same, but also print what was found for one app specifically
python -m graph_builder.enrich_cli --sbom-dir data/sbom --app microblog

# Also load Vulnerability nodes + AFFECTED_BY edges into Neo4j
# (requires the Application/Package graph already loaded via Phase 2's --load-neo4j)
python -m graph_builder.enrich_cli --sbom-dir data/sbom --load-neo4j
```

An `NVD_API_KEY` environment variable, if set, is used automatically and
raises the NVD fallback's rate limit from ~5 to ~50 requests/30s.

**Cache state right now:** `data/osv_cache/` etc. only cover `flack`'s 46
packages (found 57 real vulnerabilities, e.g. `werkzeug@0.15.2` CVSS 9.8) --
enriched separately as a fast, targeted run rather than the full 628-package
graph. Run `enrich_cli` without `--app` to fill in the rest.

## Phase 4: structural metrics

Reads the graph back OUT of Neo4j (not from local SBOMs -- this operates on
whatever's actually persisted) into an in-memory `networkx.DiGraph`, computes
four properties per Package, and writes them back:

- `fan_in` -- how many apps depend on this package (direct or transitive)
- `depth` -- shallowest distance from any app's root to this package
- `betweenness_centrality` -- normalized, computed on the Package-only/
  REQUIRES-only subgraph (Application nodes and DEPENDS_ON edges excluded)
- `blast_radius_apps` -- the actual list of app_ids that would be affected
  if this package were compromised (walks REQUIRES in reverse to find every
  package that depends on it, then finds every app that depends on any of
  those)

```bash
docker-compose up -d
python -m graph_builder.cli --sbom-dir data/sbom --load-neo4j       # Package/Application nodes must exist first
python -m graph_builder.metrics_cli                                  # computes + writes back, prints a summary
python -m graph_builder.metrics_cli --dry-run                        # compute + print only, don't write
```

Note on centrality: a package with zero outgoing REQUIRES edges (a true
sink -- nothing it depends on, in this graph) can mathematically never show
nonzero `betweenness_centrality`, since it can never lie "between" two
other packages on a path. `accepts@1.3.8` does have real onward
dependencies (e.g. `mime-types`), so it shows a small but genuinely nonzero
value (~4.9e-05 in the current real graph) rather than a flat 0.0.

## Phase 5: compromise simulation

`simulate_compromise(graph, start_package_key, blocked_edges=None)` in
[`graph_builder/compromise_simulation.py`](backend/graph_builder/compromise_simulation.py)
propagates a hypothetical compromise of one package upward through REQUIRES
edges (to everything that depends on it, directly or transitively), and
reports which apps are affected. It shares one BFS implementation
([`graph_traversal.py`](backend/graph_builder/graph_traversal.py)) with
Phase 4's `blast_radius` -- `blast_radius` is that same traversal with no
blocking and the trace discarded; `simulate_compromise` is the general case
that also respects `blocks_propagation` on REQUIRES edges. It's a pure
function over the same in-memory graph Phase 4 reads once from Neo4j (no
per-call DB traversal), meant to be called repeatedly/on-demand -- Phase 8
will wrap it in `POST /simulate/:package_id`.

`blocks_propagation` is a v1, manually-set boolean on a REQUIRES edge
(absent = not blocked) -- e.g. "this package pins an incompatible exact
version, so a compromise upstream can't actually reach it." No automatic
version-compatibility detection yet.

```bash
# Flip (or clear) blocks_propagation on one REQUIRES edge
python -m graph_builder.propagation_cli set some-package@1.0.0@npm accepts@1.3.8@npm true
python -m graph_builder.propagation_cli get some-package@1.0.0@npm accepts@1.3.8@npm
```

```python
from graph_builder.compromise_simulation import simulate_compromise
from graph_builder.models import PackageKey

result = simulate_compromise(graph, PackageKey("accepts", "1.3.8", "npm"))
# {"compromised_packages": {...}, "compromised_apps": {...}, "trace": [(dependent, dependency), ...]}
```

## Phase 6: runtime exposure + composite risk score

`data/runtime_exposure.json` stands in for Netdata (see
[`data/runtime_exposure.README.md`](data/runtime_exposure.README.md) for
the reasoning behind the 4 apps' values) --
[`graph_builder/runtime_exposure.py`](backend/graph_builder/runtime_exposure.py)'s
`get_runtime_exposure(app_id)` combines `internet_facing` (weight 0.5),
`request_volume_normalized`, and `resource_criticality` (0.25 each) into
one 0-1 score; swapping in a real Netdata client later only means
replacing that module's private `_load_runtime_signals`, not any call
site. `runtime_exposure_for_package` propagates it to packages via `max`
over `blast_radius_apps` (not average -- one highly-exposed consumer
shouldn't get diluted by several safe ones).

[`graph_builder/risk_score.py`](backend/graph_builder/risk_score.py)
computes 5 raw factors per package (`cvss_normalized`, `exploitability`,
`centrality_normalized`, `blast_radius_ratio`, `runtime_exposure`, each
0-1) as pure functions, then `score_package(raw_factors, weights)` applies
`DEFAULT_WEIGHTS` (0.2 each) to get 5 weighted terms + `risk_score`. Both
the raw factors and the weighted terms get stored on the Package node, so
retuning weights later is a cheap re-sum over stored properties, not a
full pipeline rerun.

```bash
python -m graph_builder.risk_cli                                    # writes back, prints accepts@1.3.8 breakdown
python -m graph_builder.risk_cli --dry-run --package flask@3.0.0@pypi
```

## Phase 7: mitigation ranking

Patching a CVE is a **local recompute, not a graph recompute**: it doesn't
change who depends on a package, so `blast_radius`/`centrality`/
`runtime_exposure` are untouched -- only the two vulnerability-derived raw
factors (`cvss_normalized`, `exploitability`) get zeroed out.
[`graph_builder/mitigation_ranking.py`](backend/graph_builder/mitigation_ranking.py)'s
`rank_mitigations` reuses Phase 6's `score_package` directly for both the
before and after score (no second scoring implementation, no Neo4j/
networkx touched): `risk_reduction = risk_score_before - risk_score_after`.
Packages with zero `AFFECTED_BY` vulnerabilities are excluded entirely.

Patch effort (1=low/2=medium/3=high) comes from a plain split-and-compare
version-jump classifier
([`graph_builder/mitigation_effort.py`](backend/graph_builder/mitigation_effort.py),
not a semver parser) against whatever fixed version OSV's already-cached
data from Phase 3 names -- no network calls. `priority = risk_reduction /
effort`, falling back to `risk_reduction` alone when no fixed version is
cached; the whole list is always sorted by `priority` (that fallback makes
`priority` a plain number either way). Each entry also gets a one-sentence,
deterministic explanation naming its 1-2 largest actual contributing
factors (ranked by weighted-term magnitude, not hardcoded).

```bash
python -m graph_builder.mitigation_cli                              # top 10 by priority, with explanations
python -m graph_builder.mitigation_cli --top 20 --package werkzeug@0.15.2@pypi
```

The return shape is plain dicts/lists (JSON-serializable) -- Phase 8
exposes `rank_mitigations`'s output directly as `GET /mitigations`.

## Phase 8: REST API

FastAPI, wrapping Phases 3-7 read-only. The Neo4j-backed graph (Phase 4's
shape, with Phase 6's `risk_score`/`fan_in`/`betweenness_centrality`
merged onto each Package node -- see
[`graph_builder/api_data.py`](backend/graph_builder/api_data.py)) and the
Phase 7 mitigation ranking are both built **once**, at server startup
(FastAPI `lifespan`), and held in memory
([`graph_builder/api.py`](backend/graph_builder/api.py)'s `state`
singleton) for every request after that -- no request re-pulls from Neo4j
or rebuilds the networkx graph, so `POST /simulate` stays fast. To refresh
after re-running an earlier phase's pipeline, restart the server (no
hot-reload endpoint was built, per the plan's own steer to skip it for a
hackathon).

```bash
uvicorn graph_builder.api:app --reload   # from backend/, with Neo4j reachable
# then open http://localhost:8000/docs for Swagger UI
```

**Package ids** are `ecosystem:name@version`, e.g. `npm:lodash@4.17.21` or
`npm:@babel/helper-string-parser@7.29.7` (scoped npm names contain their
own `/`, which is why `/package/{id}` and `/simulate/{id}` use a `:path`
route parameter, not a plain segment). A curl example needs the id
percent-encoded if your shell would otherwise mangle the `@`/`:`/`/`:

```bash
curl http://localhost:8000/graph
curl http://localhost:8000/package/npm:lodash@4.17.21
curl -X POST http://localhost:8000/simulate/npm:lodash@4.17.21
curl -X POST http://localhost:8000/simulate/npm:lodash@4.17.21 \
  -H "Content-Type: application/json" \
  -d '{"blocked_edges": [["npm:some-package@1.0.0", "npm:lodash@4.17.21"]]}'
curl http://localhost:8000/mitigations
```

Every error response (400 malformed id, 404 unknown package, 422 bad
request body) uses the same `{"error": "..."}` shape -- not FastAPI's
default `{"detail": ...}` -- via a global exception handler. CORS is
enabled permissively (`allow_origins=["*"]`) for local dev so Phase 9's
frontend, a separate origin, doesn't hit a wall on its first fetch.

## Phase 9: frontend

React + Vite, [cytoscape.js](https://js.cytoscape.org/) via
`react-cytoscapejs` for the graph. Plain `fetch` + `useState`/`useEffect`,
no state-management library.

**The real graph is ~1,300+ package nodes** -- rendering it all at once
settles into an illegible hairball. So: the default view is just the 4
Application nodes. Clicking an app reveals its top ~20 packages by
`risk_score` (see [`frontend/src/graphUtils.js`](frontend/src/graphUtils.js)
for why it's "top 20 by risk" and not "direct dependencies" -- our real
data's `direct` flag doesn't actually narrow anything down, a Phase 2 Syft
quirk documented there and in `data/sbom/README.md`). Clicking a package
reveals its direct REQUIRES neighbors (one hop per click, both directions),
so the graph grows incrementally.

Node size and color both come from `risk_score`, via `d3-scale-chromatic`'s
`interpolateOrRd` -- a perceptually-uniform sequential scale, not a
red-green gradient (which fails for the most common forms of color
blindness). Clicking a package node fires `POST /simulate` and
`GET /package/:id` in parallel and drives three things off one shared
"selected package" state: the graph highlight (a border/glow overlay +
dashed trace edges -- deliberately layered on top of, not replacing, the
risk-score fill color), the reasoning panel (all 5 raw + weighted factors,
not just the final score), and the matching row in the mitigation table (a
package with no known vulnerability just has no matching row -- a normal
state, not an error). Clicking a mitigation table row does the same
selection in reverse.

```bash
cd frontend
npm install
npm run dev      # http://localhost:5173, expects the API at http://localhost:8000
npm test          # Vitest + React Testing Library, no backend needed
```

**A real environment blocker, not a code issue:** if this repo lives under
a path containing a literal `#` (as this one currently does --
`.../M# project/...`), **Vite's dev server, build, and Vitest will all
fail** ("Failed to load url /@vite/env", or spurious "missing dependency"
errors) -- Vite treats `#` as a URL fragment delimiter internally, and this
is a known upstream limitation (Vite prints its own warning about it), not
something fixable from `vite.config.js`. A symlink from a `#`-free path
doesn't help either -- Node resolves it back to the real path first. The
only fix is to run `npm install`/`npm run dev`/`npm test` from a copy (or
the repo itself, if you're willing to rename its parent directory) at a
path with no `#` in it. Everything in `frontend/` was verified working
this way (all 26 Vitest tests pass, `npm run build` succeeds, and a full
click-through against a running backend was done in a browser) from a
`#`-free copy -- the code itself is not the problem.

## Tests

```bash
cd backend && python -m pytest
```

Parsing/merge/dedup/sanity-check/CVSS-scoring/enrichment logic runs with
plain pytest against saved fixture JSON, no live database or network
required. `tests/test_neo4j_writer.py` and `tests/test_neo4j_vuln_writer.py`
verify the emitted Cypher and batching against a mocked driver.
`tests/test_api.py` tests the whole HTTP layer (status codes, JSON shape,
404s, the scoped-package-id-with-slash routing edge case, optional
`/simulate` body) by populating `graph_builder.api.state` directly and
using `TestClient` *without* its `with` block -- Starlette only runs
`lifespan` (which is what would reach for Neo4j) inside that block, so
these tests never touch a database.

Two things are marked `live` and deselected by default (see `addopts` in
`backend/pyproject.toml`) since they hit a real external service:

```bash
# real Neo4j (needs docker-compose up -d)
python -m pytest -m live tests/integration/test_neo4j_integration.py -v

# the actual API lifespan/startup path against real Neo4j
python -m pytest -m live tests/integration/test_api_live.py -v
```
