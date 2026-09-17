"""Phase 8: REST API wrapping Phases 3-7.

The graph and the mitigation ranking are built ONCE at startup (lifespan)
and held in this module's `state` singleton for the life of the process --
no request re-pulls from Neo4j or rebuilds the networkx graph. To refresh
after re-running an earlier phase's pipeline, restart the server (see
README; a hot-reload endpoint was deliberately not built for this).

Run it with:
    uvicorn graph_builder.api:app --reload

Set NO_NEO4J=1 to build the same state from local files instead (SBOMs +
the on-disk vulnerability caches already shipped in the repo) -- no
Neo4j/Docker needed, see local_state.py and the README.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Any

import networkx as nx
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel

from .api_data import PackageApiData, build_app_graph
from .compromise_simulation import simulate_compromise
from .mitigation_service import compute_ranked_mitigations
from .models import PackageKey
from .package_id import InvalidPackageId, from_package_id, to_package_id
from .risk_score import DEFAULT_WEIGHTS

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "password")
OSV_CACHE_DIR = os.environ.get("OSV_CACHE_DIR", "data/osv_cache")
NO_NEO4J = os.environ.get("NO_NEO4J", "").lower() in ("1", "true", "yes")
SBOM_DIR = os.environ.get("SBOM_DIR", "data/sbom")
DATA_DIR = os.environ.get("DATA_DIR", "data")


class AppState:
    """A plain module-level singleton rather than FastAPI's own app.state --
    simpler to read from route handlers (no Request injection needed
    everywhere) and just as easy for tests to populate directly, bypassing
    Neo4j entirely for HTTP-layer-only tests (see tests/test_api.py)."""

    def __init__(self) -> None:
        self.graph: nx.DiGraph | None = None
        self.package_data: dict[PackageKey, PackageApiData] = {}
        self.mitigations: list[dict] = []


state = AppState()


def load_state_from_neo4j(driver: Any) -> None:
    state.graph, state.package_data = build_app_graph(driver)
    state.mitigations, _total, _skipped = compute_ranked_mitigations(driver, OSV_CACHE_DIR, DEFAULT_WEIGHTS)


def load_state_from_local_files() -> None:
    from .local_state import load_state_from_local_files as _load

    state.graph, state.package_data, state.mitigations = _load(SBOM_DIR, DATA_DIR)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if NO_NEO4J:
        load_state_from_local_files()
        yield
        return

    from neo4j import GraphDatabase

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    try:
        load_state_from_neo4j(driver)
    finally:
        driver.close()  # nothing further needs the driver -- everything is now in-process memory
    yield


app = FastAPI(
    title="Ecosystem Dependency Risk Analysis API",
    description="Phase 8: read-only REST API over the Neo4j graph built by Phases 2-7.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # permissive for local dev -- Phase 9's frontend is a separate origin
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"error": "invalid request", "details": exc.errors()})


# --- response/request schemas ---

class GraphResponse(BaseModel):
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]


class VulnerabilityOut(BaseModel):
    id: str | None = None
    id_type: str | None = None
    cvss_score: float | None = None
    cvss_severity: str | None = None
    cvss_source: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None


class PackageDetailResponse(BaseModel):
    id: str
    name: str
    version: str
    ecosystem: str
    fan_in: int | None = None
    depth: int | None = None
    betweenness_centrality: float | None = None
    blast_radius_apps: list[str] = []
    vulnerabilities: list[VulnerabilityOut] = []
    raw_factors: dict[str, float] | None = None
    weighted_terms: dict[str, float] | None = None
    risk_score: float | None = None


class SimulateRequest(BaseModel):
    blocked_edges: list[tuple[str, str]] | None = None


class SimulateResponse(BaseModel):
    compromised_packages: list[dict[str, str]]
    compromised_apps: list[str]
    trace: list[dict[str, str]]


class MitigationsResponse(BaseModel):
    mitigations: list[dict[str, Any]]


# --- serialization helpers ---

def _application_node(app_id: str) -> dict:
    return {"id": app_id, "type": "application", "name": app_id}


def _package_node(pkg: PackageKey, data: dict) -> dict:
    return {
        "id": to_package_id(pkg),
        "type": "package",
        "name": pkg.name,
        "version": pkg.version,
        "ecosystem": pkg.ecosystem,
        "risk_score": data.get("risk_score"),
        "fan_in": data.get("fan_in"),
        "betweenness_centrality": data.get("betweenness_centrality"),
    }


def _node_id(node: str | PackageKey) -> str:
    return node if isinstance(node, str) else to_package_id(node)


def _edge_dict(u: Any, v: Any, data: dict) -> dict:
    edge = {"from": _node_id(u), "to": _node_id(v), "type": data.get("edge_type")}
    if data.get("edge_type") == "DEPENDS_ON":
        edge["direct"] = data.get("direct")
        edge["depth"] = data.get("depth")
    else:
        edge["blocks_propagation"] = data.get("blocks_propagation")
    return edge


def _require_graph() -> nx.DiGraph:
    if state.graph is None:
        raise HTTPException(status_code=503, detail="graph not loaded yet")
    return state.graph


def _parse_package_id_or_400(package_id: str) -> PackageKey:
    try:
        return from_package_id(package_id)
    except InvalidPackageId as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# --- routes ---

@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse(url="/docs")


@app.get("/graph", response_model=GraphResponse)
def get_graph() -> dict:
    graph = _require_graph()
    nodes = [
        _application_node(node) if data.get("node_type") == "application" else _package_node(node, data)
        for node, data in graph.nodes(data=True)
    ]
    edges = [_edge_dict(u, v, data) for u, v, data in graph.edges(data=True)]
    return {"nodes": nodes, "edges": edges}


@app.get("/package/{package_id:path}", response_model=PackageDetailResponse)
def get_package(package_id: str) -> dict:
    pkg = _parse_package_id_or_400(package_id)
    data = state.package_data.get(pkg)
    if data is None:
        raise HTTPException(status_code=404, detail="package not found")

    return {
        "id": to_package_id(pkg),
        "name": pkg.name,
        "version": pkg.version,
        "ecosystem": pkg.ecosystem,
        "fan_in": data.fan_in,
        "depth": data.depth,
        "betweenness_centrality": data.betweenness_centrality,
        "blast_radius_apps": data.blast_radius_apps,
        "vulnerabilities": data.vulnerabilities,
        "raw_factors": data.raw_factors,
        "weighted_terms": data.weighted_terms,
        "risk_score": data.risk_score,
    }


@app.post("/simulate/{package_id:path}", response_model=SimulateResponse)
def post_simulate(package_id: str, body: SimulateRequest | None = None) -> dict:
    pkg = _parse_package_id_or_400(package_id)
    graph = _require_graph()
    if pkg not in graph:
        raise HTTPException(status_code=404, detail="package not found")

    blocked_edges = None
    if body and body.blocked_edges:
        blocked_edges = set()
        for from_id, to_id in body.blocked_edges:
            blocked_edges.add((_parse_package_id_or_400(from_id), _parse_package_id_or_400(to_id)))

    result = simulate_compromise(graph, pkg, blocked_edges=blocked_edges)

    return {
        "compromised_packages": [
            {"id": to_package_id(p), "name": p.name, "version": p.version, "ecosystem": p.ecosystem}
            for p in result["compromised_packages"]
        ],
        "compromised_apps": sorted(result["compromised_apps"]),
        "trace": [{"from": to_package_id(a), "to": to_package_id(b)} for a, b in result["trace"]],
    }


@app.get("/mitigations", response_model=MitigationsResponse)
def get_mitigations() -> dict:
    return {"mitigations": state.mitigations}
