// Thin fetch wrapper over Phase 8's 4 endpoints. Package ids look like
// "npm:lodash@4.17.21" (or "npm:@babel/helper-string-parser@7.29.7" for
// scoped npm names, which contain their own "/") -- always encodeURIComponent
// one before putting it in a path, per Phase 8's README.

const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8000";

class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function requestJson(path, options) {
  const res = await fetch(`${API_BASE}${path}`, options);
  if (!res.ok) {
    let message = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body?.error) message = body.error;
    } catch {
      // body wasn't JSON -- keep the generic message
    }
    throw new ApiError(message, res.status);
  }
  return res.json();
}

export function packageKeyToId({ name, version, ecosystem }) {
  return `${ecosystem}:${name}@${version}`;
}

export function getGraph() {
  return requestJson("/graph");
}

export function getPackage(packageId) {
  return requestJson(`/package/${encodeURIComponent(packageId)}`);
}

export function simulate(packageId, blockedEdges) {
  const hasBody = blockedEdges && blockedEdges.length > 0;
  return requestJson(`/simulate/${encodeURIComponent(packageId)}`, {
    method: "POST",
    headers: hasBody ? { "Content-Type": "application/json" } : undefined,
    body: hasBody ? JSON.stringify({ blocked_edges: blockedEdges }) : undefined,
  });
}

export function getMitigations() {
  return requestJson("/mitigations");
}

export { ApiError };
