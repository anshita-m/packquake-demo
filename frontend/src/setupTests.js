import "@testing-library/jest-dom/vitest";

// jsdom doesn't implement scrollIntoView; MitigationTable calls it when the
// selected row changes, so stub it out to avoid "not implemented" noise.
if (typeof Element !== "undefined" && !Element.prototype.scrollIntoView) {
  Element.prototype.scrollIntoView = () => {};
}

