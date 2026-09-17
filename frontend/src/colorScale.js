// risk_score (0-1) -> node size + color. Uses d3-scale-chromatic's
// interpolateOrRd, a perceptually-uniform sequential scale (pale yellow ->
// strong red) instead of a red-green gradient, which fails for the most
// common forms of color blindness -- a bad choice for exactly the kind of
// "risk" visualization this is.

import { interpolateOrRd } from "d3-scale-chromatic";

// Bumped up from the original 20/64: the graph is the main focus of the
// page now, rendered much larger, with package names always visible
// (not hover-only) -- small circles made those permanent labels crowd
// into each other.
const MIN_SIZE = 34;
const MAX_SIZE = 88;

export function riskScoreToStyle(riskScore) {
  const clamped = Math.max(0, Math.min(1, riskScore ?? 0));
  return {
    size: MIN_SIZE + clamped * (MAX_SIZE - MIN_SIZE),
    color: interpolateOrRd(0.15 + clamped * 0.85), // avoid the near-white bottom of the scale, which is unreadable on a light background
  };
}

// Evenly-spaced stops for rendering a legend gradient bar in CSS.
export const LEGEND_GRADIENT_STOPS = Array.from({ length: 6 }, (_, i) => {
  const t = i / 5;
  return interpolateOrRd(0.15 + t * 0.85);
});
