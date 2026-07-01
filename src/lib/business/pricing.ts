/**
 * Heuristic price suggestion: blends recent sold comps with a trend-score
 * premium/discount. Not an ML model — a transparent, explainable formula
 * a seller can sanity-check against comps.
 */
export function suggestPriceRange(
  recentSoldPrices: number[],
  trendScore: number
): { low: number; mid: number; high: number; basis: string } {
  if (recentSoldPrices.length === 0) {
    return { low: 0, mid: 0, high: 0, basis: "No recent sales data available yet." };
  }

  const sorted = [...recentSoldPrices].sort((a, b) => a - b);
  const median = sorted[Math.floor(sorted.length / 2)];

  // Trend score above 50 nudges price up, below 50 nudges it down.
  // Max swing is +/-15% at score 100/0.
  const trendMultiplier = 1 + ((trendScore - 50) / 50) * 0.15;

  const mid = Math.round(median * trendMultiplier);
  const low = Math.round(mid * 0.9);
  const high = Math.round(mid * 1.12);

  return {
    low,
    mid,
    high,
    basis: `Based on ${recentSoldPrices.length} recent sale${recentSoldPrices.length === 1 ? "" : "s"} (median ₹${median.toLocaleString("en-IN")}) adjusted for a trend score of ${trendScore}.`,
  };
}
