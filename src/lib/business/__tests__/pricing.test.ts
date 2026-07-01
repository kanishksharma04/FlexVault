import { describe, it, expect } from "vitest";
import { suggestPriceRange } from "../pricing";

describe("suggestPriceRange", () => {
  it("returns zeros with a message when there is no comp data", () => {
    const result = suggestPriceRange([], 50);
    expect(result).toEqual({ low: 0, mid: 0, high: 0, basis: "No recent sales data available yet." });
  });

  it("centers the suggestion on the median at a neutral trend score", () => {
    const result = suggestPriceRange([1000, 1000, 1000], 50);
    expect(result.mid).toBe(1000);
    expect(result.low).toBeLessThan(result.mid);
    expect(result.high).toBeGreaterThan(result.mid);
  });

  it("nudges the price up for a hot trend score", () => {
    const cold = suggestPriceRange([1000, 1000, 1000], 0);
    const hot = suggestPriceRange([1000, 1000, 1000], 100);
    expect(hot.mid).toBeGreaterThan(cold.mid);
  });

  it("keeps the trend swing within +/-15% of the median", () => {
    const median = 1000;
    const hot = suggestPriceRange([median], 100);
    const cold = suggestPriceRange([median], 0);
    expect(hot.mid).toBeLessThanOrEqual(median * 1.15);
    expect(cold.mid).toBeGreaterThanOrEqual(median * 0.85);
  });
});
