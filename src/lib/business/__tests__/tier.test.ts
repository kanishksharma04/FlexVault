import { describe, it, expect } from "vitest";
import { tierForSalesCount, nextTierProgress } from "../tier";

describe("tierForSalesCount", () => {
  it("starts sellers at BRONZE", () => {
    expect(tierForSalesCount(0)).toBe("BRONZE");
    expect(tierForSalesCount(9)).toBe("BRONZE");
  });

  it("promotes at each threshold", () => {
    expect(tierForSalesCount(10)).toBe("SILVER");
    expect(tierForSalesCount(50)).toBe("GOLD");
    expect(tierForSalesCount(150)).toBe("PLATINUM");
  });
});

describe("nextTierProgress", () => {
  it("anchors currentTier to the value passed in, not the derived one", () => {
    // A seller flagged GOLD by an admin with very few actual sales should
    // still show as GOLD — the stored tier is authoritative.
    const result = nextTierProgress("GOLD", 1);
    expect(result.currentTier).toBe("GOLD");
    expect(result.nextTier).toBe("PLATINUM");
    expect(result.progressPct).toBe(0);
  });

  it("reports no next tier at PLATINUM", () => {
    const result = nextTierProgress("PLATINUM", 500);
    expect(result.nextTier).toBeNull();
    expect(result.progressPct).toBe(100);
  });

  it("computes progress toward the next tier", () => {
    const result = nextTierProgress("BRONZE", 5);
    expect(result.nextTier).toBe("SILVER");
    expect(result.salesToNext).toBe(5);
    expect(result.progressPct).toBe(50);
  });
});
