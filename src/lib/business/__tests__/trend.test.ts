import { describe, it, expect } from "vitest";
import { calcTrendScore, trendTemperature, trendReasonSummary } from "../trend";

describe("calcTrendScore", () => {
  it("applies the weighted formula with default weights", () => {
    const score = calcTrendScore({ mentionVelocity: 100, sentimentScore: 100, engagementGrowth: 100 });
    expect(score).toBe(100);
  });

  it("weights each input independently", () => {
    const score = calcTrendScore(
      { mentionVelocity: 100, sentimentScore: 0, engagementGrowth: 0 },
      { mentionVelocityWeight: 0.5, sentimentWeight: 0.3, engagementWeight: 0.2 }
    );
    expect(score).toBe(50);
  });

  it("clamps to the 0-100 range", () => {
    expect(calcTrendScore({ mentionVelocity: 0, sentimentScore: 0, engagementGrowth: 0 })).toBe(0);
    expect(
      calcTrendScore(
        { mentionVelocity: 1000, sentimentScore: 1000, engagementGrowth: 1000 },
        { mentionVelocityWeight: 1, sentimentWeight: 1, engagementWeight: 1 }
      )
    ).toBe(100);
  });
});

describe("trendTemperature", () => {
  it("buckets scores into cold/warm/hot/blazing", () => {
    expect(trendTemperature(10)).toBe("cold");
    expect(trendTemperature(50)).toBe("warm");
    expect(trendTemperature(70)).toBe("hot");
    expect(trendTemperature(90)).toBe("blazing");
  });

  it("uses inclusive lower bounds", () => {
    expect(trendTemperature(40)).toBe("warm");
    expect(trendTemperature(65)).toBe("hot");
    expect(trendTemperature(85)).toBe("blazing");
  });
});

describe("trendReasonSummary", () => {
  it("calls out mention velocity spikes", () => {
    const summary = trendReasonSummary({ mentionVelocity: 80, sentimentScore: 10, engagementGrowth: 10 });
    expect(summary).toContain("mention velocity spiking");
  });

  it("falls back to a neutral summary when nothing stands out", () => {
    const summary = trendReasonSummary({ mentionVelocity: 20, sentimentScore: 20, engagementGrowth: 20 });
    expect(summary).toBe("steady community interest");
  });
});
