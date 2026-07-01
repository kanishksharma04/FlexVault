import { DEFAULT_TREND_WEIGHTS } from "./constants";

export type TrendWeights = {
  mentionVelocityWeight: number;
  sentimentWeight: number;
  engagementWeight: number;
};

export type TrendInputs = {
  mentionVelocity: number; // 0-100
  sentimentScore: number; // 0-100
  engagementGrowth: number; // 0-100
};

/**
 * TrendScore = (w1 × MentionVelocity) + (w2 × SentimentScore) + (w3 × EngagementGrowth)
 * Weights are admin-configurable and expected to sum to ~1.
 */
export function calcTrendScore(
  inputs: TrendInputs,
  weights: TrendWeights = DEFAULT_TREND_WEIGHTS
): number {
  const raw =
    weights.mentionVelocityWeight * inputs.mentionVelocity +
    weights.sentimentWeight * inputs.sentimentScore +
    weights.engagementWeight * inputs.engagementGrowth;
  return Math.max(0, Math.min(100, Math.round(raw * 10) / 10));
}

export function trendTemperature(score: number): "cold" | "warm" | "hot" | "blazing" {
  if (score >= 85) return "blazing";
  if (score >= 65) return "hot";
  if (score >= 40) return "warm";
  return "cold";
}

export function trendReasonSummary(inputs: TrendInputs): string {
  const parts: string[] = [];
  if (inputs.mentionVelocity >= 70) parts.push("mention velocity spiking");
  if (inputs.sentimentScore >= 70) parts.push("sentiment strongly positive");
  if (inputs.engagementGrowth >= 70) parts.push("engagement climbing fast");
  if (parts.length === 0) parts.push("steady community interest");
  return parts.join(", ");
}
