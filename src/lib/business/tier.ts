import type { SellerTier } from "@prisma/client";
import { SELLER_TIER_ORDER, SELLER_TIER_THRESHOLDS } from "./constants";

export function tierForSalesCount(salesCount: number): SellerTier {
  let tier: SellerTier = "BRONZE";
  for (const candidate of SELLER_TIER_ORDER) {
    if (salesCount >= SELLER_TIER_THRESHOLDS[candidate]) tier = candidate;
  }
  return tier;
}

/**
 * Progress toward the next tier, anchored to the seller's actual stored
 * tier (not re-derived from salesCount) so admin-set tiers stay authoritative.
 */
export function nextTierProgress(
  currentTier: SellerTier,
  salesCount: number
): {
  currentTier: SellerTier;
  nextTier: SellerTier | null;
  salesToNext: number;
  progressPct: number;
} {
  const currentIndex = SELLER_TIER_ORDER.indexOf(currentTier);
  const nextTier = SELLER_TIER_ORDER[currentIndex + 1] ?? null;

  if (!nextTier) {
    return { currentTier, nextTier: null, salesToNext: 0, progressPct: 100 };
  }

  const floor = SELLER_TIER_THRESHOLDS[currentTier];
  const ceiling = SELLER_TIER_THRESHOLDS[nextTier];
  const progressPct = Math.round(((salesCount - floor) / (ceiling - floor)) * 100);

  return {
    currentTier,
    nextTier,
    salesToNext: Math.max(0, ceiling - salesCount),
    progressPct: Math.max(0, Math.min(100, progressPct)),
  };
}
