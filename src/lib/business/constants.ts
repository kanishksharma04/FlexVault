import type { SellerTier } from "@prisma/client";

export const SELLER_TIER_COMMISSION: Record<SellerTier, number> = {
  BRONZE: 0.1,
  SILVER: 0.09,
  GOLD: 0.085,
  PLATINUM: 0.08,
};

export const SELLER_TIER_PAYOUT_DAYS: Record<SellerTier, number> = {
  BRONZE: 7,
  SILVER: 5,
  GOLD: 3,
  PLATINUM: 1,
};

export const SELLER_TIER_THRESHOLDS: Record<SellerTier, number> = {
  BRONZE: 0,
  SILVER: 10,
  GOLD: 50,
  PLATINUM: 150,
};

export const SELLER_TIER_ORDER: SellerTier[] = ["BRONZE", "SILVER", "GOLD", "PLATINUM"];

export const INSURANCE_THRESHOLD_INR = 10_000;
export const INSURANCE_RATE = 0.015; // 1.5% of item price, applied above threshold

export const PRO_MEMBERSHIP_COMMISSION_DISCOUNT = 0.02;
export const PRO_MEMBERSHIP_PRICE_INR = 999;

export const DEFAULT_TREND_WEIGHTS = {
  mentionVelocityWeight: 0.4,
  sentimentWeight: 0.35,
  engagementWeight: 0.25,
};
