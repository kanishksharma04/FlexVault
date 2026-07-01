import type { SellerTier } from "@prisma/client";
import { TierBadge } from "@/components/vault/tier-badge";
import { Progress } from "@/components/ui/progress";
import { nextTierProgress } from "@/lib/business/tier";
import { SELLER_TIER_COMMISSION } from "@/lib/business/constants";

export function TierProgress({ tier, salesCount }: { tier: SellerTier; salesCount: number }) {
  const { currentTier, nextTier, salesToNext, progressPct } = nextTierProgress(tier, salesCount);

  return (
    <div className="flex flex-col gap-3 border border-border bg-card p-5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <TierBadge tier={currentTier} />
          <span className="font-mono text-xs text-muted-foreground">
            {(SELLER_TIER_COMMISSION[currentTier] * 100).toFixed(1)}% commission
          </span>
        </div>
        {nextTier && (
          <span className="font-mono text-xs text-muted-foreground">{salesToNext} sales to {nextTier}</span>
        )}
      </div>
      <Progress value={progressPct} />
      {!nextTier && <p className="font-mono text-[11px] text-acid">Top tier reached — max perks unlocked.</p>}
    </div>
  );
}
