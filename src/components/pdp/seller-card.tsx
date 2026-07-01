import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { TierBadge } from "@/components/vault/tier-badge";
import { SELLER_TIER_PAYOUT_DAYS } from "@/lib/business/constants";
import type { SellerTier } from "@prisma/client";

export function SellerCard({ name, tier, image }: { name: string; tier: SellerTier; image?: string | null }) {
  return (
    <div className="flex items-center gap-3 border border-border bg-card p-3">
      <Avatar className="size-10">
        <AvatarImage src={image ?? undefined} />
        <AvatarFallback>{name[0]?.toUpperCase()}</AvatarFallback>
      </Avatar>
      <div className="flex-1">
        <p className="text-sm font-semibold">{name}</p>
        <p className="font-mono text-[10px] text-muted-foreground">
          {SELLER_TIER_PAYOUT_DAYS[tier]}-day payout tier
        </p>
      </div>
      <TierBadge tier={tier} />
    </div>
  );
}
