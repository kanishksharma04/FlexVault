import { Gem, Award, Medal, Crown } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const TIER_CONFIG = {
  BRONZE: { icon: Medal, className: "border-transparent bg-[#8a5a3a]/20 text-[#c98a5c]" },
  SILVER: { icon: Award, className: "border-transparent bg-white/10 text-zinc-200" },
  GOLD: { icon: Gem, className: "border-transparent bg-gold/15 text-gold" },
  PLATINUM: { icon: Crown, className: "border-transparent bg-acid/15 text-acid" },
} as const;

export function TierBadge({ tier, className }: { tier: keyof typeof TIER_CONFIG; className?: string }) {
  const config = TIER_CONFIG[tier] ?? TIER_CONFIG.BRONZE;
  const Icon = config.icon;
  return (
    <Badge className={cn(config.className, className)}>
      <Icon />
      {tier}
    </Badge>
  );
}
