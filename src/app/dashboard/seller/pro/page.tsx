import { Crown, Check } from "lucide-react";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { Badge } from "@/components/ui/badge";
import { ProUpgradeButton } from "@/components/dashboard/pro-upgrade-button";
import { PRO_MEMBERSHIP_PRICE_INR, PRO_MEMBERSHIP_COMMISSION_DISCOUNT } from "@/lib/business/constants";

export const dynamic = "force-dynamic";

const PERKS = [
  `${(PRO_MEMBERSHIP_COMMISSION_DISCOUNT * 100).toFixed(0)}% lower commission on every sale`,
  "Early access to drops before the public countdown",
  "Free shipping counter for your first 5 sales each month",
  "Priority authentication queue placement",
];

export default async function SellerProPage() {
  const session = await auth();
  if (!session?.user) return null;
  const user = await db.user.findUnique({ where: { id: session.user.id } });

  return (
    <div className="mx-auto max-w-lg border border-acid/30 bg-card p-8 text-center">
      <Crown className="mx-auto size-8 text-gold" />
      <h2 className="mt-3 font-display text-2xl tracking-wide">FLEX VAULT PRO</h2>
      <p className="mt-1 font-mono text-sm text-muted-foreground">₹{PRO_MEMBERSHIP_PRICE_INR}/month</p>

      {user?.isProMember ? (
        <Badge variant="acid" className="mx-auto mt-4 w-fit">
          <Crown /> Active Member
        </Badge>
      ) : (
        <div className="mt-6">
          <ProUpgradeButton />
        </div>
      )}

      <ul className="mt-6 flex flex-col gap-2 text-left">
        {PERKS.map((perk) => (
          <li key={perk} className="flex items-start gap-2 text-sm text-foreground/90">
            <Check className="mt-0.5 size-4 shrink-0 text-acid" />
            {perk}
          </li>
        ))}
      </ul>
    </div>
  );
}
