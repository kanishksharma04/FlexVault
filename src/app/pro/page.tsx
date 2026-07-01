import Link from "next/link";
import { Crown, Check } from "lucide-react";
import { auth } from "@/lib/auth";
import { SectionHeading } from "@/components/vault/section-heading";
import { Button } from "@/components/ui/button";
import { PRO_MEMBERSHIP_PRICE_INR, PRO_MEMBERSHIP_COMMISSION_DISCOUNT } from "@/lib/business/constants";

const PERKS = [
  `${(PRO_MEMBERSHIP_COMMISSION_DISCOUNT * 100).toFixed(0)}% lower commission on every sale`,
  "Early access to drops before the public countdown",
  "Free shipping counter for your first 5 sales each month",
  "Priority authentication queue placement",
];

export default async function ProPage() {
  const session = await auth();

  return (
    <div className="mx-auto max-w-lg px-4 py-16 text-center sm:px-6">
      <Crown className="mx-auto size-8 text-gold" />
      <SectionHeading eyebrow="Membership" title="FLEX VAULT PRO" description={`₹${PRO_MEMBERSHIP_PRICE_INR}/month for buyers and sellers who move fast.`} align="center" className="mx-auto mt-3" />

      <ul className="mx-auto mt-8 flex max-w-xs flex-col gap-2 text-left">
        {PERKS.map((perk) => (
          <li key={perk} className="flex items-start gap-2 text-sm text-foreground/90">
            <Check className="mt-0.5 size-4 shrink-0 text-acid" />
            {perk}
          </li>
        ))}
      </ul>

      <div className="mt-8">
        {session?.user ? (
          <Button asChild size="lg">
            <Link href={session.user.role === "SELLER" ? "/dashboard/seller/pro" : "/dashboard/buyer"}>
              Manage Membership
            </Link>
          </Button>
        ) : (
          <Button asChild size="lg">
            <Link href="/signup">Create an account to upgrade</Link>
          </Button>
        )}
      </div>
    </div>
  );
}
