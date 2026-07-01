import Image from "next/image";
import Link from "next/link";
import { Gavel } from "lucide-react";
import { auth } from "@/lib/auth";
import { getBuyerBids } from "@/lib/queries/buyer";
import { EmptyState } from "@/components/vault/empty-state";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";

export const dynamic = "force-dynamic";

const STATUS_VARIANT: Record<string, "acid" | "hype" | "secondary" | "outline"> = {
  ACTIVE: "acid",
  OUTBID: "hype",
  WON: "acid",
  LOST: "secondary",
  RETRACTED: "outline",
};

export default async function BuyerBidsPage() {
  const session = await auth();
  if (!session?.user) return null;
  const bids = await getBuyerBids(session.user.id);

  if (bids.length === 0) {
    return <EmptyState icon={Gavel} title="NO BIDS PLACED" description="Jump into an auction listing to place your first bid." />;
  }

  return (
    <div className="flex flex-col gap-3">
      {bids.map((bid) => {
        const isTopBid = bid.listing.bids[0]?.amount === bid.amount;
        return (
          <Link key={bid.id} href={`/product/${bid.listing.product.slug}`}>
            <Card className="gap-0 py-3 transition hover:border-acid">
              <CardContent className="flex items-center gap-3 px-4">
                <div className="relative size-12 shrink-0 overflow-hidden rounded-sm bg-vault-3">
                  <Image src={bid.listing.product.images[0]} alt={bid.listing.product.name} fill className="object-cover" />
                </div>
                <div className="flex-1">
                  <p className="line-clamp-1 text-sm font-semibold">{bid.listing.product.name}</p>
                  <p className="font-mono text-xs text-muted-foreground">
                    Your bid ₹{bid.amount.toLocaleString("en-IN")}
                    {isTopBid && bid.status === "ACTIVE" ? " · Highest bid" : ""}
                  </p>
                </div>
                <Badge variant={STATUS_VARIANT[bid.status] ?? "outline"}>{bid.status}</Badge>
              </CardContent>
            </Card>
          </Link>
        );
      })}
    </div>
  );
}
