import Image from "next/image";
import { PackageX } from "lucide-react";
import { auth } from "@/lib/auth";
import { getBuyerOrders } from "@/lib/queries/buyer";
import { OrderStatusTracker } from "@/components/dashboard/order-status-tracker";
import { EmptyState } from "@/components/vault/empty-state";
import { TierBadge } from "@/components/vault/tier-badge";
import { AuthBadge } from "@/components/vault/auth-badge";
import { Card, CardContent } from "@/components/ui/card";

export const dynamic = "force-dynamic";

export default async function BuyerOrdersPage() {
  const session = await auth();
  if (!session?.user) return null;
  const orders = await getBuyerOrders(session.user.id);

  if (orders.length === 0) {
    return <EmptyState icon={PackageX} title="NO ORDERS YET" description="Your purchase history will show up here." />;
  }

  return (
    <div className="flex flex-col gap-4">
      {orders.map((order) => (
        <Card key={order.id} className="gap-4 py-5">
          <CardContent className="flex flex-col gap-4 px-5">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div className="flex gap-3">
                <div className="relative size-16 shrink-0 overflow-hidden rounded-sm bg-vault-3">
                  <Image src={order.listing.product.images[0]} alt={order.listing.product.name} fill className="object-cover" />
                </div>
                <div>
                  <p className="font-semibold">{order.listing.product.name}</p>
                  <p className="font-mono text-xs text-muted-foreground">
                    {order.listing.condition.replace(/_/g, " ")}
                    {order.listing.size ? ` · ${order.listing.size}` : ""} · Sold by {order.listing.seller.name}
                  </p>
                  <div className="mt-1 flex items-center gap-2">
                    <TierBadge tier={order.listing.seller.sellerTier} />
                    {order.listing.authenticationRecord && (
                      <AuthBadge status={order.listing.authenticationRecord.status as "APPROVED" | "PENDING" | "REJECTED"} />
                    )}
                  </div>
                </div>
              </div>
              <div className="text-right">
                <p className="font-mono text-lg font-bold text-acid">₹{order.price.toLocaleString("en-IN")}</p>
                <p className="font-mono text-[10px] text-muted-foreground">
                  {order.insuranceOpted ? `+₹${order.insuranceFee.toLocaleString("en-IN")} insured` : "No insurance"}
                </p>
                <p className="font-mono text-[10px] text-muted-foreground">
                  {new Date(order.createdAt).toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" })}
                </p>
              </div>
            </div>
            <OrderStatusTracker status={order.status} />
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
