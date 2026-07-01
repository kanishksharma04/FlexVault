import Link from "next/link";
import Image from "next/image";
import { Package, ShieldCheck, Heart, Gavel, ArrowRight } from "lucide-react";
import { auth } from "@/lib/auth";
import { getBuyerStats, getBuyerOrders } from "@/lib/queries/buyer";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { OrderStatusTracker } from "@/components/dashboard/order-status-tracker";

export const dynamic = "force-dynamic";

export default async function BuyerOverviewPage() {
  const session = await auth();
  if (!session?.user) return null;

  const [stats, orders] = await Promise.all([
    getBuyerStats(session.user.id),
    getBuyerOrders(session.user.id),
  ]);

  const recentOrders = orders.slice(0, 3);

  const statCards = [
    { label: "Orders", value: stats.orderCount, icon: Package },
    { label: "In Vault", value: stats.vaultCount, icon: ShieldCheck },
    { label: "Watchlist", value: stats.watchlistCount, icon: Heart },
    { label: "Active Bids", value: stats.activeBids, icon: Gavel },
  ];

  return (
    <div className="flex flex-col gap-8">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {statCards.map((s) => (
          <Card key={s.label} className="gap-2 py-4">
            <CardContent className="flex flex-col gap-1 px-4">
              <s.icon className="size-4 text-acid" />
              <p className="font-mono text-2xl font-bold">{s.value}</p>
              <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">{s.label}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <div>
        <div className="mb-3 flex items-center justify-between">
          <h2 className="font-display text-xl tracking-wide">RECENT ORDERS</h2>
          <Button asChild variant="link" size="sm">
            <Link href="/dashboard/buyer/orders">
              View all <ArrowRight className="size-3.5" />
            </Link>
          </Button>
        </div>

        {recentOrders.length === 0 ? (
          <p className="text-sm text-muted-foreground">No orders yet — go find your next grail.</p>
        ) : (
          <div className="flex flex-col gap-3">
            {recentOrders.map((order) => (
              <Card key={order.id} className="gap-3 py-4">
                <CardContent className="flex flex-col gap-3 px-4 sm:flex-row sm:items-center">
                  <div className="flex flex-1 items-center gap-3">
                    <div className="relative size-14 shrink-0 overflow-hidden rounded-sm bg-vault-3">
                      <Image src={order.listing.product.images[0]} alt={order.listing.product.name} fill className="object-cover" />
                    </div>
                    <div>
                      <p className="line-clamp-1 text-sm font-semibold">{order.listing.product.name}</p>
                      <p className="font-mono text-xs text-muted-foreground">
                        ₹{order.price.toLocaleString("en-IN")}
                      </p>
                    </div>
                  </div>
                  <div className="sm:w-72">
                    <OrderStatusTracker status={order.status} />
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
