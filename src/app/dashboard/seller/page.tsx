import Link from "next/link";
import { Tag, Clock, TrendingUp, Wallet } from "lucide-react";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { getSellerStats, getSellerSalesByDay } from "@/lib/queries/seller";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { TierProgress } from "@/components/dashboard/tier-progress";
import { SalesBarChart } from "@/components/dashboard/sales-bar-chart";

export const dynamic = "force-dynamic";

export default async function SellerOverviewPage() {
  const session = await auth();
  if (!session?.user) return null;

  const [stats, sales, user] = await Promise.all([
    getSellerStats(session.user.id),
    getSellerSalesByDay(session.user.id),
    db.user.findUnique({ where: { id: session.user.id } }),
  ]);

  const statCards = [
    { label: "Active Listings", value: stats.activeListings, icon: Tag },
    { label: "Pending Auth", value: stats.pendingAuth, icon: Clock },
    { label: "Total Sales", value: stats.totalSales, icon: TrendingUp },
    { label: "Net Payout", value: `₹${Math.round(stats.netPayout).toLocaleString("en-IN")}`, icon: Wallet },
  ];

  return (
    <div className="flex flex-col gap-8">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <p className="text-sm text-muted-foreground">Manage your listings and track performance.</p>
        <Button asChild>
          <Link href="/sell">+ New Listing</Link>
        </Button>
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {statCards.map((s) => (
          <Card key={s.label} className="gap-2 py-4">
            <CardContent className="flex flex-col gap-1 px-4">
              <s.icon className="size-4 text-acid" />
              <p className="font-mono text-xl font-bold">{s.value}</p>
              <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">{s.label}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {user && <TierProgress tier={user.sellerTier} salesCount={stats.totalSales} />}

      <div className="border border-border bg-card p-5">
        <p className="mb-4 font-mono text-xs uppercase tracking-widest text-muted-foreground">
          Revenue — last 14 days
        </p>
        <SalesBarChart data={sales} />
      </div>
    </div>
  );
}
