import Link from "next/link";
import { ShieldCheck, Tag, Users, ClipboardList, AlertTriangle, IndianRupee } from "lucide-react";
import { getAdminStats } from "@/lib/queries/admin";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

export const dynamic = "force-dynamic";

export default async function AdminOverviewPage() {
  const stats = await getAdminStats();

  const cards = [
    { label: "Pending Authentication", value: stats.pendingAuth, icon: ShieldCheck, href: "/dashboard/admin/authentication", highlight: stats.pendingAuth > 0 },
    { label: "Active Listings", value: stats.activeListings, icon: Tag, href: "/dashboard/admin/listings" },
    { label: "Users", value: stats.totalUsers, icon: Users, href: "/dashboard/admin/users" },
    { label: "Total Orders", value: stats.totalOrders, icon: ClipboardList, href: "/dashboard/admin/orders" },
    { label: "Open Disputes", value: stats.openDisputes, icon: AlertTriangle, href: "/dashboard/admin/orders", highlight: stats.openDisputes > 0 },
    { label: "GMV", value: `₹${Math.round(stats.gmv).toLocaleString("en-IN")}`, icon: IndianRupee, href: "/dashboard/admin/orders" },
  ];

  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
      {cards.map((c) => (
        <Link key={c.label} href={c.href}>
          <Card className={`gap-2 py-4 transition hover:border-acid ${c.highlight ? "border-hype/50" : ""}`}>
            <CardContent className="flex flex-col gap-1 px-4">
              <c.icon className={`size-4 ${c.highlight ? "text-hype" : "text-acid"}`} />
              <p className="font-mono text-xl font-bold">{c.value}</p>
              <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">{c.label}</p>
            </CardContent>
          </Card>
        </Link>
      ))}
      <Card className="col-span-2 gap-2 py-4 sm:col-span-3">
        <CardContent className="flex flex-col gap-3 px-4">
          <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">Quick actions</p>
          <div className="flex flex-wrap gap-2">
            <Button asChild size="sm"><Link href="/dashboard/admin/authentication">Review Auth Queue</Link></Button>
            <Button asChild size="sm" variant="outline"><Link href="/dashboard/admin/products">Manage Products</Link></Button>
            <Button asChild size="sm" variant="outline"><Link href="/dashboard/admin/drops">Manage Drops</Link></Button>
            <Button asChild size="sm" variant="outline"><Link href="/dashboard/admin/trends">Trend Weights</Link></Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
