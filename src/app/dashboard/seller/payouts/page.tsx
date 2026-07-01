import { Wallet } from "lucide-react";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { getSellerOrders } from "@/lib/queries/seller";
import { EmptyState } from "@/components/vault/empty-state";
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { SELLER_TIER_PAYOUT_DAYS } from "@/lib/business/constants";

export const dynamic = "force-dynamic";

export default async function SellerPayoutsPage() {
  const session = await auth();
  if (!session?.user) return null;

  const [orders, user] = await Promise.all([
    getSellerOrders(session.user.id),
    db.user.findUnique({ where: { id: session.user.id } }),
  ]);

  if (orders.length === 0) {
    return <EmptyState icon={Wallet} title="NO PAYOUTS YET" description="Payouts are issued after delivery is confirmed." />;
  }

  const payoutDays = user ? SELLER_TIER_PAYOUT_DAYS[user.sellerTier] : 7;

  return (
    <div className="flex flex-col gap-4">
      <p className="font-mono text-xs text-muted-foreground">
        Your tier pays out within {payoutDays} day{payoutDays === 1 ? "" : "s"} of delivery confirmation.
      </p>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Order</TableHead>
            <TableHead>Sale Price</TableHead>
            <TableHead>Commission</TableHead>
            <TableHead>Net Payout</TableHead>
            <TableHead>Status</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {orders.map((o) => {
            const commission = o.price * o.commissionRate;
            const net = o.price - commission;
            const paid = o.status === "DELIVERED";
            return (
              <TableRow key={o.id}>
                <TableCell className="line-clamp-1 max-w-48 text-sm">{o.listing.product.name}</TableCell>
                <TableCell className="font-mono text-sm">₹{o.price.toLocaleString("en-IN")}</TableCell>
                <TableCell className="font-mono text-sm text-muted-foreground">
                  -₹{Math.round(commission).toLocaleString("en-IN")} ({(o.commissionRate * 100).toFixed(1)}%)
                </TableCell>
                <TableCell className="font-mono text-sm font-bold text-acid">
                  ₹{Math.round(net).toLocaleString("en-IN")}
                </TableCell>
                <TableCell>
                  <Badge variant={paid ? "acid" : "outline"}>{paid ? "Paid" : "Pending"}</Badge>
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}
