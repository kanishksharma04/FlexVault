import Image from "next/image";
import { PackageSearch } from "lucide-react";
import { auth } from "@/lib/auth";
import { getSellerOrders } from "@/lib/queries/seller";
import { EmptyState } from "@/components/vault/empty-state";
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";

export const dynamic = "force-dynamic";

export default async function SellerOrdersPage() {
  const session = await auth();
  if (!session?.user) return null;
  const orders = await getSellerOrders(session.user.id);

  if (orders.length === 0) {
    return <EmptyState icon={PackageSearch} title="NO SALES YET" description="Sold items will appear here." />;
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Item</TableHead>
          <TableHead>Buyer</TableHead>
          <TableHead>Price</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Date</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {orders.map((o) => (
          <TableRow key={o.id}>
            <TableCell>
              <div className="flex items-center gap-2">
                <div className="relative size-10 shrink-0 overflow-hidden rounded-sm bg-vault-3">
                  <Image src={o.listing.product.images[0]} alt={o.listing.product.name} fill className="object-cover" />
                </div>
                <p className="line-clamp-1 max-w-48 text-sm">{o.listing.product.name}</p>
              </div>
            </TableCell>
            <TableCell className="text-sm text-muted-foreground">{o.buyer.name}</TableCell>
            <TableCell className="font-mono text-acid">₹{o.price.toLocaleString("en-IN")}</TableCell>
            <TableCell>
              <Badge variant="outline">{o.status}</Badge>
            </TableCell>
            <TableCell className="font-mono text-xs text-muted-foreground">
              {new Date(o.createdAt).toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" })}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
