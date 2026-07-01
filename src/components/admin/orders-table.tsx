"use client";

import { useState, useTransition } from "react";
import { toast } from "sonner";
import { AlertTriangle } from "lucide-react";
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { updateOrderStatus, resolveDispute } from "@/actions/admin-orders";
import type { OrderStatus } from "@prisma/client";

const STATUSES: OrderStatus[] = ["PLACED", "AUTHENTICATED", "SHIPPED", "DELIVERED", "DISPUTED", "RETURNED", "CANCELLED"];

export type AdminOrderRow = {
  id: string;
  price: number;
  status: OrderStatus;
  createdAt: Date;
  buyer: { name: string };
  listing: { product: { name: string }; seller: { name: string } };
  reviews: { id: string; reason: string; status: string }[];
};

export function OrdersTable({ orders }: { orders: AdminOrderRow[] }) {
  const [pending, startTransition] = useTransition();
  const [disputeOrder, setDisputeOrder] = useState<AdminOrderRow | null>(null);
  const [note, setNote] = useState("");

  const openDispute = disputeOrder?.reviews.find((r) => r.status === "OPEN" || r.status === "UNDER_REVIEW");

  return (
    <div className="flex flex-col gap-4">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Item</TableHead>
            <TableHead>Buyer</TableHead>
            <TableHead>Seller</TableHead>
            <TableHead>Price</TableHead>
            <TableHead>Status</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {orders.map((o) => {
            const hasOpenDispute = o.reviews.some((r) => r.status === "OPEN" || r.status === "UNDER_REVIEW");
            return (
              <TableRow key={o.id}>
                <TableCell className="line-clamp-1 max-w-48 text-sm">{o.listing.product.name}</TableCell>
                <TableCell className="text-sm text-muted-foreground">{o.buyer.name}</TableCell>
                <TableCell className="text-sm text-muted-foreground">{o.listing.seller.name}</TableCell>
                <TableCell className="font-mono text-sm">₹{o.price.toLocaleString("en-IN")}</TableCell>
                <TableCell>
                  <Select
                    defaultValue={o.status}
                    onValueChange={(v) =>
                      startTransition(async () => {
                        await updateOrderStatus(o.id, v as OrderStatus);
                        toast.success("Order status updated.");
                      })
                    }
                  >
                    <SelectTrigger className="h-8 w-40 text-xs"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {STATUSES.map((s) => (
                        <SelectItem key={s} value={s}>{s}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </TableCell>
                <TableCell className="text-right">
                  {hasOpenDispute && (
                    <Button variant="ghost" size="sm" onClick={() => setDisputeOrder(o)} className="text-hype">
                      <AlertTriangle className="size-3.5" /> Dispute
                    </Button>
                  )}
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>

      <Dialog open={!!disputeOrder} onOpenChange={(open) => !open && setDisputeOrder(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Resolve Dispute</DialogTitle>
            <DialogDescription>{openDispute?.reason}</DialogDescription>
          </DialogHeader>
          <Textarea
            placeholder="Resolution notes..."
            value={note}
            onChange={(e) => setNote(e.target.value)}
            className="min-h-20"
          />
          <DialogFooter>
            <Button
              variant="outline"
              disabled={pending}
              onClick={() => {
                if (!openDispute) return;
                startTransition(async () => {
                  await resolveDispute(openDispute.id, "RESOLVED_SELLER", note || "Item found genuine; seller upheld.");
                  toast.success("Resolved in favor of seller.");
                  setDisputeOrder(null);
                  setNote("");
                });
              }}
            >
              Uphold Seller
            </Button>
            <Button
              variant="destructive"
              disabled={pending}
              onClick={() => {
                if (!openDispute) return;
                startTransition(async () => {
                  await resolveDispute(openDispute.id, "RESOLVED_BUYER", note || "Item confirmed invalid; buyer refunded.");
                  toast.success("Refund issued to buyer.");
                  setDisputeOrder(null);
                  setNote("");
                });
              }}
            >
              Refund Buyer
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
