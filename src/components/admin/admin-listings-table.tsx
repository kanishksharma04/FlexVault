"use client";

import { useState, useTransition } from "react";
import Image from "next/image";
import { toast } from "sonner";
import { Pencil, Archive } from "lucide-react";
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter, DialogClose,
} from "@/components/ui/dialog";
import { updateListing, archiveListing } from "@/actions/listings";
import type { Condition, ListingStatus, ListingType } from "@prisma/client";

export type AdminListingRow = {
  id: string;
  price: number;
  quantity: number;
  condition: Condition;
  listingType: ListingType;
  status: ListingStatus;
  product: { name: string; images: string[] };
  seller: { name: string };
};

const STATUS_VARIANT: Record<ListingStatus, "acid" | "hype" | "secondary" | "outline"> = {
  ACTIVE: "acid", PENDING_AUTH: "outline", SOLD: "secondary", REJECTED: "hype", ARCHIVED: "secondary", DRAFT: "outline",
};

export function AdminListingsTable({ listings }: { listings: AdminListingRow[] }) {
  const [editing, setEditing] = useState<AdminListingRow | null>(null);
  const [confirmArchive, setConfirmArchive] = useState<AdminListingRow | null>(null);
  const [pending, startTransition] = useTransition();

  return (
    <>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Item</TableHead>
            <TableHead>Seller</TableHead>
            <TableHead>Price</TableHead>
            <TableHead>Type</TableHead>
            <TableHead>Status</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {listings.map((l) => (
            <TableRow key={l.id}>
              <TableCell>
                <div className="flex items-center gap-2">
                  <div className="relative size-10 shrink-0 overflow-hidden rounded-sm bg-vault-3">
                    <Image src={l.product.images[0]} alt={l.product.name} fill className="object-cover" />
                  </div>
                  <p className="line-clamp-1 max-w-48 text-sm">{l.product.name}</p>
                </div>
              </TableCell>
              <TableCell className="text-sm text-muted-foreground">{l.seller.name}</TableCell>
              <TableCell className="font-mono text-acid">₹{l.price.toLocaleString("en-IN")}</TableCell>
              <TableCell className="font-mono text-xs">{l.listingType}</TableCell>
              <TableCell><Badge variant={STATUS_VARIANT[l.status]}>{l.status.replace(/_/g, " ")}</Badge></TableCell>
              <TableCell className="text-right">
                <div className="flex justify-end gap-1">
                  <Button variant="ghost" size="icon" className="size-7" onClick={() => setEditing(l)}>
                    <Pencil className="size-3.5" />
                  </Button>
                  <Button variant="ghost" size="icon" className="size-7" onClick={() => setConfirmArchive(l)}>
                    <Archive className="size-3.5" />
                  </Button>
                </div>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      <Dialog open={!!editing} onOpenChange={(open) => !open && setEditing(null)}>
        <DialogContent>
          <DialogHeader><DialogTitle>Edit Listing</DialogTitle></DialogHeader>
          {editing && (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                const fd = new FormData(e.currentTarget);
                startTransition(async () => {
                  await updateListing(editing.id, { price: Number(fd.get("price")), quantity: Number(fd.get("quantity")) });
                  toast.success("Listing updated.");
                  setEditing(null);
                });
              }}
              className="flex flex-col gap-4"
            >
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="admin-price">Price (₹)</Label>
                <Input id="admin-price" name="price" type="number" defaultValue={editing.price} min={1} required />
              </div>
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="admin-qty">Quantity</Label>
                <Input id="admin-qty" name="quantity" type="number" defaultValue={editing.quantity} min={1} required />
              </div>
              <DialogFooter>
                <DialogClose asChild><Button type="button" variant="outline">Cancel</Button></DialogClose>
                <Button type="submit" disabled={pending}>{pending ? "Saving..." : "Save changes"}</Button>
              </DialogFooter>
            </form>
          )}
        </DialogContent>
      </Dialog>

      <Dialog open={!!confirmArchive} onOpenChange={(open) => !open && setConfirmArchive(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Archive this listing?</DialogTitle>
            <DialogDescription>{confirmArchive?.product.name} will be removed from the marketplace.</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <DialogClose asChild><Button variant="outline">Cancel</Button></DialogClose>
            <Button
              variant="destructive"
              disabled={pending}
              onClick={() => {
                if (!confirmArchive) return;
                startTransition(async () => {
                  await archiveListing(confirmArchive.id);
                  toast.success("Listing archived.");
                  setConfirmArchive(null);
                });
              }}
            >
              {pending ? "Archiving..." : "Archive Listing"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
