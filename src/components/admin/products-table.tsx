"use client";

import { useState, useTransition, useActionState, useEffect } from "react";
import Image from "next/image";
import { toast } from "sonner";
import { Plus, Pencil, Archive } from "lucide-react";
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import {
  Select, SelectTrigger, SelectValue, SelectContent, SelectItem,
} from "@/components/ui/select";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter, DialogClose, DialogTrigger,
} from "@/components/ui/dialog";
import { createProduct, updateProduct, archiveProduct, type ProductFormState } from "@/actions/admin-products";

export type AdminProductRow = {
  id: string;
  name: string;
  brand: string;
  baseTrendScore: number;
  sku: string;
  images: string[];
  description: string;
  category: { name: string };
  _count: { listings: number };
};

export function ProductsTable({
  products,
  categories,
}: {
  products: AdminProductRow[];
  categories: { id: string; name: string }[];
}) {
  const [editing, setEditing] = useState<AdminProductRow | null>(null);
  const [confirmArchive, setConfirmArchive] = useState<AdminProductRow | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [pending, startTransition] = useTransition();

  const initialState: ProductFormState = {};
  const [createState, createAction, createPending] = useActionState(createProduct, initialState);

  useEffect(() => {
    if (createState.success) {
      toast.success("Product created.");
      // Closing the dialog in response to the server action's resolved state.
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setCreateOpen(false);
    }
  }, [createState.success]);

  return (
    <div className="flex flex-col gap-4">
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogTrigger asChild>
          <Button size="sm" className="w-fit self-end">
            <Plus className="size-3.5" /> New Product
          </Button>
        </DialogTrigger>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Product</DialogTitle>
            <DialogDescription>Adds a new canonical catalog item.</DialogDescription>
          </DialogHeader>
          <form action={createAction} className="flex flex-col gap-4">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="name">Name</Label>
              <Input id="name" name="name" required />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="brand">Brand</Label>
              <Input id="brand" name="brand" required />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="categoryId">Category</Label>
              <Select name="categoryId" required>
                <SelectTrigger><SelectValue placeholder="Select category" /></SelectTrigger>
                <SelectContent>
                  {categories.map((c) => (
                    <SelectItem key={c.id} value={c.id}>{c.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="baseTrendScore">Base Trend Score</Label>
              <Input id="baseTrendScore" name="baseTrendScore" type="number" defaultValue={50} min={0} max={100} />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="description">Description</Label>
              <Textarea id="description" name="description" />
            </div>
            {createState.error && <p className="text-sm text-hype">{createState.error}</p>}
            <DialogFooter>
              <DialogClose asChild><Button type="button" variant="outline">Cancel</Button></DialogClose>
              <Button type="submit" disabled={createPending}>{createPending ? "Creating..." : "Create"}</Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Product</TableHead>
            <TableHead>Category</TableHead>
            <TableHead>Trend</TableHead>
            <TableHead>Listings</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {products.map((p) => (
            <TableRow key={p.id}>
              <TableCell>
                <div className="flex items-center gap-2">
                  <div className="relative size-10 shrink-0 overflow-hidden rounded-sm bg-vault-3">
                    <Image src={p.images[0]} alt={p.name} fill className="object-cover" />
                  </div>
                  <div>
                    <p className="line-clamp-1 max-w-56 text-sm font-medium">{p.name}</p>
                    <p className="font-mono text-[10px] text-muted-foreground">{p.sku}</p>
                  </div>
                </div>
              </TableCell>
              <TableCell><Badge variant="outline">{p.category.name}</Badge></TableCell>
              <TableCell className="font-mono">{p.baseTrendScore.toFixed(0)}</TableCell>
              <TableCell className="font-mono">{p._count.listings}</TableCell>
              <TableCell className="text-right">
                <div className="flex justify-end gap-1">
                  <Button variant="ghost" size="icon" className="size-7" onClick={() => setEditing(p)} aria-label="Edit product">
                    <Pencil className="size-3.5" />
                  </Button>
                  <Button variant="ghost" size="icon" className="size-7" onClick={() => setConfirmArchive(p)} aria-label="Archive product">
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
          <DialogHeader><DialogTitle>Edit Product</DialogTitle></DialogHeader>
          {editing && (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                const fd = new FormData(e.currentTarget);
                startTransition(async () => {
                  await updateProduct(editing.id, {
                    name: String(fd.get("name")),
                    brand: String(fd.get("brand")),
                    baseTrendScore: Number(fd.get("baseTrendScore")),
                    description: String(fd.get("description")),
                  });
                  toast.success("Product updated.");
                  setEditing(null);
                });
              }}
              className="flex flex-col gap-4"
            >
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="edit-name">Name</Label>
                <Input id="edit-name" name="name" defaultValue={editing.name} required />
              </div>
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="edit-brand">Brand</Label>
                <Input id="edit-brand" name="brand" defaultValue={editing.brand} required />
              </div>
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="edit-trend">Base Trend Score</Label>
                <Input id="edit-trend" name="baseTrendScore" type="number" defaultValue={editing.baseTrendScore} min={0} max={100} />
              </div>
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="edit-desc">Description</Label>
                <Textarea id="edit-desc" name="description" defaultValue={editing.description} />
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
            <DialogTitle>Archive this product?</DialogTitle>
            <DialogDescription>
              {confirmArchive?.name} will be hidden from the catalog. Existing listings and orders are preserved.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <DialogClose asChild><Button variant="outline">Cancel</Button></DialogClose>
            <Button
              variant="destructive"
              disabled={pending}
              onClick={() => {
                if (!confirmArchive) return;
                startTransition(async () => {
                  await archiveProduct(confirmArchive.id);
                  toast.success("Product archived.");
                  setConfirmArchive(null);
                });
              }}
            >
              {pending ? "Archiving..." : "Archive Product"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
