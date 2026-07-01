"use client";

import { useState, useTransition, useActionState, useEffect } from "react";
import Image from "next/image";
import { toast } from "sonner";
import { Plus, Trash2, Settings, X } from "lucide-react";
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter, DialogClose, DialogTrigger } from "@/components/ui/dialog";
import { ProductPicker, type PickedProduct } from "@/components/sell/product-picker";
import { createDrop, toggleDropActive, deleteDrop, addFeaturedProduct, removeFeaturedProduct, type DropFormState } from "@/actions/admin-drops";

export type AdminDropRow = {
  id: string;
  title: string;
  dropDate: Date;
  isActive: boolean;
  featuredProducts: { id: string; product: { id: string; name: string; images: string[] } }[];
};

export function DropsTable({ drops }: { drops: AdminDropRow[] }) {
  const [createOpen, setCreateOpen] = useState(false);
  const [manageDrop, setManageDrop] = useState<AdminDropRow | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<AdminDropRow | null>(null);
  const [pending, startTransition] = useTransition();

  const initialState: DropFormState = {};
  const [createState, createAction, createPending] = useActionState(createDrop, initialState);

  useEffect(() => {
    if (createState.success) {
      toast.success("Drop created.");
      // Closing the dialog in response to the server action's resolved state.
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setCreateOpen(false);
    }
  }, [createState.success]);

  return (
    <div className="flex flex-col gap-4">
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogTrigger asChild>
          <Button size="sm" className="w-fit self-end"><Plus className="size-3.5" /> New Drop</Button>
        </DialogTrigger>
        <DialogContent>
          <DialogHeader><DialogTitle>Create Drop</DialogTitle></DialogHeader>
          <form action={createAction} className="flex flex-col gap-4">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="drop-title">Title</Label>
              <Input id="drop-title" name="title" required />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="drop-desc">Description</Label>
              <Textarea id="drop-desc" name="description" />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="drop-date">Drop / Countdown Date</Label>
              <Input id="drop-date" name="dropDate" type="datetime-local" required />
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
            <TableHead>Drop</TableHead>
            <TableHead>Date</TableHead>
            <TableHead>Products</TableHead>
            <TableHead>Active</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {drops.map((d) => (
            <TableRow key={d.id}>
              <TableCell className="text-sm font-medium">{d.title}</TableCell>
              <TableCell className="font-mono text-xs text-muted-foreground">
                {new Date(d.dropDate).toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" })}
              </TableCell>
              <TableCell className="font-mono">{d.featuredProducts.length}</TableCell>
              <TableCell>
                <Switch
                  checked={d.isActive}
                  onCheckedChange={(checked) =>
                    startTransition(async () => {
                      await toggleDropActive(d.id, checked);
                      toast.success(checked ? "Drop activated." : "Drop deactivated.");
                    })
                  }
                />
              </TableCell>
              <TableCell className="text-right">
                <div className="flex justify-end gap-1">
                  <Button variant="ghost" size="icon" className="size-7" aria-label={`Manage ${d.title}`} onClick={() => setManageDrop(d)}>
                    <Settings className="size-3.5" />
                  </Button>
                  <Button variant="ghost" size="icon" className="size-7" aria-label={`Delete ${d.title}`} onClick={() => setConfirmDelete(d)}>
                    <Trash2 className="size-3.5" />
                  </Button>
                </div>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      <Dialog open={!!manageDrop} onOpenChange={(open) => !open && setManageDrop(null)}>
        <DialogContent className="max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Manage Featured Products</DialogTitle>
            <DialogDescription>{manageDrop?.title}</DialogDescription>
          </DialogHeader>
          {manageDrop && (
            <div className="flex flex-col gap-4">
              <div className="flex flex-col gap-2">
                {manageDrop.featuredProducts.map((fp) => (
                  <div key={fp.id} className="flex items-center gap-2 border border-border p-2">
                    <div className="relative size-8 shrink-0 overflow-hidden bg-vault-3">
                      <Image src={fp.product.images[0]} alt={fp.product.name} fill className="object-cover" />
                    </div>
                    <p className="line-clamp-1 flex-1 text-sm">{fp.product.name}</p>
                    <button
                      onClick={() =>
                        startTransition(async () => {
                          await removeFeaturedProduct(fp.id);
                          toast.success("Removed from drop.");
                        })
                      }
                    >
                      <X className="size-4 text-muted-foreground hover:text-hype" />
                    </button>
                  </div>
                ))}
                {manageDrop.featuredProducts.length === 0 && (
                  <p className="text-xs text-muted-foreground">No products featured yet.</p>
                )}
              </div>
              <ProductPicker
                categorySlug=""
                value={null}
                onChange={(p: PickedProduct) =>
                  startTransition(async () => {
                    await addFeaturedProduct(manageDrop.id, p.id);
                    toast.success(`${p.name} added to drop.`);
                  })
                }
              />
            </div>
          )}
        </DialogContent>
      </Dialog>

      <Dialog open={!!confirmDelete} onOpenChange={(open) => !open && setConfirmDelete(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete this drop?</DialogTitle>
            <DialogDescription>{confirmDelete?.title} will be permanently removed.</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <DialogClose asChild><Button variant="outline">Cancel</Button></DialogClose>
            <Button
              variant="destructive"
              disabled={pending}
              onClick={() => {
                if (!confirmDelete) return;
                startTransition(async () => {
                  await deleteDrop(confirmDelete.id);
                  toast.success("Drop deleted.");
                  setConfirmDelete(null);
                });
              }}
            >
              {pending ? "Deleting..." : "Delete Drop"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
