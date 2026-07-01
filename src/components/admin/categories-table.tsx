"use client";

import { useState, useTransition, useActionState, useEffect } from "react";
import { toast } from "sonner";
import { Plus, Pencil, Trash2 } from "lucide-react";
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter, DialogClose, DialogTrigger } from "@/components/ui/dialog";
import { createCategory, updateCategory, deleteCategory, type CategoryFormState } from "@/actions/admin-categories";
import type { CategoryPhase } from "@prisma/client";

export type AdminCategoryRow = {
  id: string;
  name: string;
  slug: string;
  phase: CategoryPhase;
  parent: { name: string } | null;
  _count: { products: number };
};

export function CategoriesTable({ categories }: { categories: AdminCategoryRow[] }) {
  const [editing, setEditing] = useState<AdminCategoryRow | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<AdminCategoryRow | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [pending, startTransition] = useTransition();

  const initialState: CategoryFormState = {};
  const [createState, createAction, createPending] = useActionState(createCategory, initialState);

  useEffect(() => {
    if (createState.success) {
      toast.success("Category created.");
      // Closing the dialog in response to the server action's resolved state.
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setCreateOpen(false);
    }
  }, [createState.success]);

  return (
    <div className="flex flex-col gap-4">
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogTrigger asChild>
          <Button size="sm" className="w-fit self-end"><Plus className="size-3.5" /> New Category</Button>
        </DialogTrigger>
        <DialogContent>
          <DialogHeader><DialogTitle>Create Category</DialogTitle></DialogHeader>
          <form action={createAction} className="flex flex-col gap-4">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="cat-name">Name</Label>
              <Input id="cat-name" name="name" required />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="cat-phase">Rollout Phase</Label>
              <Select name="phase" defaultValue="PHASE_1">
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="PHASE_1">Phase 1</SelectItem>
                  <SelectItem value="PHASE_2">Phase 2</SelectItem>
                  <SelectItem value="PHASE_3">Phase 3</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="cat-parent">Parent (optional)</Label>
              <Select name="parentId">
                <SelectTrigger><SelectValue placeholder="None (top-level)" /></SelectTrigger>
                <SelectContent>
                  {categories.filter((c) => !c.parent).map((c) => (
                    <SelectItem key={c.id} value={c.id}>{c.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
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
            <TableHead>Name</TableHead>
            <TableHead>Parent</TableHead>
            <TableHead>Phase</TableHead>
            <TableHead>Products</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {categories.map((c) => (
            <TableRow key={c.id}>
              <TableCell className="text-sm font-medium">{c.name}</TableCell>
              <TableCell className="text-sm text-muted-foreground">{c.parent?.name ?? "—"}</TableCell>
              <TableCell><Badge variant="outline">{c.phase.replace("_", " ")}</Badge></TableCell>
              <TableCell className="font-mono">{c._count.products}</TableCell>
              <TableCell className="text-right">
                <div className="flex justify-end gap-1">
                  <Button variant="ghost" size="icon" className="size-7" aria-label={`Edit ${c.name}`} onClick={() => setEditing(c)}>
                    <Pencil className="size-3.5" />
                  </Button>
                  <Button variant="ghost" size="icon" className="size-7" aria-label={`Delete ${c.name}`} onClick={() => setConfirmDelete(c)}>
                    <Trash2 className="size-3.5" />
                  </Button>
                </div>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      <Dialog open={!!editing} onOpenChange={(open) => !open && setEditing(null)}>
        <DialogContent>
          <DialogHeader><DialogTitle>Edit Category</DialogTitle></DialogHeader>
          {editing && (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                const fd = new FormData(e.currentTarget);
                startTransition(async () => {
                  await updateCategory(editing.id, { name: String(fd.get("name")), phase: fd.get("phase") as CategoryPhase });
                  toast.success("Category updated.");
                  setEditing(null);
                });
              }}
              className="flex flex-col gap-4"
            >
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="edit-cat-name">Name</Label>
                <Input id="edit-cat-name" name="name" defaultValue={editing.name} required />
              </div>
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="edit-cat-phase">Phase</Label>
                <Select name="phase" defaultValue={editing.phase}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="PHASE_1">Phase 1</SelectItem>
                    <SelectItem value="PHASE_2">Phase 2</SelectItem>
                    <SelectItem value="PHASE_3">Phase 3</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <DialogFooter>
                <DialogClose asChild><Button type="button" variant="outline">Cancel</Button></DialogClose>
                <Button type="submit" disabled={pending}>{pending ? "Saving..." : "Save changes"}</Button>
              </DialogFooter>
            </form>
          )}
        </DialogContent>
      </Dialog>

      <Dialog open={!!confirmDelete} onOpenChange={(open) => !open && setConfirmDelete(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete this category?</DialogTitle>
            <DialogDescription>
              {confirmDelete?.name} will be permanently removed. This only works if it has no products.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <DialogClose asChild><Button variant="outline">Cancel</Button></DialogClose>
            <Button
              variant="destructive"
              disabled={pending}
              onClick={() => {
                if (!confirmDelete) return;
                startTransition(async () => {
                  const res = await deleteCategory(confirmDelete.id);
                  if ("error" in res && res.error) {
                    toast.error(res.error);
                    return;
                  }
                  toast.success("Category deleted.");
                  setConfirmDelete(null);
                });
              }}
            >
              {pending ? "Deleting..." : "Delete Category"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
