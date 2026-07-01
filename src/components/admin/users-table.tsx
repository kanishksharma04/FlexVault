"use client";

import { useState, useTransition } from "react";
import { toast } from "sonner";
import { Pencil, Archive } from "lucide-react";
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter, DialogClose } from "@/components/ui/dialog";
import { updateUser, archiveUser } from "@/actions/admin-users";
import { TierBadge } from "@/components/vault/tier-badge";
import type { Role, SellerTier } from "@prisma/client";

export type AdminUserRow = {
  id: string;
  name: string;
  email: string;
  role: Role;
  sellerTier: SellerTier;
  isProMember: boolean;
};

const ROLE_VARIANT: Record<Role, "acid" | "gold" | "hype" | "secondary"> = {
  ADMIN: "hype",
  AUTHENTICATOR: "gold",
  SELLER: "acid",
  BUYER: "secondary",
};

export function UsersTable({ users }: { users: AdminUserRow[] }) {
  const [editing, setEditing] = useState<AdminUserRow | null>(null);
  const [confirmArchive, setConfirmArchive] = useState<AdminUserRow | null>(null);
  const [pending, startTransition] = useTransition();

  return (
    <div className="flex flex-col gap-4">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>User</TableHead>
            <TableHead>Role</TableHead>
            <TableHead>Seller Tier</TableHead>
            <TableHead>Pro</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {users.map((u) => (
            <TableRow key={u.id}>
              <TableCell>
                <p className="text-sm font-medium">{u.name}</p>
                <p className="font-mono text-[10px] text-muted-foreground">{u.email}</p>
              </TableCell>
              <TableCell><Badge variant={ROLE_VARIANT[u.role]}>{u.role}</Badge></TableCell>
              <TableCell>{u.role === "SELLER" ? <TierBadge tier={u.sellerTier} /> : "—"}</TableCell>
              <TableCell>{u.isProMember ? <Badge variant="acid">Pro</Badge> : "—"}</TableCell>
              <TableCell className="text-right">
                <div className="flex justify-end gap-1">
                  <Button variant="ghost" size="icon" className="size-7" onClick={() => setEditing(u)}>
                    <Pencil className="size-3.5" />
                  </Button>
                  <Button variant="ghost" size="icon" className="size-7" onClick={() => setConfirmArchive(u)}>
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
          <DialogHeader><DialogTitle>Edit User</DialogTitle></DialogHeader>
          {editing && (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                const fd = new FormData(e.currentTarget);
                startTransition(async () => {
                  await updateUser(editing.id, {
                    role: fd.get("role") as Role,
                    sellerTier: fd.get("sellerTier") as SellerTier,
                    isProMember: fd.get("isProMember") === "on",
                  });
                  toast.success("User updated.");
                  setEditing(null);
                });
              }}
              className="flex flex-col gap-4"
            >
              <div className="flex flex-col gap-1.5">
                <Label>Role</Label>
                <Select name="role" defaultValue={editing.role}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="BUYER">Buyer</SelectItem>
                    <SelectItem value="SELLER">Seller</SelectItem>
                    <SelectItem value="ADMIN">Admin</SelectItem>
                    <SelectItem value="AUTHENTICATOR">Authenticator</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="flex flex-col gap-1.5">
                <Label>Seller Tier</Label>
                <Select name="sellerTier" defaultValue={editing.sellerTier}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="BRONZE">Bronze</SelectItem>
                    <SelectItem value="SILVER">Silver</SelectItem>
                    <SelectItem value="GOLD">Gold</SelectItem>
                    <SelectItem value="PLATINUM">Platinum</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" name="isProMember" defaultChecked={editing.isProMember} className="size-4" />
                Flex Vault Pro member
              </label>
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
            <DialogTitle>Archive this user?</DialogTitle>
            <DialogDescription>{confirmArchive?.name} will lose access but their order history is preserved.</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <DialogClose asChild><Button variant="outline">Cancel</Button></DialogClose>
            <Button
              variant="destructive"
              disabled={pending}
              onClick={() => {
                if (!confirmArchive) return;
                startTransition(async () => {
                  const res = await archiveUser(confirmArchive.id);
                  if ("error" in res && res.error) {
                    toast.error(res.error);
                    return;
                  }
                  toast.success("User archived.");
                  setConfirmArchive(null);
                });
              }}
            >
              {pending ? "Archiving..." : "Archive User"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
