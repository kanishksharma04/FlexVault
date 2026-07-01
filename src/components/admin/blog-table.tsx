"use client";

import { useState, useTransition, useActionState, useEffect } from "react";
import { toast } from "sonner";
import { Plus, Pencil, Trash2 } from "lucide-react";
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter, DialogClose, DialogTrigger } from "@/components/ui/dialog";
import { createBlogPost, updateBlogPost, deleteBlogPost, type BlogFormState } from "@/actions/admin-blog";

export type AdminBlogRow = {
  id: string;
  title: string;
  excerpt: string;
  content: string;
  publishedAt: Date | null;
};

export function BlogTable({ posts }: { posts: AdminBlogRow[] }) {
  const [editing, setEditing] = useState<AdminBlogRow | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<AdminBlogRow | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [pending, startTransition] = useTransition();

  const initialState: BlogFormState = {};
  const [createState, createAction, createPending] = useActionState(createBlogPost, initialState);

  useEffect(() => {
    if (createState.success) {
      toast.success("Post created.");
      // Closing the dialog in response to the server action's resolved state.
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setCreateOpen(false);
    }
  }, [createState.success]);

  return (
    <div className="flex flex-col gap-4">
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogTrigger asChild>
          <Button size="sm" className="w-fit self-end"><Plus className="size-3.5" /> New Post</Button>
        </DialogTrigger>
        <DialogContent className="max-h-[85vh] overflow-y-auto">
          <DialogHeader><DialogTitle>Create Post</DialogTitle></DialogHeader>
          <form action={createAction} className="flex flex-col gap-4">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="post-title">Title</Label>
              <Input id="post-title" name="title" required />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="post-excerpt">Excerpt</Label>
              <Textarea id="post-excerpt" name="excerpt" required className="min-h-16" />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="post-content">Content</Label>
              <Textarea id="post-content" name="content" required className="min-h-32" />
            </div>
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" name="publish" className="size-4" />
              Publish immediately
            </label>
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
            <TableHead>Title</TableHead>
            <TableHead>Status</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {posts.map((p) => (
            <TableRow key={p.id}>
              <TableCell>
                <p className="text-sm font-medium">{p.title}</p>
                <p className="line-clamp-1 max-w-96 text-xs text-muted-foreground">{p.excerpt}</p>
              </TableCell>
              <TableCell>
                <Badge variant={p.publishedAt ? "acid" : "outline"}>{p.publishedAt ? "Published" : "Draft"}</Badge>
              </TableCell>
              <TableCell className="text-right">
                <div className="flex justify-end gap-1">
                  <Button variant="ghost" size="icon" className="size-7" aria-label={`Edit ${p.title}`} onClick={() => setEditing(p)}>
                    <Pencil className="size-3.5" />
                  </Button>
                  <Button variant="ghost" size="icon" className="size-7" aria-label={`Delete ${p.title}`} onClick={() => setConfirmDelete(p)}>
                    <Trash2 className="size-3.5" />
                  </Button>
                </div>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      <Dialog open={!!editing} onOpenChange={(open) => !open && setEditing(null)}>
        <DialogContent className="max-h-[85vh] overflow-y-auto">
          <DialogHeader><DialogTitle>Edit Post</DialogTitle></DialogHeader>
          {editing && (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                const fd = new FormData(e.currentTarget);
                startTransition(async () => {
                  await updateBlogPost(editing.id, {
                    title: String(fd.get("title")),
                    excerpt: String(fd.get("excerpt")),
                    content: String(fd.get("content")),
                    published: fd.get("publish") === "on",
                  });
                  toast.success("Post updated.");
                  setEditing(null);
                });
              }}
              className="flex flex-col gap-4"
            >
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="edit-post-title">Title</Label>
                <Input id="edit-post-title" name="title" defaultValue={editing.title} required />
              </div>
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="edit-post-excerpt">Excerpt</Label>
                <Textarea id="edit-post-excerpt" name="excerpt" defaultValue={editing.excerpt} required className="min-h-16" />
              </div>
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="edit-post-content">Content</Label>
                <Textarea id="edit-post-content" name="content" defaultValue={editing.content} required className="min-h-32" />
              </div>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" name="publish" defaultChecked={!!editing.publishedAt} className="size-4" />
                Published
              </label>
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
            <DialogTitle>Delete this post?</DialogTitle>
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
                  await deleteBlogPost(confirmDelete.id);
                  toast.success("Post deleted.");
                  setConfirmDelete(null);
                });
              }}
            >
              {pending ? "Deleting..." : "Delete Post"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
