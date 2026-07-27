"use server";

import { revalidatePath } from "next/cache";
import { db } from "@/lib/db";
import { assertAdmin } from "@/lib/auth-guards";
import { slugify } from "@/lib/slugify";
import { CategoryPhase } from "@prisma/client";

export type CategoryFormState = { error?: string; success?: boolean };

export async function createCategory(_prev: CategoryFormState, formData: FormData): Promise<CategoryFormState> {
  if (!(await assertAdmin())) return { error: "Not authorized." };

  const name = String(formData.get("name") ?? "").trim();
  const phaseInput = String(formData.get("phase") ?? "PHASE_1");
  const parentId = String(formData.get("parentId") ?? "") || null;
  if (!name) return { error: "Name is required." };
  if (!(Object.values(CategoryPhase) as string[]).includes(phaseInput)) {
    return { error: "Select a valid phase." };
  }
  const phase = phaseInput as CategoryPhase;

  const slug = slugify(name);
  const existing = await db.category.findUnique({ where: { slug } });
  if (existing) return { error: "A category with that name already exists." };

  await db.category.create({ data: { name, slug, phase, parentId } });
  revalidatePath("/dashboard/admin/categories");
  return { success: true };
}

export async function updateCategory(id: string, data: { name?: string; phase?: CategoryPhase }) {
  if (!(await assertAdmin())) return { error: "Not authorized." };

  if (data.name !== undefined && !data.name.trim()) return { error: "Name cannot be empty." };
  if (data.phase !== undefined && !(Object.values(CategoryPhase) as string[]).includes(data.phase)) {
    return { error: "Select a valid phase." };
  }

  // Whitelist fields explicitly instead of forwarding `data` as-is — Prisma
  // only rejects unknown keys, not extra *valid* Category fields (e.g. slug,
  // parentId), so a crafted call could otherwise smuggle those in.
  await db.category.update({
    where: { id },
    data: {
      ...(data.name !== undefined ? { name: data.name.trim() } : {}),
      ...(data.phase !== undefined ? { phase: data.phase } : {}),
    },
  });
  revalidatePath("/dashboard/admin/categories");
  return { success: true };
}

export async function deleteCategory(id: string) {
  if (!(await assertAdmin())) return { error: "Not authorized." };
  const productCount = await db.product.count({ where: { categoryId: id } });
  if (productCount > 0) return { error: "Cannot delete a category with products. Reassign or archive them first." };
  await db.category.delete({ where: { id } });
  revalidatePath("/dashboard/admin/categories");
  return { success: true };
}
