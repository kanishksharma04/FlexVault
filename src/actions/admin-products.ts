"use server";

import { revalidatePath } from "next/cache";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { mockProductImages } from "@/lib/mock-image";

async function assertAdmin() {
  const session = await auth();
  if (!session?.user || session.user.role !== "ADMIN") return null;
  return session;
}

function slugify(s: string) {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
}

export type ProductFormState = { error?: string; success?: boolean };

export async function createProduct(_prev: ProductFormState, formData: FormData): Promise<ProductFormState> {
  if (!(await assertAdmin())) return { error: "Not authorized." };

  const name = String(formData.get("name") ?? "").trim();
  const brand = String(formData.get("brand") ?? "").trim();
  const categoryId = String(formData.get("categoryId") ?? "");
  const description = String(formData.get("description") ?? "").trim();
  const baseTrendScore = Number(formData.get("baseTrendScore") ?? 50);

  if (!name || !brand || !categoryId) return { error: "Name, brand, and category are required." };

  await db.product.create({
    data: {
      name,
      brand,
      categoryId,
      description: description || `${name} — authenticated by Flex Vault.`,
      baseTrendScore: Number.isFinite(baseTrendScore) ? baseTrendScore : 50,
      slug: slugify(`${name}-${Date.now()}`),
      sku: `FV-${slugify(brand)}-${Math.floor(Math.random() * 90000 + 10000)}`.toUpperCase(),
      images: mockProductImages(name, name, 4),
    },
  });

  revalidatePath("/dashboard/admin/products");
  return { success: true };
}

export async function updateProduct(id: string, data: { name?: string; brand?: string; baseTrendScore?: number; description?: string }) {
  if (!(await assertAdmin())) return { error: "Not authorized." };

  if (data.name !== undefined && !data.name.trim()) return { error: "Name cannot be empty." };
  if (data.brand !== undefined && !data.brand.trim()) return { error: "Brand cannot be empty." };
  if (data.baseTrendScore !== undefined && !Number.isFinite(data.baseTrendScore)) {
    return { error: "Enter a valid trend score." };
  }

  // Whitelist fields explicitly instead of forwarding `data` as-is — Prisma
  // only rejects unknown keys, not extra *valid* Product fields (e.g. slug,
  // sku, categoryId), so a crafted call could otherwise smuggle those in.
  await db.product.update({
    where: { id },
    data: {
      ...(data.name !== undefined ? { name: data.name.trim() } : {}),
      ...(data.brand !== undefined ? { brand: data.brand.trim() } : {}),
      ...(data.baseTrendScore !== undefined ? { baseTrendScore: data.baseTrendScore } : {}),
      ...(data.description !== undefined ? { description: data.description } : {}),
    },
  });
  revalidatePath("/dashboard/admin/products");
  return { success: true };
}

export async function archiveProduct(id: string) {
  if (!(await assertAdmin())) return { error: "Not authorized." };
  await db.product.update({ where: { id }, data: { archivedAt: new Date() } });
  revalidatePath("/dashboard/admin/products");
  return { success: true };
}
