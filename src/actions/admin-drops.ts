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

export type DropFormState = { error?: string; success?: boolean };

export async function createDrop(_prev: DropFormState, formData: FormData): Promise<DropFormState> {
  if (!(await assertAdmin())) return { error: "Not authorized." };

  const title = String(formData.get("title") ?? "").trim();
  const description = String(formData.get("description") ?? "").trim();
  const dropDate = String(formData.get("dropDate") ?? "");

  if (!title || !dropDate) return { error: "Title and drop date are required." };

  const target = new Date(dropDate);
  if (Number.isNaN(target.getTime())) return { error: "Enter a valid drop date." };
  await db.drop.create({
    data: {
      title,
      slug: slugify(`${title}-${Date.now()}`),
      description: description || `${title} — curated by the Flex Vault team.`,
      coverImage: mockProductImages(title, title, 1)[0],
      dropDate: target,
      countdownTarget: target,
      isActive: true,
    },
  });

  revalidatePath("/dashboard/admin/drops");
  return { success: true };
}

export async function toggleDropActive(id: string, isActive: boolean) {
  if (!(await assertAdmin())) return { error: "Not authorized." };
  await db.drop.update({ where: { id }, data: { isActive } });
  revalidatePath("/dashboard/admin/drops");
  return { success: true };
}

export async function deleteDrop(id: string) {
  if (!(await assertAdmin())) return { error: "Not authorized." };
  await db.drop.delete({ where: { id } });
  revalidatePath("/dashboard/admin/drops");
  return { success: true };
}

export async function addFeaturedProduct(dropId: string, productId: string) {
  if (!(await assertAdmin())) return { error: "Not authorized." };
  await db.dropProduct.upsert({
    where: { dropId_productId: { dropId, productId } },
    update: {},
    create: { dropId, productId },
  });
  revalidatePath("/dashboard/admin/drops");
  return { success: true };
}

export async function removeFeaturedProduct(dropProductId: string) {
  if (!(await assertAdmin())) return { error: "Not authorized." };
  await db.dropProduct.delete({ where: { id: dropProductId } });
  revalidatePath("/dashboard/admin/drops");
  return { success: true };
}
