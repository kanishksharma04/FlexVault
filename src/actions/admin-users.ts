"use server";

import { revalidatePath } from "next/cache";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import type { Role, SellerTier } from "@prisma/client";

async function assertAdmin() {
  const session = await auth();
  if (!session?.user || session.user.role !== "ADMIN") return null;
  return session;
}

export async function updateUser(id: string, data: { role?: Role; sellerTier?: SellerTier; isProMember?: boolean }) {
  const session = await assertAdmin();
  if (!session) return { error: "Not authorized." };
  if (session.user.id === id && data.role && data.role !== "ADMIN") {
    return { error: "You cannot remove your own admin role." };
  }
  await db.user.update({ where: { id }, data });
  revalidatePath("/dashboard/admin/users");
  return { success: true };
}

export async function archiveUser(id: string) {
  const session = await assertAdmin();
  if (!session) return { error: "Not authorized." };
  if (session.user.id === id) return { error: "You cannot archive your own account." };
  await db.user.update({ where: { id }, data: { archivedAt: new Date() } });
  revalidatePath("/dashboard/admin/users");
  return { success: true };
}
