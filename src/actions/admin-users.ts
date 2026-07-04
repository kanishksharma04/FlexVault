"use server";

import { revalidatePath } from "next/cache";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { Role, SellerTier } from "@prisma/client";

async function assertAdmin() {
  const session = await auth();
  if (!session?.user || session.user.role !== "ADMIN") return null;
  return session;
}

export async function updateUser(id: string, data: { role?: Role; sellerTier?: SellerTier; isProMember?: boolean }) {
  const session = await assertAdmin();
  if (!session) return { error: "Not authorized." };
  if (data.role && !(Object.values(Role) as string[]).includes(data.role)) {
    return { error: "Invalid role." };
  }
  if (data.sellerTier && !(Object.values(SellerTier) as string[]).includes(data.sellerTier)) {
    return { error: "Invalid seller tier." };
  }
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
