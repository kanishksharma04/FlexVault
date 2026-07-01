"use server";

import { revalidatePath } from "next/cache";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";

export async function upgradeToPro() {
  const session = await auth();
  if (!session?.user) return { error: "Log in to upgrade." };

  await db.user.update({ where: { id: session.user.id }, data: { isProMember: true } });
  revalidatePath("/dashboard/seller/pro");
  revalidatePath("/dashboard/buyer");
  return { success: true };
}
