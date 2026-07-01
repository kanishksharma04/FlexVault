"use server";

import { revalidatePath } from "next/cache";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";

export async function toggleWatchlist(productId: string, productSlug: string) {
  const session = await auth();
  if (!session?.user) return { error: "Log in to save items to your watchlist." };

  const existing = await db.watchlistItem.findUnique({
    where: { userId_productId: { userId: session.user.id, productId } },
  });

  if (existing) {
    await db.watchlistItem.delete({ where: { id: existing.id } });
    revalidatePath(`/product/${productSlug}`);
    return { watching: false };
  }

  await db.watchlistItem.create({ data: { userId: session.user.id, productId } });
  revalidatePath(`/product/${productSlug}`);
  return { watching: true };
}
