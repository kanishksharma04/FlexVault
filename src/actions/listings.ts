"use server";

import { revalidatePath } from "next/cache";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";

async function assertOwnsListing(listingId: string) {
  const session = await auth();
  if (!session?.user) return { session: null, listing: null };
  const listing = await db.listing.findUnique({ where: { id: listingId } });
  if (!listing || (listing.sellerId !== session.user.id && session.user.role !== "ADMIN")) {
    return { session, listing: null };
  }
  return { session, listing };
}

export async function updateListing(listingId: string, data: { price?: number; quantity?: number }) {
  const { listing } = await assertOwnsListing(listingId);
  if (!listing) return { error: "Not authorized to edit this listing." };

  if (data.price !== undefined && (!Number.isFinite(data.price) || data.price <= 0)) {
    return { error: "Enter a valid price." };
  }
  if (data.quantity !== undefined && (!Number.isFinite(data.quantity) || data.quantity <= 0)) {
    return { error: "Enter a valid quantity." };
  }

  await db.listing.update({ where: { id: listingId }, data });
  revalidatePath("/dashboard/seller/listings");
  return { success: true };
}

export async function archiveListing(listingId: string) {
  const { listing } = await assertOwnsListing(listingId);
  if (!listing) return { error: "Not authorized to archive this listing." };

  await db.listing.update({
    where: { id: listingId },
    data: { archivedAt: new Date(), status: "ARCHIVED" },
  });
  revalidatePath("/dashboard/seller/listings");
  return { success: true };
}
