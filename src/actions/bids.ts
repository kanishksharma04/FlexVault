"use server";

import { revalidatePath } from "next/cache";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";

export type PlaceBidState = {
  error?: string;
  success?: boolean;
};

export async function placeBid(_prev: PlaceBidState, formData: FormData): Promise<PlaceBidState> {
  const session = await auth();
  if (!session?.user) return { error: "Log in to place a bid." };

  const listingId = String(formData.get("listingId") ?? "");
  const amount = Number(formData.get("amount"));
  const productSlug = String(formData.get("productSlug") ?? "");

  if (!listingId || !Number.isFinite(amount) || amount <= 0) {
    return { error: "Enter a valid bid amount." };
  }

  const listing = await db.listing.findUnique({
    where: { id: listingId },
    include: { bids: { orderBy: { amount: "desc" }, take: 1 } },
  });

  if (!listing || listing.listingType !== "AUCTION" || listing.status !== "ACTIVE") {
    return { error: "This auction is no longer active." };
  }
  if (listing.auctionEndsAt && listing.auctionEndsAt < new Date()) {
    return { error: "This auction has ended." };
  }

  const currentTop = listing.bids[0]?.amount ?? listing.price * 0.8;
  if (amount <= currentTop) {
    return { error: `Bid must be higher than ₹${currentTop.toLocaleString("en-IN")}.` };
  }

  await db.$transaction([
    db.bid.updateMany({
      where: { listingId, status: "ACTIVE" },
      data: { status: "OUTBID" },
    }),
    db.bid.create({
      data: { listingId, bidderId: session.user.id, amount, status: "ACTIVE" },
    }),
  ]);

  if (productSlug) revalidatePath(`/product/${productSlug}`);
  return { success: true };
}
