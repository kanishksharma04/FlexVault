"use server";

import { revalidatePath } from "next/cache";
import { Prisma } from "@prisma/client";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { rateLimitAction } from "@/lib/rate-limit";

export type PlaceBidState = {
  error?: string;
  success?: boolean;
};

export async function placeBid(_prev: PlaceBidState, formData: FormData): Promise<PlaceBidState> {
  const session = await auth();
  if (!session?.user) return { error: "Log in to place a bid." };

  const limitError = await rateLimitAction("place-bid", 10, "10 s");
  if (limitError) return { error: limitError };

  const listingId = String(formData.get("listingId") ?? "");
  const amount = Number(formData.get("amount"));
  const productSlug = String(formData.get("productSlug") ?? "");

  if (!listingId || !Number.isFinite(amount) || amount <= 0) {
    return { error: "Enter a valid bid amount." };
  }

  // The top-bid check and the write both happen inside one Serializable
  // transaction, so two bids racing to beat the same current top can't both
  // succeed — Postgres aborts the loser with a serialization failure (P2034)
  // instead of silently accepting two "highest" bids.
  let result: PlaceBidState;
  try {
    result = await db.$transaction(
      async (tx) => {
        const listing = await tx.listing.findUnique({
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

        await tx.bid.updateMany({
          where: { listingId, status: "ACTIVE" },
          data: { status: "OUTBID" },
        });
        await tx.bid.create({
          data: { listingId, bidderId: session.user.id, amount, status: "ACTIVE" },
        });

        return { success: true };
      },
      { isolationLevel: Prisma.TransactionIsolationLevel.Serializable }
    );
  } catch (err) {
    if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2034") {
      return { error: "Someone else bid at the same moment — please try again." };
    }
    throw err;
  }

  if (result.success && productSlug) revalidatePath(`/product/${productSlug}`);
  return result;
}
