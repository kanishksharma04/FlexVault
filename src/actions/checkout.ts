"use server";

import { revalidatePath } from "next/cache";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { SELLER_TIER_COMMISSION, INSURANCE_THRESHOLD_INR, INSURANCE_RATE, PRO_MEMBERSHIP_COMMISSION_DISCOUNT } from "@/lib/business/constants";

export type CheckoutState = {
  error?: string;
  success?: boolean;
  orderIds?: string[];
};

class ListingUnavailableError extends Error {}

export async function submitOrder(_prev: CheckoutState, formData: FormData): Promise<CheckoutState> {
  const session = await auth();
  if (!session?.user) return { error: "You must be logged in to check out." };

  const listingIds = formData.getAll("listingId").map(String);
  if (listingIds.length === 0) return { error: "Your cart is empty." };

  const insuranceListingIds = new Set(formData.getAll("insuranceListingId").map(String));

  const fullName = String(formData.get("fullName") ?? "").trim();
  const line1 = String(formData.get("line1") ?? "").trim();
  const line2 = String(formData.get("line2") ?? "").trim();
  const city = String(formData.get("city") ?? "").trim();
  const state = String(formData.get("state") ?? "").trim();
  const pincode = String(formData.get("pincode") ?? "").trim();
  const phone = String(formData.get("phone") ?? "").trim();

  if (!fullName || !line1 || !city || !state || !pincode || !phone) {
    return { error: "Fill in all required shipping fields." };
  }

  const listings = await db.listing.findMany({
    where: { id: { in: listingIds }, status: "ACTIVE" },
    include: { seller: true },
  });

  if (listings.length !== listingIds.length) {
    return { error: "One or more items in your cart are no longer available." };
  }

  const orderIds = await db.$transaction(async (tx) => {
    const address = await tx.address.create({
      data: { userId: session.user.id, fullName, line1, line2: line2 || null, city, state, pincode, phone },
    });

    const ids: string[] = [];

    for (const listing of listings) {
      const baseCommission = SELLER_TIER_COMMISSION[listing.seller.sellerTier];
      const commissionRate = listing.seller.isProMember
        ? Math.max(0.02, baseCommission - PRO_MEMBERSHIP_COMMISSION_DISCOUNT)
        : baseCommission;

      const insuranceOpted = listing.price >= INSURANCE_THRESHOLD_INR && insuranceListingIds.has(listing.id);
      const insuranceFee = insuranceOpted ? Math.round(listing.price * INSURANCE_RATE) : 0;

      // Conditional update so two concurrent checkouts can't both claim the
      // same listing — only the first to flip ACTIVE -> SOLD wins.
      const claimed = await tx.listing.updateMany({
        where: { id: listing.id, status: "ACTIVE" },
        data: { status: "SOLD" },
      });
      if (claimed.count === 0) throw new ListingUnavailableError();

      const order = await tx.order.create({
        data: {
          buyerId: session.user.id,
          listingId: listing.id,
          price: listing.price,
          commissionRate,
          insuranceOpted,
          insuranceFee,
          addressId: address.id,
          status: "PLACED",
          trackingEvents: [
            { status: "PLACED", label: "Order placed & payment secured in escrow", at: new Date().toISOString() },
          ],
        },
      });

      ids.push(order.id);
    }

    return ids;
  }).catch((err) => {
    if (err instanceof ListingUnavailableError) return null;
    throw err;
  });

  if (!orderIds) {
    return { error: "One or more items in your cart were just purchased by someone else." };
  }

  revalidatePath("/dashboard/buyer");
  return { success: true, orderIds };
}
