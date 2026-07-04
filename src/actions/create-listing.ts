"use server";

import { revalidatePath } from "next/cache";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { Condition, ListingType } from "@prisma/client";

export type CreateListingState = {
  error?: string;
  success?: boolean;
  listingId?: string;
};

export async function createListing(_prev: CreateListingState, formData: FormData): Promise<CreateListingState> {
  const session = await auth();
  if (!session?.user || (session.user.role !== "SELLER" && session.user.role !== "ADMIN")) {
    return { error: "You must be logged in as a seller to list an item." };
  }

  const productId = String(formData.get("productId") ?? "");
  const price = Number(formData.get("price"));
  const quantity = Number(formData.get("quantity") ?? 1);
  const conditionInput = String(formData.get("condition") ?? "NEW");
  const listingTypeInput = String(formData.get("listingType") ?? "FIXED");
  const size = String(formData.get("size") ?? "").trim() || null;
  const photos = formData.getAll("photoUrl").map(String).filter(Boolean);

  if (!productId) return { error: "Select a product to list." };
  if (!Number.isFinite(price) || price <= 0) return { error: "Enter a valid price." };
  if (photos.length === 0) return { error: "Upload at least one inspection photo." };
  if (!(Object.values(Condition) as string[]).includes(conditionInput)) {
    return { error: "Select a valid condition." };
  }
  if (!(Object.values(ListingType) as string[]).includes(listingTypeInput)) {
    return { error: "Select a valid listing type." };
  }
  const condition = conditionInput as Condition;
  const listingType = listingTypeInput as ListingType;

  const product = await db.product.findUnique({ where: { id: productId } });
  if (!product) return { error: "Product not found." };

  const auctionEndsAt = listingType === "AUCTION" ? new Date(Date.now() + 5 * 86_400_000) : null;
  const preorderShipsAt = listingType === "PREORDER" ? new Date(Date.now() + 21 * 86_400_000) : null;

  const listing = await db.listing.create({
    data: {
      sellerId: session.user.id,
      productId,
      price,
      quantity: Number.isFinite(quantity) && quantity > 0 && quantity <= 999 ? quantity : 1,
      condition,
      listingType,
      size,
      status: "PENDING_AUTH",
      auctionEndsAt,
      preorderShipsAt,
    },
  });

  await db.authenticationRecord.create({
    data: {
      listingId: listing.id,
      status: "PENDING",
      inspectionPhotos: photos,
    },
  });

  revalidatePath("/dashboard/seller/listings");
  return { success: true, listingId: listing.id };
}
