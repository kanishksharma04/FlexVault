import { PrismaClient, ListingType, ListingStatus, AuthDecision, Condition } from "@prisma/client";
import { generateCertificateHash } from "../src/lib/business/certificate";

const db = new PrismaClient();

function randInt(min: number, max: number) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
function pick<T>(arr: T[]): T {
  return arr[randInt(0, arr.length - 1)];
}

async function main() {
  const authenticator = await db.user.findFirstOrThrow({ where: { role: "AUTHENTICATOR" } });
  const sellers = await db.user.findMany({ where: { role: "SELLER" } });
  if (sellers.length === 0) throw new Error("No sellers found in DB");

  const conditions = [Condition.NEW, Condition.LIKE_NEW, Condition.USED_EXCELLENT, Condition.USED_GOOD];

  const products = await db.product.findMany({
    where: { archivedAt: null },
    include: { listings: { select: { status: true, price: true } }, category: { select: { name: true } } },
  });

  const orphans = products.filter((p) => !p.listings.some((l) => l.status === "ACTIVE"));

  if (orphans.length === 0) {
    console.log("No orphaned products found — every product has an active listing.");
    await db.$disconnect();
    return;
  }

  console.log(`Found ${orphans.length} product(s) with no active listing.`);

  for (const product of orphans) {
    const prices = product.listings.map((l) => l.price);
    const [min, max] = prices.length > 0 ? [Math.min(...prices) * 0.92, Math.max(...prices) * 1.08] : [5000, 8000];

    const seller = pick(sellers);
    const price = randInt(Math.round(min), Math.round(max));

    const listing = await db.listing.create({
      data: {
        sellerId: seller.id,
        productId: product.id,
        price,
        condition: pick(conditions),
        listingType: ListingType.FIXED,
        status: ListingStatus.ACTIVE,
        size: product.subcategory ? pick(["UK6", "UK7", "UK8", "UK9", "UK10", "UK11"]) : undefined,
        quantity: 1,
      },
    });

    await db.authenticationRecord.create({
      data: {
        listingId: listing.id,
        authenticatorId: authenticator.id,
        status: AuthDecision.APPROVED,
        inspectionPhotos: product.images.slice(0, 2),
        notes: "Stitching, materials, and packaging match verified reference set. Cleared for listing.",
        certificateHash: generateCertificateHash(listing.id),
        reviewedAt: new Date(),
      },
    });

    console.log(`[${product.category.name}] Added active listing for ${product.name} at ₹${price}.`);
  }
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await db.$disconnect();
  });
