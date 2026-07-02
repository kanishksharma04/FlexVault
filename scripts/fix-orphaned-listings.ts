import { PrismaClient, ListingType, ListingStatus, AuthDecision, Condition } from "@prisma/client";
import { generateCertificateHash } from "../src/lib/business/certificate";

const db = new PrismaClient();

function randInt(min: number, max: number) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
function pick<T>(arr: T[]): T {
  return arr[randInt(0, arr.length - 1)];
}

type Fix = { name: string; priceRange: [number, number] };

const fixes: Fix[] = [
  { name: "Jordan Air Jordan 4 Retro White Cement", priceRange: [22000, 36000] },
  { name: "Jordan Air Jordan 11 Retro Cool Grey", priceRange: [24000, 40000] },
  { name: "Puma Suede Classic XXI", priceRange: [4500, 7000] },
];

async function main() {
  const authenticator = await db.user.findFirstOrThrow({ where: { role: "AUTHENTICATOR" } });
  const sellers = await db.user.findMany({ where: { role: "SELLER" } });
  if (sellers.length === 0) throw new Error("No sellers found in DB");

  const conditions = [Condition.NEW, Condition.LIKE_NEW, Condition.USED_EXCELLENT, Condition.USED_GOOD];

  for (const fix of fixes) {
    const product = await db.product.findFirst({ where: { name: fix.name } });
    if (!product) {
      console.log(`Skipping ${fix.name} — not found.`);
      continue;
    }

    const existingActive = await db.listing.findFirst({ where: { productId: product.id, status: ListingStatus.ACTIVE } });
    if (existingActive) {
      console.log(`Skipping ${fix.name} — already has an active listing.`);
      continue;
    }

    const seller = pick(sellers);
    const price = randInt(fix.priceRange[0], fix.priceRange[1]);
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

    console.log(`Added active listing for ${fix.name} at ₹${price}.`);
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
