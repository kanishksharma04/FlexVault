import { PrismaClient, ListingType, ListingStatus, AuthDecision, Condition } from "@prisma/client";
import { PRODUCT_IMAGE_OVERRIDES } from "../src/lib/product-images";
import { calcTrendScore, trendReasonSummary } from "../src/lib/business/trend";
import { generateCertificateHash } from "../src/lib/business/certificate";

const db = new PrismaClient();

function randInt(min: number, max: number) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
function randFloat(min: number, max: number) {
  return Math.round((Math.random() * (max - min) + min) * 10) / 10;
}
function pick<T>(arr: T[]): T {
  return arr[randInt(0, arr.length - 1)];
}
function slugify(s: string) {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "");
}

type NewAccessory = { name: string; brand: string; priceRange: [number, number] };

const newAccessories: NewAccessory[] = [{ name: "Saddle Bag", brand: "Dior", priceRange: [90000, 140000] }];

async function main() {
  const accessories = await db.category.findFirstOrThrow({ where: { slug: "accessories" } });
  const authenticator = await db.user.findFirstOrThrow({ where: { role: "AUTHENTICATOR" } });
  const sellers = await db.user.findMany({ where: { role: "SELLER" } });
  if (sellers.length === 0) throw new Error("No sellers found in DB");

  const conditions = [Condition.NEW, Condition.LIKE_NEW, Condition.USED_EXCELLENT, Condition.USED_GOOD];

  for (const item of newAccessories) {
    const fullName = `${item.brand} ${item.name}`;
    const images = PRODUCT_IMAGE_OVERRIDES[fullName];
    if (!images) throw new Error(`No sourced image for ${fullName}`);

    const existing = await db.product.findFirst({ where: { name: fullName } });
    if (existing) {
      console.log(`Skipping ${fullName} — already exists.`);
      continue;
    }

    const slug = slugify(`${fullName}-${randInt(1000, 9999)}`);
    const releaseDaysAgo = randInt(20, 900);
    const product = await db.product.create({
      data: {
        name: fullName,
        slug,
        brand: item.brand,
        categoryId: accessories.id,
        images,
        description: `Authenticated ${fullName}, verified by Flex Vault's multi-layer inspection process. Every unit is cross-checked against ${item.brand}'s construction, materials, and packaging references before it clears the vault.`,
        releaseDate: new Date(Date.now() - releaseDaysAgo * 86_400_000),
        sku: `FV-${slugify(item.brand)}-${randInt(10000, 99999)}`.toUpperCase(),
        baseTrendScore: randFloat(35, 90),
      },
    });

    // Trend history (14 days)
    let mv = randFloat(30, 70);
    let sent = randFloat(30, 70);
    let eng = randFloat(30, 70);
    const entries = [];
    for (let day = 13; day >= 0; day--) {
      mv = Math.max(0, Math.min(100, mv + randFloat(-12, 12)));
      sent = Math.max(0, Math.min(100, sent + randFloat(-10, 10)));
      eng = Math.max(0, Math.min(100, eng + randFloat(-12, 12)));
      const score = calcTrendScore({ mentionVelocity: mv, sentimentScore: sent, engagementGrowth: eng });
      entries.push({
        productId: product.id,
        score,
        mentionVelocity: mv,
        sentimentScore: sent,
        engagementGrowth: eng,
        reasonSummary: trendReasonSummary({ mentionVelocity: mv, sentimentScore: sent, engagementGrowth: eng }),
        calculatedAt: new Date(Date.now() - day * 86_400_000),
      });
    }
    await db.trendScore.createMany({ data: entries });

    // Listings — at least one ACTIVE so it surfaces in browse
    const numListings = randInt(2, 4);
    for (let i = 0; i < numListings; i++) {
      const seller = pick(sellers);
      const price = randInt(item.priceRange[0], item.priceRange[1]);
      const status = i === 0 ? ListingStatus.ACTIVE : pick([ListingStatus.ACTIVE, ListingStatus.SOLD, ListingStatus.PENDING_AUTH]);

      const listing = await db.listing.create({
        data: {
          sellerId: seller.id,
          productId: product.id,
          price,
          condition: pick(conditions),
          listingType: ListingType.FIXED,
          status,
          quantity: 1,
        },
      });

      if (status === ListingStatus.ACTIVE || status === ListingStatus.SOLD) {
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
      } else {
        await db.authenticationRecord.create({
          data: {
            listingId: listing.id,
            status: AuthDecision.PENDING,
            inspectionPhotos: product.images.slice(0, 2),
          },
        });
      }
    }

    console.log(`Created ${fullName} (${numListings} listings).`);
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
