import { PrismaClient } from "@prisma/client";

const db = new PrismaClient();

const FEATURED_COUNT = 5;

async function main() {
  const drop = await db.drop.findFirst({ where: { isActive: true }, orderBy: { dropDate: "asc" } });
  if (!drop) {
    console.log("No active drop found — nothing to refresh.");
    await db.$disconnect();
    return;
  }

  const trending = await db.product.findMany({
    where: { archivedAt: null, listings: { some: { status: "ACTIVE" } } },
    orderBy: { baseTrendScore: "desc" },
    take: FEATURED_COUNT,
    select: { id: true, name: true, baseTrendScore: true },
  });

  await db.$transaction([
    db.dropProduct.deleteMany({ where: { dropId: drop.id } }),
    db.dropProduct.createMany({
      data: trending.map((p) => ({ dropId: drop.id, productId: p.id })),
    }),
  ]);

  console.log(`Refreshed "${drop.title}" with the current top ${trending.length} trending products:`);
  for (const p of trending) console.log(`  - ${p.name} (trend ${p.baseTrendScore.toFixed(1)})`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await db.$disconnect();
  });
