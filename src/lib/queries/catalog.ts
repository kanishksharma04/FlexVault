import { db } from "@/lib/db";
import type { ProductCardData } from "@/components/vault/product-card";

export async function getTrendingProducts(limit = 8): Promise<ProductCardData[]> {
  const products = await db.product.findMany({
    where: { archivedAt: null },
    orderBy: { baseTrendScore: "desc" },
    take: limit,
    include: {
      listings: { where: { status: "ACTIVE" }, orderBy: { price: "asc" }, take: 1 },
      trendHistory: { orderBy: { calculatedAt: "desc" }, take: 1 },
    },
  });

  return products.map((p) => ({
    slug: p.slug,
    name: p.name,
    brand: p.brand,
    images: p.images,
    fromPrice: p.listings[0]?.price ?? null,
    trendScore: p.trendHistory[0]?.score ?? p.baseTrendScore,
    listingCount: p.listings.length,
  }));
}

export async function getActiveDrop() {
  return db.drop.findFirst({
    where: { isActive: true },
    orderBy: { dropDate: "asc" },
  });
}

export async function getCategoryCounts() {
  const categories = await db.category.findMany({
    where: { parentId: null },
    include: { _count: { select: { products: true } } },
    orderBy: { name: "asc" },
  });
  return categories;
}
