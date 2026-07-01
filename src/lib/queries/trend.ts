import { db } from "@/lib/db";
import type { ProductCardData } from "@/components/vault/product-card";

export type HypeTickerEntry = {
  productId: string;
  productSlug: string;
  productName: string;
  brand: string;
  image: string;
  score: number;
  delta: number;
  calculatedAt: Date;
};

export async function getHypeTicker(limit = 20, categorySlug?: string): Promise<HypeTickerEntry[]> {
  const products = await db.product.findMany({
    where: { archivedAt: null, ...(categorySlug ? { category: { slug: categorySlug } } : {}) },
    select: {
      id: true,
      slug: true,
      name: true,
      brand: true,
      images: true,
      trendHistory: {
        orderBy: { calculatedAt: "desc" },
        take: 2,
      },
    },
    take: limit * 3,
  });

  const entries = products
    .filter((p) => p.trendHistory.length > 0)
    .map((p) => {
      const [latest, previous] = p.trendHistory;
      return {
        productId: p.id,
        productSlug: p.slug,
        productName: p.name,
        brand: p.brand,
        image: p.images[0],
        score: latest.score,
        delta: previous ? Math.round((latest.score - previous.score) * 10) / 10 : 0,
        calculatedAt: latest.calculatedAt,
      };
    })
    .sort((a, b) => Math.abs(b.delta) - Math.abs(a.delta));

  return entries.slice(0, limit);
}

export async function getTrendHistory(productId: string, days = 14) {
  return db.trendScore.findMany({
    where: { productId },
    orderBy: { calculatedAt: "asc" },
    take: days,
  });
}

export async function getHypeSpikeFeed(limit = 30, categorySlug?: string) {
  const entries = await getHypeTicker(limit * 2, categorySlug);
  return entries.filter((e) => Math.abs(e.delta) >= 3).slice(0, limit);
}

export async function getTrendingGrid(limit = 12, categorySlug?: string): Promise<ProductCardData[]> {
  const products = await db.product.findMany({
    where: { archivedAt: null, ...(categorySlug ? { category: { slug: categorySlug } } : {}) },
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
