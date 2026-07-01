import { db } from "@/lib/db";
import type { Condition, Prisma } from "@prisma/client";
import type { ProductCardData } from "@/components/vault/product-card";

export type SortOption = "trending" | "price_asc" | "price_desc" | "newest";

export type BrowseFilters = {
  categorySlug?: string;
  brands?: string[];
  sizes?: string[];
  conditions?: Condition[];
  minPrice?: number;
  maxPrice?: number;
  minTrend?: number;
  sort?: SortOption;
  page?: number;
  pageSize?: number;
  query?: string;
};

export async function getFilteredProducts(filters: BrowseFilters) {
  const pageSize = filters.pageSize ?? 24;
  const page = Math.max(1, filters.page ?? 1);

  const listingWhere: Prisma.ListingWhereInput = {
    status: "ACTIVE",
    ...(filters.sizes?.length ? { size: { in: filters.sizes } } : {}),
    ...(filters.conditions?.length ? { condition: { in: filters.conditions } } : {}),
    ...(filters.minPrice != null || filters.maxPrice != null
      ? { price: { gte: filters.minPrice ?? undefined, lte: filters.maxPrice ?? undefined } }
      : {}),
  };

  const where: Prisma.ProductWhereInput = {
    archivedAt: null,
    ...(filters.categorySlug ? { category: { slug: filters.categorySlug } } : {}),
    ...(filters.brands?.length ? { brand: { in: filters.brands } } : {}),
    ...(filters.minTrend != null ? { baseTrendScore: { gte: filters.minTrend } } : {}),
    ...(filters.query
      ? {
          OR: [
            { name: { contains: filters.query, mode: "insensitive" } },
            { brand: { contains: filters.query, mode: "insensitive" } },
          ],
        }
      : {}),
    listings: { some: listingWhere },
  };

  const orderBy: Prisma.ProductOrderByWithRelationInput =
    filters.sort === "newest"
      ? { releaseDate: "desc" }
      : filters.sort === "trending" || !filters.sort
      ? { baseTrendScore: "desc" }
      : { createdAt: "desc" }; // price sorts handled client-side after fetch below

  const [total, products] = await Promise.all([
    db.product.count({ where }),
    db.product.findMany({
      where,
      orderBy,
      skip: (page - 1) * pageSize,
      take: pageSize,
      include: {
        listings: { where: listingWhere, orderBy: { price: "asc" }, take: 1 },
        trendHistory: { orderBy: { calculatedAt: "desc" }, take: 1 },
      },
    }),
  ]);

  let cards: ProductCardData[] = products.map((p) => ({
    slug: p.slug,
    name: p.name,
    brand: p.brand,
    images: p.images,
    fromPrice: p.listings[0]?.price ?? null,
    trendScore: p.trendHistory[0]?.score ?? p.baseTrendScore,
    listingCount: p.listings.length,
  }));

  if (filters.sort === "price_asc") {
    cards = [...cards].sort((a, b) => (a.fromPrice ?? Infinity) - (b.fromPrice ?? Infinity));
  } else if (filters.sort === "price_desc") {
    cards = [...cards].sort((a, b) => (b.fromPrice ?? 0) - (a.fromPrice ?? 0));
  }

  return { products: cards, total, page, pageSize, pageCount: Math.max(1, Math.ceil(total / pageSize)) };
}

export async function getBrowseFacets(categorySlug?: string) {
  const where: Prisma.ProductWhereInput = {
    archivedAt: null,
    ...(categorySlug ? { category: { slug: categorySlug } } : {}),
  };

  const [brandsRaw, sizesRaw] = await Promise.all([
    db.product.findMany({ where, select: { brand: true }, distinct: ["brand"], orderBy: { brand: "asc" } }),
    db.listing.findMany({
      where: { status: "ACTIVE", product: where },
      select: { size: true },
      distinct: ["size"],
    }),
  ]);

  return {
    brands: brandsRaw.map((b) => b.brand),
    sizes: sizesRaw.map((s) => s.size).filter((s): s is string => Boolean(s)).sort(),
  };
}

export async function getProductBySlug(slug: string) {
  const product = await db.product.findUnique({
    where: { slug },
    include: {
      category: true,
      listings: {
        where: { status: "ACTIVE" },
        orderBy: { price: "asc" },
        include: {
          seller: { select: { id: true, name: true, sellerTier: true, image: true } },
          authenticationRecord: true,
          bids: { orderBy: { amount: "desc" }, take: 5, include: { bidder: { select: { name: true } } } },
        },
      },
      trendHistory: { orderBy: { calculatedAt: "asc" }, take: 14 },
    },
  });
  return product;
}

export async function getRelatedProducts(categoryId: string, excludeProductId: string, limit = 4): Promise<ProductCardData[]> {
  const products = await db.product.findMany({
    where: { categoryId, id: { not: excludeProductId }, archivedAt: null },
    take: limit,
    orderBy: { baseTrendScore: "desc" },
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
