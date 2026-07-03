import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { suggestPriceRange } from "@/lib/business/pricing";
import { rateLimit } from "@/lib/rate-limit";

export async function GET(req: NextRequest) {
  const limited = await rateLimit(req, "pricing-suggestion", 20, "10 s");
  if (limited) return limited;

  const productId = req.nextUrl.searchParams.get("productId");
  if (!productId) return NextResponse.json({ error: "productId required" }, { status: 400 });

  const [product, soldOrders, latestTrend] = await Promise.all([
    db.product.findUnique({ where: { id: productId } }),
    db.order.findMany({
      where: { listing: { productId } },
      orderBy: { createdAt: "desc" },
      take: 10,
      select: { price: true },
    }),
    db.trendScore.findFirst({ where: { productId }, orderBy: { calculatedAt: "desc" } }),
  ]);

  if (!product) return NextResponse.json({ error: "Product not found" }, { status: 404 });

  const trendScore = latestTrend?.score ?? product.baseTrendScore;
  const soldPrices = soldOrders.map((o) => o.price);

  const fallbackPrices = soldPrices.length > 0 ? soldPrices : (await db.listing.findMany({
    where: { productId, status: "ACTIVE" },
    select: { price: true },
    take: 10,
  })).map((l) => l.price);

  const suggestion = suggestPriceRange(fallbackPrices, trendScore);
  return NextResponse.json({ ...suggestion, trendScore });
}
