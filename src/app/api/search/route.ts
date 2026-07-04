import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { rateLimit } from "@/lib/rate-limit";

export async function GET(req: NextRequest) {
  const limited = await rateLimit(req, "search", 20, "10 s");
  if (limited) return limited;

  const q = (req.nextUrl.searchParams.get("q")?.trim() ?? "").slice(0, 100);
  const category = req.nextUrl.searchParams.get("category")?.trim() || undefined;
  if (q.length < 2) return NextResponse.json({ results: [] });

  const products = await db.product.findMany({
    where: {
      archivedAt: null,
      ...(category ? { category: { slug: category } } : {}),
      OR: [
        { name: { contains: q, mode: "insensitive" } },
        { brand: { contains: q, mode: "insensitive" } },
        { subcategory: { contains: q, mode: "insensitive" } },
      ],
    },
    take: 8,
    select: { id: true, slug: true, name: true, brand: true, images: true },
  });

  return NextResponse.json({
    results: products.map((p) => ({ id: p.id, slug: p.slug, name: p.name, brand: p.brand, image: p.images[0] })),
  });
}
