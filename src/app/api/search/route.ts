import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";

export async function GET(req: NextRequest) {
  const q = req.nextUrl.searchParams.get("q")?.trim() ?? "";
  const category = req.nextUrl.searchParams.get("category")?.trim() || undefined;
  if (q.length < 2) return NextResponse.json({ results: [] });

  const products = await db.product.findMany({
    where: {
      archivedAt: null,
      ...(category ? { category: { slug: category } } : {}),
      OR: [
        { name: { contains: q, mode: "insensitive" } },
        { brand: { contains: q, mode: "insensitive" } },
      ],
    },
    take: 8,
    select: { id: true, slug: true, name: true, brand: true, images: true },
  });

  return NextResponse.json({
    results: products.map((p) => ({ id: p.id, slug: p.slug, name: p.name, brand: p.brand, image: p.images[0] })),
  });
}
