import { db } from "@/lib/db";

export async function getAdminProducts(query?: string, page = 1, pageSize = 20) {
  const where = {
    archivedAt: null,
    ...(query
      ? { OR: [{ name: { contains: query, mode: "insensitive" as const } }, { brand: { contains: query, mode: "insensitive" as const } }] }
      : {}),
  };

  const [total, products] = await Promise.all([
    db.product.count({ where }),
    db.product.findMany({
      where,
      orderBy: { createdAt: "desc" },
      skip: (page - 1) * pageSize,
      take: pageSize,
      include: { category: true, _count: { select: { listings: true } } },
    }),
  ]);

  return { products, total, pageCount: Math.max(1, Math.ceil(total / pageSize)) };
}
