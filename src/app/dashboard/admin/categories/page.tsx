import { db } from "@/lib/db";
import { CategoriesTable } from "@/components/admin/categories-table";

export const dynamic = "force-dynamic";

export default async function AdminCategoriesPage() {
  const categories = await db.category.findMany({
    orderBy: { name: "asc" },
    include: { parent: { select: { name: true } }, _count: { select: { products: true } } },
  });

  return <CategoriesTable categories={categories} />;
}
