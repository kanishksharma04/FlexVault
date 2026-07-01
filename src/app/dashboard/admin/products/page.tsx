import { db } from "@/lib/db";
import { getAdminProducts } from "@/lib/queries/admin-products";
import { ProductsTable } from "@/components/admin/products-table";
import { AdminSearchBar } from "@/components/admin/admin-search-bar";
import {
  Pagination, PaginationContent, PaginationItem, PaginationLink, PaginationPrevious, PaginationNext,
} from "@/components/ui/pagination";

export const dynamic = "force-dynamic";

type Props = { searchParams: Promise<{ q?: string; page?: string }> };

export default async function AdminProductsPage({ searchParams }: Props) {
  const sp = await searchParams;
  const page = sp.page ? Number(sp.page) : 1;

  const [{ products, total, pageCount }, categories] = await Promise.all([
    getAdminProducts(sp.q, page),
    db.category.findMany({ orderBy: { name: "asc" } }),
  ]);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <AdminSearchBar placeholder="Search products..." />
        <p className="font-mono text-xs text-muted-foreground">{total} products</p>
      </div>

      <ProductsTable products={products} categories={categories} />

      {pageCount > 1 && (
        <Pagination>
          <PaginationContent>
            {page > 1 && <PaginationItem><PaginationPrevious href={`?page=${page - 1}`} /></PaginationItem>}
            {Array.from({ length: pageCount }, (_, i) => i + 1).map((p) => (
              <PaginationItem key={p}>
                <PaginationLink href={`?page=${p}`} isActive={p === page}>{p}</PaginationLink>
              </PaginationItem>
            ))}
            {page < pageCount && <PaginationItem><PaginationNext href={`?page=${page + 1}`} /></PaginationItem>}
          </PaginationContent>
        </Pagination>
      )}
    </div>
  );
}
