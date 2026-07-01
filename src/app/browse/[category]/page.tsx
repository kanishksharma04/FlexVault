import { notFound } from "next/navigation";
import { PackageX } from "lucide-react";
import { db } from "@/lib/db";
import { getFilteredProducts, getBrowseFacets } from "@/lib/queries/browse";
import type { Condition } from "@prisma/client";
import { ProductCard } from "@/components/vault/product-card";
import { EmptyState } from "@/components/vault/empty-state";
import { FilterSidebar } from "@/components/browse/filter-sidebar";
import { SortSelect } from "@/components/browse/sort-select";
import {
  Pagination,
  PaginationContent,
  PaginationItem,
  PaginationLink,
  PaginationPrevious,
  PaginationNext,
} from "@/components/ui/pagination";

export const dynamic = "force-dynamic";

type Props = {
  params: Promise<{ category: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
};

function toArray(v: string | string[] | undefined): string[] {
  if (!v) return [];
  return Array.isArray(v) ? v : [v];
}

function pageHref(sp: Record<string, string | string[] | undefined>, page: number): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(sp)) {
    if (key === "page") continue;
    for (const v of toArray(value)) params.append(key, v);
  }
  params.set("page", String(page));
  return `?${params.toString()}`;
}

export default async function BrowseCategoryPage({ params, searchParams }: Props) {
  const { category: categorySlug } = await params;
  const sp = await searchParams;

  const category = await db.category.findUnique({ where: { slug: categorySlug } });
  if (!category) notFound();

  const filters = {
    categorySlug,
    brands: toArray(sp.brand),
    sizes: toArray(sp.size),
    conditions: toArray(sp.condition) as Condition[],
    minPrice: sp.minPrice ? Number(sp.minPrice) : undefined,
    maxPrice: sp.maxPrice ? Number(sp.maxPrice) : undefined,
    sort: (sp.sort as "trending" | "price_asc" | "price_desc" | "newest") ?? "trending",
    page: sp.page ? Number(sp.page) : 1,
  };

  const [{ products, total, page, pageCount }, facets] = await Promise.all([
    getFilteredProducts(filters),
    getBrowseFacets(categorySlug),
  ]);

  return (
    <div className="mx-auto max-w-7xl px-4 py-10 sm:px-6">
      <div className="mb-8 flex flex-col gap-1">
        <p className="font-mono text-xs uppercase tracking-widest text-acid">Browse</p>
        <h1 className="font-display text-4xl tracking-wide">{category.name.toUpperCase()}</h1>
        <p className="font-mono text-xs text-muted-foreground">{total} authenticated listings</p>
      </div>

      <div className="flex flex-col gap-8 lg:flex-row">
        <FilterSidebar brands={facets.brands} sizes={facets.sizes} />

        <div className="flex-1">
          <div className="mb-4 flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              Showing {products.length} of {total}
            </p>
            <SortSelect />
          </div>

          {products.length === 0 ? (
            <EmptyState
              icon={PackageX}
              title="NOTHING HERE — YET"
              description="No listings match those filters. Try widening your search."
            />
          ) : (
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 xl:grid-cols-4">
              {products.map((p) => (
                <ProductCard key={p.slug} product={p} />
              ))}
            </div>
          )}

          {pageCount > 1 && (
            <Pagination className="mt-10">
              <PaginationContent>
                {page > 1 && (
                  <PaginationItem>
                    <PaginationPrevious href={pageHref(sp, page - 1)} />
                  </PaginationItem>
                )}
                {Array.from({ length: pageCount }, (_, i) => i + 1).map((p) => (
                  <PaginationItem key={p}>
                    <PaginationLink href={pageHref(sp, p)} isActive={p === page}>
                      {p}
                    </PaginationLink>
                  </PaginationItem>
                ))}
                {page < pageCount && (
                  <PaginationItem>
                    <PaginationNext href={pageHref(sp, page + 1)} />
                  </PaginationItem>
                )}
              </PaginationContent>
            </Pagination>
          )}
        </div>
      </div>
    </div>
  );
}
