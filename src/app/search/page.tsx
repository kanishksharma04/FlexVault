import { SearchX } from "lucide-react";
import { getFilteredProducts } from "@/lib/queries/browse";
import { ProductCard } from "@/components/vault/product-card";
import { EmptyState } from "@/components/vault/empty-state";
import { SearchBar } from "@/components/search/search-bar";

export const dynamic = "force-dynamic";

type Props = { searchParams: Promise<{ q?: string }> };

export default async function SearchPage({ searchParams }: Props) {
  const { q } = await searchParams;
  const query = q?.trim() ?? "";
  const { products, total } = query ? await getFilteredProducts({ query, pageSize: 40 }) : { products: [], total: 0 };

  return (
    <div className="mx-auto max-w-6xl px-4 py-10 sm:px-6">
      <div className="mx-auto max-w-xl">
        <SearchBar autoFocus />
      </div>

      {query && (
        <p className="mt-6 text-center font-mono text-xs text-muted-foreground">
          {total} result{total === 1 ? "" : "s"} for &ldquo;{query}&rdquo;
        </p>
      )}

      {query && products.length === 0 && (
        <EmptyState
          className="mt-10"
          icon={SearchX}
          title="NO MATCHES"
          description="Try a different brand, model, or SKU."
        />
      )}

      {products.length > 0 && (
        <div className="mt-8 grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-4">
          {products.map((p) => (
            <ProductCard key={p.slug} product={p} />
          ))}
        </div>
      )}
    </div>
  );
}
