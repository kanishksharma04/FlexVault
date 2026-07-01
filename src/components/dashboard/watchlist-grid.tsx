"use client";

import { useTransition } from "react";
import { X } from "lucide-react";
import { toast } from "sonner";
import { ProductCard, type ProductCardData } from "@/components/vault/product-card";
import { toggleWatchlist } from "@/actions/watchlist";
import { useRouter } from "next/navigation";

export function WatchlistGrid({ items }: { items: (ProductCardData & { productId: string })[] }) {
  const [pending, startTransition] = useTransition();
  const router = useRouter();

  return (
    <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-4">
      {items.map((item) => (
        <div key={item.slug} className="relative">
          <button
            disabled={pending}
            onClick={() =>
              startTransition(async () => {
                await toggleWatchlist(item.productId, item.slug);
                toast.success("Removed from watchlist.");
                router.refresh();
              })
            }
            className="absolute right-2 top-2 z-10 flex size-7 items-center justify-center rounded-full border border-border bg-vault/80 text-muted-foreground backdrop-blur transition hover:border-hype hover:text-hype"
            aria-label="Remove from watchlist"
          >
            <X className="size-3.5" />
          </button>
          <ProductCard product={item} />
        </div>
      ))}
    </div>
  );
}
