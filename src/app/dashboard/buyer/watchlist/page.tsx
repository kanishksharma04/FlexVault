import { HeartOff } from "lucide-react";
import { auth } from "@/lib/auth";
import { getBuyerWatchlist } from "@/lib/queries/buyer";
import { EmptyState } from "@/components/vault/empty-state";
import { WatchlistGrid } from "@/components/dashboard/watchlist-grid";

export const dynamic = "force-dynamic";

export default async function WatchlistPage() {
  const session = await auth();
  if (!session?.user) return null;
  const watchlist = await getBuyerWatchlist(session.user.id);

  const items = watchlist
    .filter((w) => w.product)
    .map((w) => ({
      productId: w.product!.id,
      slug: w.product!.slug,
      name: w.product!.name,
      brand: w.product!.brand,
      images: w.product!.images,
      fromPrice: w.product!.listings[0]?.price ?? null,
      trendScore: w.product!.trendHistory[0]?.score ?? w.product!.baseTrendScore,
      listingCount: w.product!.listings.length,
    }));

  if (items.length === 0) {
    return <EmptyState icon={HeartOff} title="NOTHING SAVED" description="Watch items from the PDP to track them here." />;
  }

  return <WatchlistGrid items={items} />;
}
