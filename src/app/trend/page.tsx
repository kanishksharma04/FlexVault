import { Flame } from "lucide-react";
import { getHypeSpikeFeed, getTrendingGrid } from "@/lib/queries/trend";
import { SectionHeading } from "@/components/vault/section-heading";
import { CategoryFilterTabs } from "@/components/trend/category-filter-tabs";
import { HypeSpikeFeed } from "@/components/trend/hype-spike-feed";
import { TrendGaugeCard } from "@/components/trend/trend-gauge-card";

export const dynamic = "force-dynamic";

type Props = { searchParams: Promise<{ category?: string }> };

export default async function TrendPage({ searchParams }: Props) {
  const { category } = await searchParams;

  const [spikes, grid] = await Promise.all([
    getHypeSpikeFeed(20, category),
    getTrendingGrid(12, category),
  ]);

  return (
    <div className="mx-auto max-w-6xl px-4 py-10 sm:px-6">
      <div className="mb-8 flex items-center gap-2">
        <Flame className="size-6 text-hype" />
        <SectionHeading eyebrow="Live" title="HYPE FEED" description="Real-time trend spikes across the vault." />
      </div>

      <CategoryFilterTabs />

      <div className="mt-8 grid gap-8 lg:grid-cols-[1fr_1.4fr]">
        <div>
          <h3 className="mb-3 font-mono text-xs uppercase tracking-widest text-muted-foreground">
            Hype Spike Detected
          </h3>
          <HypeSpikeFeed entries={spikes} />
        </div>

        <div>
          <h3 className="mb-3 font-mono text-xs uppercase tracking-widest text-muted-foreground">Trending Now</h3>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            {grid.map((p) => (
              <TrendGaugeCard key={p.slug} product={p} />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
