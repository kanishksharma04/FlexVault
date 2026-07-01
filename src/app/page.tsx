import { Hero } from "@/components/landing/hero";
import { CategoryTiles } from "@/components/landing/category-tiles";
import { TrendingGrid } from "@/components/landing/trending-grid";
import { DropSection } from "@/components/landing/drop-section";
import { HowItWorks } from "@/components/landing/how-it-works";
import { Testimonials } from "@/components/landing/testimonials";
import { ClosingCta } from "@/components/landing/closing-cta";
import { getTrendingProducts, getActiveDrop, getCategoryCounts } from "@/lib/queries/catalog";

export default async function Home() {
  const [trending, drop, categories] = await Promise.all([
    getTrendingProducts(8),
    getActiveDrop(),
    getCategoryCounts(),
  ]);

  return (
    <>
      <Hero />
      <CategoryTiles
        categories={categories.map((c) => ({ slug: c.slug, name: c.name, icon: c.icon, count: c._count.products }))}
      />
      {drop && (
        <DropSection
          title={drop.title}
          slug={drop.slug}
          description={drop.description}
          coverImage={drop.coverImage}
          countdownTarget={drop.countdownTarget}
          products={drop.products}
        />
      )}
      <TrendingGrid products={trending} />
      <HowItWorks />
      <Testimonials />
      <ClosingCta />
    </>
  );
}
