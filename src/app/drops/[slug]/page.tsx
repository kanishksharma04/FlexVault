import { notFound } from "next/navigation";
import Image from "next/image";
import { db } from "@/lib/db";
import { Countdown } from "@/components/vault/countdown";
import { ProductCard, type ProductCardData } from "@/components/vault/product-card";
import { Badge } from "@/components/ui/badge";

export const dynamic = "force-dynamic";

type Props = { params: Promise<{ slug: string }> };

export default async function DropDetailPage({ params }: Props) {
  const { slug } = await params;
  const drop = await db.drop.findUnique({
    where: { slug },
    include: {
      featuredProducts: {
        include: {
          product: {
            include: {
              listings: { where: { status: "ACTIVE" }, orderBy: { price: "asc" }, take: 1 },
              trendHistory: { orderBy: { calculatedAt: "desc" }, take: 1 },
            },
          },
        },
      },
    },
  });
  if (!drop) notFound();

  const products: ProductCardData[] = drop.featuredProducts.map((fp) => ({
    slug: fp.product.slug,
    name: fp.product.name,
    brand: fp.product.brand,
    images: fp.product.images,
    fromPrice: fp.product.listings[0]?.price ?? null,
    trendScore: fp.product.trendHistory[0]?.score ?? fp.product.baseTrendScore,
    listingCount: fp.product.listings.length,
  }));

  return (
    <div>
      <div className="relative h-72 w-full overflow-hidden border-b border-border sm:h-96">
        <Image src={drop.coverImage} alt={drop.title} fill className="object-cover" priority />
        <div className="absolute inset-0 bg-gradient-to-t from-vault via-vault/60 to-transparent" />
        <div className="absolute inset-x-0 bottom-0 mx-auto flex max-w-6xl flex-col gap-3 px-4 pb-8 sm:px-6">
          {drop.isActive && <Badge variant="hype" className="w-fit">Active Drop</Badge>}
          <h1 className="font-display text-4xl tracking-wide sm:text-5xl">{drop.title}</h1>
          <p className="max-w-xl text-sm text-muted-foreground">{drop.description}</p>
        </div>
      </div>

      <div className="mx-auto max-w-6xl px-4 py-10 sm:px-6">
        {drop.isActive && (
          <div className="mb-10">
            <p className="mb-2 font-mono text-xs uppercase tracking-widest text-muted-foreground">
              Drop closes in
            </p>
            <Countdown target={drop.countdownTarget} />
          </div>
        )}

        <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-4">
          {products.map((p) => (
            <ProductCard key={p.slug} product={p} />
          ))}
        </div>
      </div>
    </div>
  );
}
