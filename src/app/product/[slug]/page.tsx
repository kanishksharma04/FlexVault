import { notFound } from "next/navigation";
import type { Metadata } from "next";
import { getProductBySlug, getRelatedProducts } from "@/lib/queries/browse";
import { ImageGallery } from "@/components/pdp/image-gallery";
import { ListingsPanel } from "@/components/pdp/listings-panel";
import { CertificatePreview } from "@/components/pdp/certificate-preview";
import { WatchlistButton } from "@/components/pdp/watchlist-button";
import { TrendGauge } from "@/components/vault/trend-gauge";
import { TrendSparkline } from "@/components/vault/trend-sparkline";
import { SectionHeading } from "@/components/vault/section-heading";
import { ProductCard } from "@/components/vault/product-card";
import { Badge } from "@/components/ui/badge";
import { trendReasonSummary } from "@/lib/business/trend";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";

export const dynamic = "force-dynamic";

const SITE_URL = "https://flex-vault.vercel.app";

const CONDITION_SCHEMA: Record<string, string> = {
  NEW: "https://schema.org/NewCondition",
  LIKE_NEW: "https://schema.org/UsedCondition",
  USED_EXCELLENT: "https://schema.org/UsedCondition",
  USED_GOOD: "https://schema.org/UsedCondition",
  USED_FAIR: "https://schema.org/UsedCondition",
};

function buildProductJsonLd(product: NonNullable<Awaited<ReturnType<typeof getProductBySlug>>>) {
  const url = `${SITE_URL}/product/${product.slug}`;
  const images = product.images.filter((src) => src.startsWith("http"));
  const prices = product.listings.map((l) => l.price);

  const offers =
    product.listings.length === 0
      ? { "@type": "Offer", priceCurrency: "INR", availability: "https://schema.org/OutOfStock", url }
      : product.listings.length === 1
        ? {
            "@type": "Offer",
            price: product.listings[0].price,
            priceCurrency: "INR",
            availability: "https://schema.org/InStock",
            itemCondition: CONDITION_SCHEMA[product.listings[0].condition],
            url,
          }
        : {
            "@type": "AggregateOffer",
            lowPrice: Math.min(...prices),
            highPrice: Math.max(...prices),
            offerCount: product.listings.length,
            priceCurrency: "INR",
            availability: "https://schema.org/InStock",
            url,
          };

  return {
    "@context": "https://schema.org",
    "@type": "Product",
    name: product.name,
    description: product.description,
    sku: product.sku,
    brand: { "@type": "Brand", name: product.brand },
    category: product.category.name,
    url,
    ...(images.length > 0 && { image: images }),
    offers,
  };
}

type Props = { params: Promise<{ slug: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { slug } = await params;
  const product = await getProductBySlug(slug);
  if (!product) return {};
  return {
    title: `${product.name} | Flex Vault`,
    description: product.description,
  };
}

export default async function ProductPage({ params }: Props) {
  const { slug } = await params;
  const product = await getProductBySlug(slug);
  if (!product) notFound();

  const related = await getRelatedProducts(product.categoryId, product.id, 4);
  const latestTrend = product.trendHistory[product.trendHistory.length - 1];
  const trendScore = latestTrend?.score ?? product.baseTrendScore;
  const reasonSummary =
    latestTrend?.reasonSummary ??
    (latestTrend
      ? trendReasonSummary({
          mentionVelocity: latestTrend.mentionVelocity,
          sentimentScore: latestTrend.sentimentScore,
          engagementGrowth: latestTrend.engagementGrowth,
        })
      : "Not enough data yet.");

  const approvedListing = product.listings.find((l) => l.authenticationRecord?.status === "APPROVED" && l.authenticationRecord.certificateHash);

  const session = await auth();
  const isWatching = session?.user
    ? Boolean(
        await db.watchlistItem.findUnique({
          where: { userId_productId: { userId: session.user.id, productId: product.id } },
        })
      )
    : false;

  const jsonLd = buildProductJsonLd(product);

  return (
    <div className="mx-auto max-w-6xl px-4 py-10 sm:px-6">
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd).replace(/</g, "\\u003c") }}
      />
      <div className="grid gap-10 lg:grid-cols-2">
        <ImageGallery images={product.images} alt={product.name} />

        <div className="flex flex-col gap-5">
          <div className="flex items-start justify-between gap-3">
            <div>
              <p className="font-mono text-xs uppercase tracking-widest text-acid">{product.brand}</p>
              <h1 className="font-display text-3xl tracking-wide sm:text-4xl">{product.name}</h1>
              <p className="mt-1 font-mono text-[11px] text-muted-foreground">SKU {product.sku}</p>
            </div>
            <WatchlistButton productId={product.id} productSlug={product.slug} initialWatching={isWatching} />
          </div>

          <div className="flex flex-col gap-4 border border-border bg-card p-4 sm:flex-row sm:items-center sm:gap-6">
            <TrendGauge score={trendScore} size={96} className="self-center sm:self-auto" />
            <div className="min-w-0 flex-1">
              <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">Why it&apos;s trending</p>
              <p className="mt-1 text-sm text-foreground/90">{reasonSummary}</p>
              {product.trendHistory.length > 1 && (
                <TrendSparkline
                  points={product.trendHistory.map((t) => t.score)}
                  width={240}
                  height={48}
                  className="mt-2"
                />
              )}
            </div>
          </div>

          {product.listings.length === 0 ? (
            <Badge variant="outline" className="w-fit">
              No active listings — check back soon
            </Badge>
          ) : (
            <ListingsPanel listings={product.listings} product={product} />
          )}

          <p className="text-sm leading-relaxed text-muted-foreground">{product.description}</p>
        </div>
      </div>

      {approvedListing?.authenticationRecord?.certificateHash && (
        <div className="mt-10">
          <SectionHeading eyebrow="Trust" title="CERTIFICATE PREVIEW" className="mb-4" />
          <CertificatePreview
            certificateHash={approvedListing.authenticationRecord.certificateHash}
            listingId={approvedListing.id}
          />
        </div>
      )}

      {related.length > 0 && (
        <div className="mt-14">
          <SectionHeading eyebrow="More" title="YOU MIGHT ALSO LIKE" className="mb-6" />
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            {related.map((p) => (
              <ProductCard key={p.slug} product={p} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
