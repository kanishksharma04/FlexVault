import Link from "next/link";
import Image from "next/image";
import { TrendGauge } from "@/components/vault/trend-gauge";
import type { ProductCardData } from "@/components/vault/product-card";

export function TrendGaugeCard({ product }: { product: ProductCardData }) {
  return (
    <Link
      href={`/product/${product.slug}`}
      className="card-hype group flex flex-col items-center gap-3 border border-border bg-card p-4 text-center"
    >
      <div className="relative size-16 shrink-0 overflow-hidden rounded-sm bg-vault-3">
        <Image src={product.images[0]} alt={product.name} fill className="object-cover transition-transform duration-300 group-hover:scale-110" />
      </div>
      <TrendGauge score={product.trendScore} size={88} />
      <div>
        <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">{product.brand}</p>
        <p className="line-clamp-2 text-sm font-semibold">{product.name}</p>
      </div>
    </Link>
  );
}
