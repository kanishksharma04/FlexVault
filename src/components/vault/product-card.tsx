"use client";

import { useRef, useState } from "react";
import Image from "next/image";
import Link from "next/link";
import { motion, useMotionValue, useSpring, useTransform, useReducedMotion } from "framer-motion";
import { Flame } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { trendTemperature } from "@/lib/business/trend";
import { mockProductImage } from "@/lib/mock-image";

export type ProductCardData = {
  slug: string;
  name: string;
  brand: string;
  images: string[];
  fromPrice: number | null;
  trendScore: number;
  listingCount: number;
};

export function ProductCard({ product, className }: { product: ProductCardData; className?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const reducedMotion = useReducedMotion();

  const mvX = useMotionValue(0);
  const mvY = useMotionValue(0);
  const rotateX = useSpring(useTransform(mvY, [-0.5, 0.5], [8, -8]), { stiffness: 250, damping: 20 });
  const rotateY = useSpring(useTransform(mvX, [-0.5, 0.5], [-8, 8]), { stiffness: 250, damping: 20 });

  function onMouseMove(e: React.MouseEvent<HTMLDivElement>) {
    if (reducedMotion || !ref.current) return;
    const rect = ref.current.getBoundingClientRect();
    mvX.set((e.clientX - rect.left) / rect.width - 0.5);
    mvY.set((e.clientY - rect.top) / rect.height - 0.5);
  }

  function onMouseLeave() {
    mvX.set(0);
    mvY.set(0);
  }

  const temp = trendTemperature(product.trendScore);
  const secondaryImage = product.images[1] ?? product.images[0];
  const fallback = mockProductImage(product.name, product.name);
  const [primarySrc, setPrimarySrc] = useState(product.images[0]);
  const [secondarySrc, setSecondarySrc] = useState(secondaryImage);

  return (
    <motion.div
      ref={ref}
      onMouseMove={onMouseMove}
      onMouseLeave={onMouseLeave}
      style={{ rotateX: reducedMotion ? 0 : rotateX, rotateY: reducedMotion ? 0 : rotateY, transformPerspective: 800 }}
      className={cn("card-hype group relative flex flex-col bg-card", className)}
    >
      <Link href={`/product/${product.slug}`} className="flex flex-1 flex-col">
        <div className="relative aspect-square w-full overflow-hidden bg-vault-3">
          <Image
            src={primarySrc}
            alt={product.name}
            fill
            unoptimized={primarySrc.startsWith("data:")}
            onError={() => setPrimarySrc(fallback)}
            className="object-cover transition-opacity duration-300 group-hover:opacity-0"
            sizes="(max-width: 768px) 50vw, 25vw"
          />
          <Image
            src={secondarySrc}
            alt={`${product.name} alternate view`}
            fill
            unoptimized={secondarySrc.startsWith("data:")}
            onError={() => setSecondarySrc(fallback)}
            className="object-cover opacity-0 transition-opacity duration-300 group-hover:opacity-100"
            sizes="(max-width: 768px) 50vw, 25vw"
          />
          {(temp === "hot" || temp === "blazing") && (
            <Badge variant="hype" className="absolute left-2 top-2">
              <Flame />
              {temp === "blazing" ? "Blazing" : "Hot"}
            </Badge>
          )}
        </div>
        <div className="flex flex-1 flex-col gap-1 p-3">
          <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">{product.brand}</p>
          <p className="line-clamp-2 flex-1 text-sm font-semibold leading-snug">{product.name}</p>
          <div className="mt-1 flex items-center justify-between">
            <div>
              <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">From</p>
              <p className="font-mono text-sm font-bold text-acid">
                {product.fromPrice ? `₹${product.fromPrice.toLocaleString("en-IN")}` : "No listings"}
              </p>
            </div>
            <div className="text-right">
              <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">Trend</p>
              <p className="font-mono text-sm font-bold">{product.trendScore.toFixed(0)}</p>
            </div>
          </div>
        </div>
      </Link>
    </motion.div>
  );
}
