"use client";

import Image from "next/image";
import Link from "next/link";
import { motion } from "framer-motion";
import { Countdown } from "@/components/vault/countdown";
import { ProductCard, type ProductCardData } from "@/components/vault/product-card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

type DropSectionProps = {
  title: string;
  slug: string;
  description: string;
  coverImage: string;
  countdownTarget: Date;
  products: ProductCardData[];
};

export function DropSection({ title, slug, description, coverImage, countdownTarget, products }: DropSectionProps) {
  return (
    <section className="border-y border-border bg-vault-2">
      <div className="mx-auto max-w-7xl px-4 py-16 sm:px-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="grid gap-8 lg:grid-cols-[1.1fr_1fr] lg:items-center"
        >
          <div className="relative aspect-[16/10] overflow-hidden rounded-md border border-border">
            <Image src={coverImage} alt={title} fill className="object-cover" />
            <div className="absolute inset-0 bg-gradient-to-t from-vault via-transparent to-transparent" />
            <Badge variant="hype" className="absolute left-4 top-4">
              Active Drop
            </Badge>
          </div>
          <div className="flex flex-col gap-4">
            <p className="font-mono text-xs uppercase tracking-widest text-acid">Pre-order now</p>
            <h2 className="font-display text-3xl tracking-wide sm:text-4xl">{title}</h2>
            <p className="text-sm text-muted-foreground">{description}</p>
            <Countdown target={countdownTarget} />
            <Button asChild size="lg" className="mt-2 w-fit">
              <Link href={`/drops/${slug}`}>View the drop</Link>
            </Button>
          </div>
        </motion.div>

        {products.length > 0 && (
          <div className="mt-12 grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
            {products.map((p) => (
              <ProductCard key={p.slug} product={p} />
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
