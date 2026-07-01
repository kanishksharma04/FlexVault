"use client";

import Link from "next/link";
import { motion } from "framer-motion";
import { ProductCard, type ProductCardData } from "@/components/vault/product-card";
import { SectionHeading } from "@/components/vault/section-heading";
import { Button } from "@/components/ui/button";

export function TrendingGrid({ products }: { products: ProductCardData[] }) {
  if (products.length === 0) return null;
  return (
    <section className="mx-auto max-w-7xl px-4 py-16 sm:px-6">
      <div className="flex items-end justify-between">
        <SectionHeading eyebrow="Hype Spike" title="TRENDING NOW" />
        <Button asChild variant="link" className="hidden sm:inline-flex">
          <Link href="/trend">View hype feed →</Link>
        </Button>
      </div>
      <div className="mt-8 grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-4">
        {products.map((p, i) => (
          <motion.div
            key={p.slug}
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: (i % 4) * 0.08 }}
          >
            <ProductCard product={p} />
          </motion.div>
        ))}
      </div>
    </section>
  );
}
