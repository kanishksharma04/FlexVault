"use client";

import Link from "next/link";
import { motion } from "framer-motion";
import { Footprints, Car, Shirt, Gem, Watch, FlaskConical, type LucideIcon } from "lucide-react";
import { SectionHeading } from "@/components/vault/section-heading";

const ICONS: Record<string, LucideIcon> = {
  footprints: Footprints,
  car: Car,
  shirt: Shirt,
  gem: Gem,
  watch: Watch,
  "flask-conical": FlaskConical,
};

export type CategoryTile = { slug: string; name: string; icon: string | null; count: number };

export function CategoryTiles({ categories }: { categories: CategoryTile[] }) {
  return (
    <section className="mx-auto max-w-7xl px-4 py-16 sm:px-6">
      <SectionHeading eyebrow="Browse" title="SHOP BY CATEGORY" />
      <div className="mt-8 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {categories.map((c, i) => {
          const Icon = ICONS[c.icon ?? ""] ?? Gem;
          return (
            <motion.div
              key={c.slug}
              initial={{ opacity: 0, y: 16 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.06 }}
            >
              <Link
                href={`/browse/${c.slug}`}
                className="card-hype group flex flex-col items-center gap-3 border border-border bg-card px-4 py-8 text-center"
              >
                <Icon className="size-7 text-muted-foreground transition-colors group-hover:text-acid" />
                <span className="font-display text-sm tracking-wide">{c.name}</span>
                <span className="font-mono text-[10px] text-muted-foreground">{c.count} items</span>
              </Link>
            </motion.div>
          );
        })}
      </div>
    </section>
  );
}
