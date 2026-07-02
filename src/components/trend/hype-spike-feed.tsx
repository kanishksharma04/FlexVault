"use client";

import Link from "next/link";
import Image from "next/image";
import { motion } from "framer-motion";
import { Flame, TrendingDown } from "lucide-react";
import { relativeTime } from "@/lib/relative-time";
import type { HypeTickerEntry } from "@/lib/queries/trend";

export function HypeSpikeFeed({ entries }: { entries: HypeTickerEntry[] }) {
  if (entries.length === 0) {
    return <p className="text-sm text-muted-foreground">No major hype spikes right now — check back soon.</p>;
  }

  return (
    <div className="flex flex-col gap-2">
      {entries.map((e, i) => {
        const rising = e.delta >= 0;
        return (
          <motion.div
            key={`${e.productId}-${e.calculatedAt}`}
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: Math.min(i * 0.04, 0.6) }}
          >
            <Link
              href={`/product/${e.productSlug}`}
              className="group flex items-center gap-3 border border-border bg-card p-3 transition duration-200 hover:translate-x-1 hover:border-acid"
            >
              <div
                className={`flex size-9 shrink-0 items-center justify-center rounded-full transition-transform duration-200 group-hover:scale-110 ${rising ? "bg-hype/15 text-hype" : "bg-vault-3 text-muted-foreground"}`}
              >
                {rising ? <Flame className="size-4" /> : <TrendingDown className="size-4" />}
              </div>
              <div className="relative size-10 shrink-0 overflow-hidden rounded-sm bg-vault-3">
                <Image src={e.image} alt={e.productName} fill className="object-cover" />
              </div>
              <div className="flex-1">
                <p className="text-sm">
                  <span className="font-semibold">{e.productName}</span>{" "}
                  <span className="text-muted-foreground">
                    {rising ? "spiked" : "cooled"} {rising ? "+" : ""}
                    {e.delta.toFixed(1)} pts
                  </span>
                </p>
                <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                  {e.brand} · {relativeTime(e.calculatedAt)}
                </p>
              </div>
              <span className={`font-mono text-lg font-bold ${rising ? "text-hype" : "text-muted-foreground"}`}>
                {e.score.toFixed(0)}
              </span>
            </Link>
          </motion.div>
        );
      })}
    </div>
  );
}
