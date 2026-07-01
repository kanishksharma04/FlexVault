"use client";

import Link from "next/link";
import { TrendingUp, TrendingDown } from "lucide-react";
import type { HypeTickerEntry } from "@/lib/queries/trend";
import { cn } from "@/lib/utils";

export function HypeTickerMarquee({ entries }: { entries: HypeTickerEntry[] }) {
  const loop = [...entries, ...entries];

  return (
    <div className="w-full overflow-hidden border-b border-border bg-vault-2 py-1.5">
      <div className="flex w-max animate-marquee gap-8 hover:[animation-play-state:paused]">
        {loop.map((entry, i) => (
          <Link
            key={`${entry.productId}-${i}`}
            href={`/product/${entry.productSlug}`}
            className="flex shrink-0 items-center gap-2 font-mono text-xs tracking-wide"
          >
            <span className="text-muted-foreground">{entry.productName}</span>
            <span className="font-bold text-foreground">{entry.score.toFixed(1)}</span>
            <span
              className={cn(
                "flex items-center gap-0.5 font-bold",
                entry.delta >= 0 ? "text-acid" : "text-hype"
              )}
            >
              {entry.delta >= 0 ? (
                <TrendingUp className="size-3" />
              ) : (
                <TrendingDown className="size-3" />
              )}
              {entry.delta >= 0 ? "+" : ""}
              {entry.delta.toFixed(1)}
            </span>
            <span className="text-border">/</span>
          </Link>
        ))}
      </div>
    </div>
  );
}
