"use client";

import { useQuery } from "@tanstack/react-query";
import { Sparkles } from "lucide-react";

type Suggestion = { low: number; mid: number; high: number; basis: string; trendScore: number };

export function PriceSuggestion({ productId }: { productId: string }) {
  const { data, isLoading } = useQuery<Suggestion>({
    queryKey: ["price-suggestion", productId],
    queryFn: async () => {
      const res = await fetch(`/api/pricing-suggestion?productId=${productId}`);
      return res.json();
    },
  });

  if (isLoading) {
    return <p className="font-mono text-xs text-muted-foreground">Calculating suggested price...</p>;
  }
  if (!data || data.mid === 0) {
    return <p className="font-mono text-xs text-muted-foreground">Not enough sales data for a suggestion yet — price based on comparable listings.</p>;
  }

  return (
    <div className="flex flex-col gap-2 border border-acid/30 bg-acid/5 p-4">
      <div className="flex items-center gap-2 text-acid">
        <Sparkles className="size-4" />
        <span className="font-mono text-xs uppercase tracking-widest">AI-Suggested Price</span>
      </div>
      <div className="flex items-baseline gap-3">
        <span className="font-mono text-2xl font-bold text-acid">₹{data.mid.toLocaleString("en-IN")}</span>
        <span className="font-mono text-xs text-muted-foreground">
          Range ₹{data.low.toLocaleString("en-IN")} – ₹{data.high.toLocaleString("en-IN")}
        </span>
      </div>
      <p className="text-xs text-muted-foreground">{data.basis}</p>
    </div>
  );
}
