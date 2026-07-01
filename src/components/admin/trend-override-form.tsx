"use client";

import { useState, useTransition } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ProductPicker, type PickedProduct } from "@/components/sell/product-picker";
import { overrideTrendScore } from "@/actions/admin-trends";

export function TrendOverrideForm() {
  const [product, setProduct] = useState<PickedProduct | null>(null);
  const [score, setScore] = useState("75");
  const [reason, setReason] = useState("");
  const [pending, startTransition] = useTransition();

  return (
    <div className="flex flex-col gap-4 border border-border bg-card p-5">
      <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">Manual Trend Score Override</p>
      <ProductPicker categorySlug="" value={product} onChange={setProduct} />
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="override-score">Score (0-100)</Label>
          <Input id="override-score" type="number" min={0} max={100} value={score} onChange={(e) => setScore(e.target.value)} />
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="override-reason">Reason</Label>
          <Input id="override-reason" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Viral restock announcement" />
        </div>
      </div>
      <Button
        className="w-fit"
        disabled={!product || pending}
        onClick={() => {
          if (!product) return;
          startTransition(async () => {
            const res = await overrideTrendScore(product.id, Number(score), reason);
            if ("error" in res && res.error) {
              toast.error(res.error);
              return;
            }
            toast.success(`Trend score for ${product.name} updated.`);
            setProduct(null);
            setReason("");
          });
        }}
      >
        {pending ? "Applying..." : "Apply Override"}
      </Button>
    </div>
  );
}
