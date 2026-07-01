"use client";

import { useState, useTransition } from "react";
import Image from "next/image";
import { toast } from "sonner";
import { Check, X, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { TierBadge } from "@/components/vault/tier-badge";
import { reviewAuthentication } from "@/actions/authentication";
import type { SellerTier } from "@prisma/client";

export type AuthQueueEntry = {
  id: string;
  inspectionPhotos: string[];
  listing: {
    id: string;
    price: number;
    condition: string;
    product: { name: string; brand: string; images: string[]; sku: string };
    seller: { name: string; sellerTier: SellerTier };
  };
};

export function AuthQueueCard({ entry }: { entry: AuthQueueEntry }) {
  const [notes, setNotes] = useState("");
  const [showReject, setShowReject] = useState(false);
  const [pending, startTransition] = useTransition();
  const [resolved, setResolved] = useState<"APPROVED" | "REJECTED" | null>(null);

  function submit(decision: "APPROVED" | "REJECTED") {
    startTransition(async () => {
      const res = await reviewAuthentication(entry.id, decision, notes);
      if ("error" in res && res.error) {
        toast.error(res.error);
        return;
      }
      toast.success(decision === "APPROVED" ? "Listing approved and cleared." : "Listing rejected.");
      setResolved(decision);
    });
  }

  if (resolved) {
    return (
      <div className="flex items-center gap-3 border border-border bg-card p-4 opacity-60">
        <p className="text-sm">
          {entry.listing.product.name} — <span className="font-mono text-xs">{resolved}</span>
        </p>
      </div>
    );
  }

  const photos = entry.inspectionPhotos.length > 0 ? entry.inspectionPhotos : entry.listing.product.images;

  return (
    <div className="flex flex-col gap-4 border border-border bg-card p-5">
      <div className="flex flex-col justify-between gap-2 sm:flex-row sm:items-start">
        <div>
          <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
            {entry.listing.product.brand} · SKU {entry.listing.product.sku}
          </p>
          <p className="font-display text-lg tracking-wide">{entry.listing.product.name}</p>
          <p className="font-mono text-xs text-muted-foreground">
            ₹{entry.listing.price.toLocaleString("en-IN")} · {entry.listing.condition.replace(/_/g, " ")}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-sm">{entry.listing.seller.name}</span>
          <TierBadge tier={entry.listing.seller.sellerTier} />
        </div>
      </div>

      <div className="grid grid-cols-4 gap-2 sm:grid-cols-6">
        {photos.map((url, i) => (
          <div key={i} className="relative aspect-square overflow-hidden rounded-sm border border-border bg-vault-3">
            <Image src={url} alt={`Inspection ${i + 1}`} fill className="object-cover" />
          </div>
        ))}
      </div>

      {showReject && (
        <Textarea
          placeholder="Reason for rejection (required)..."
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          className="min-h-16"
        />
      )}

      <div className="flex gap-2">
        {!showReject ? (
          <>
            <Button size="sm" disabled={pending} onClick={() => submit("APPROVED")}>
              {pending ? <Loader2 className="size-3.5 animate-spin" /> : <Check className="size-3.5" />}
              Approve
            </Button>
            <Button size="sm" variant="destructive" onClick={() => setShowReject(true)}>
              <X className="size-3.5" />
              Reject
            </Button>
          </>
        ) : (
          <>
            <Button size="sm" variant="destructive" disabled={pending} onClick={() => submit("REJECTED")}>
              {pending ? "Rejecting..." : "Confirm Rejection"}
            </Button>
            <Button size="sm" variant="outline" onClick={() => setShowReject(false)}>
              Cancel
            </Button>
          </>
        )}
      </div>
    </div>
  );
}
