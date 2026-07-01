"use client";

import { useState, useTransition } from "react";
import { Heart } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { toggleWatchlist } from "@/actions/watchlist";
import { cn } from "@/lib/utils";

export function WatchlistButton({
  productId,
  productSlug,
  initialWatching,
}: {
  productId: string;
  productSlug: string;
  initialWatching: boolean;
}) {
  const [watching, setWatching] = useState(initialWatching);
  const [pending, startTransition] = useTransition();

  return (
    <Button
      variant="outline"
      size="sm"
      disabled={pending}
      onClick={() => {
        startTransition(async () => {
          const res = await toggleWatchlist(productId, productSlug);
          if ("error" in res) {
            toast.error(res.error);
            return;
          }
          setWatching(res.watching);
          toast.success(res.watching ? "Added to watchlist." : "Removed from watchlist.");
        });
      }}
    >
      <Heart className={cn("size-4", watching && "fill-hype text-hype")} />
      {watching ? "Watching" : "Watch"}
    </Button>
  );
}
