"use client";

import { useState, useActionState } from "react";
import { useSession } from "next-auth/react";
import { toast } from "sonner";
import { ShieldCheck, Gavel, CalendarClock, ShoppingBag } from "lucide-react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { TierBadge } from "@/components/vault/tier-badge";
import { useCart } from "@/components/cart/cart-context";
import { placeBid, type PlaceBidState } from "@/actions/bids";
import type { Condition, ListingType, SellerTier } from "@prisma/client";

export type PdpListing = {
  id: string;
  price: number;
  condition: Condition;
  listingType: ListingType;
  size: string | null;
  auctionEndsAt: Date | null;
  preorderShipsAt: Date | null;
  seller: { id: string; name: string; sellerTier: SellerTier; image: string | null };
  authenticationRecord: { status: string } | null;
  bids: { amount: number; bidder: { name: string } }[];
};

export function ListingsPanel({
  listings,
  product,
}: {
  listings: PdpListing[];
  product: { slug: string; name: string; brand: string; images: string[] };
}) {
  const fixed = listings.filter((l) => l.listingType === "FIXED");
  const auctions = listings.filter((l) => l.listingType === "AUCTION");
  const preorders = listings.filter((l) => l.listingType === "PREORDER");

  const defaultTab = fixed.length ? "buy" : auctions.length ? "bid" : "preorder";

  return (
    <Tabs defaultValue={defaultTab}>
      <TabsList className="w-full">
        {fixed.length > 0 && (
          <TabsTrigger value="buy">
            <ShoppingBag className="mr-1 size-3.5" /> Buy Now ({fixed.length})
          </TabsTrigger>
        )}
        {auctions.length > 0 && (
          <TabsTrigger value="bid">
            <Gavel className="mr-1 size-3.5" /> Bids ({auctions.length})
          </TabsTrigger>
        )}
        {preorders.length > 0 && (
          <TabsTrigger value="preorder">
            <CalendarClock className="mr-1 size-3.5" /> Pre-order ({preorders.length})
          </TabsTrigger>
        )}
      </TabsList>

      {fixed.length > 0 && (
        <TabsContent value="buy" className="mt-4 flex flex-col gap-2">
          {fixed.map((l) => (
            <FixedListingRow key={l.id} listing={l} product={product} />
          ))}
        </TabsContent>
      )}
      {auctions.length > 0 && (
        <TabsContent value="bid" className="mt-4 flex flex-col gap-3">
          {auctions.map((l) => (
            <AuctionListingRow key={l.id} listing={l} productSlug={product.slug} />
          ))}
        </TabsContent>
      )}
      {preorders.length > 0 && (
        <TabsContent value="preorder" className="mt-4 flex flex-col gap-2">
          {preorders.map((l) => (
            <FixedListingRow key={l.id} listing={l} product={product} isPreorder />
          ))}
        </TabsContent>
      )}
    </Tabs>
  );
}

function ListingMeta({ listing }: { listing: PdpListing }) {
  return (
    <div className="flex flex-1 items-center gap-3">
      <div>
        <p className="font-mono text-sm font-bold text-acid">₹{listing.price.toLocaleString("en-IN")}</p>
        <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
          {listing.condition.replace(/_/g, " ")}
          {listing.size ? ` · ${listing.size}` : ""}
        </p>
      </div>
      <span className="h-6 w-px bg-border" />
      <div className="flex items-center gap-1.5">
        <span className="text-xs text-muted-foreground">{listing.seller.name}</span>
        <TierBadge tier={listing.seller.sellerTier} />
      </div>
      {listing.authenticationRecord?.status === "APPROVED" && (
        <ShieldCheck className="ml-auto size-4 shrink-0 text-acid" />
      )}
    </div>
  );
}

function FixedListingRow({
  listing,
  product,
  isPreorder = false,
}: {
  listing: PdpListing;
  product: { slug: string; name: string; brand: string; images: string[] };
  isPreorder?: boolean;
}) {
  const { addItem, items } = useCart();
  const inCart = items.some((i) => i.listingId === listing.id);

  return (
    <div className="flex flex-col gap-2 border border-border bg-card p-3 sm:flex-row sm:items-center">
      <ListingMeta listing={listing} />
      {isPreorder && listing.preorderShipsAt && (
        <p className="text-xs text-muted-foreground">
          Ships {new Date(listing.preorderShipsAt).toLocaleDateString("en-IN", { day: "numeric", month: "short" })}
        </p>
      )}
      <Button
        size="sm"
        disabled={inCart}
        onClick={() => {
          addItem({
            listingId: listing.id,
            productName: product.name,
            brand: product.brand,
            image: product.images[0],
            price: listing.price,
            size: listing.size,
            condition: listing.condition,
            sellerName: listing.seller.name,
          });
          toast.success(`${product.name} added to your vault cart.`);
        }}
      >
        {inCart ? "In Cart" : isPreorder ? "Reserve" : "Cop It"}
      </Button>
    </div>
  );
}

function AuctionListingRow({ listing, productSlug }: { listing: PdpListing; productSlug: string }) {
  const { data: session } = useSession();
  const [open, setOpen] = useState(false);
  const initialState: PlaceBidState = {};
  const [state, formAction, pending] = useActionState(placeBid, initialState);
  const topBid = listing.bids[0]?.amount ?? Math.round(listing.price * 0.8);
  // Approximate "time remaining" display only — recomputed on natural re-renders,
  // not used as a source of truth for any state or effect dependency.
  // eslint-disable-next-line react-hooks/purity
  const endsIn = listing.auctionEndsAt ? new Date(listing.auctionEndsAt).getTime() - Date.now() : null;

  return (
    <div className="flex flex-col gap-3 border border-border bg-card p-3">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <ListingMeta listing={{ ...listing, price: topBid }} />
        {endsIn != null && endsIn > 0 && (
          <p className="font-mono text-[11px] text-hype">
            Ends in {Math.max(1, Math.round(endsIn / 3_600_000))}h
          </p>
        )}
        <Button size="sm" variant="outline" onClick={() => setOpen((v) => !v)}>
          Place Bid
        </Button>
      </div>

      {open && (
        <form
          action={formAction}
          className="flex items-center gap-2 border-t border-border pt-3"
          onSubmit={() => {
            if (!session?.user) toast.error("Log in to place a bid.");
          }}
        >
          <input type="hidden" name="listingId" value={listing.id} />
          <input type="hidden" name="productSlug" value={productSlug} />
          <Input
            type="number"
            name="amount"
            min={topBid + 1}
            placeholder={`> ₹${topBid.toLocaleString("en-IN")}`}
            required
            className="h-9 w-40"
          />
          <Button type="submit" size="sm" disabled={pending}>
            {pending ? "Placing..." : "Confirm Bid"}
          </Button>
          {state.error && <p className="text-xs text-hype">{state.error}</p>}
          {state.success && <p className="text-xs text-acid">Bid placed!</p>}
        </form>
      )}
    </div>
  );
}
