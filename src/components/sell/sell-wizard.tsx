"use client";

import { useState, useActionState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { AnimatePresence, motion } from "framer-motion";
import { toast } from "sonner";
import { CheckCircle2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from "@/components/ui/select";
import { StepProgress } from "@/components/checkout/step-progress";
import { ProductPicker, type PickedProduct } from "./product-picker";
import { PhotoUploader } from "./photo-uploader";
import { PriceSuggestion } from "./price-suggestion";
import { CATEGORY_NAV } from "@/lib/nav";
import { createListing, type CreateListingState } from "@/actions/create-listing";
import { cn } from "@/lib/utils";

const STEPS = ["Category", "Item", "Condition", "Pricing", "Type", "Review"];

const CONDITIONS = [
  { value: "NEW", label: "New" },
  { value: "LIKE_NEW", label: "Like New" },
  { value: "USED_EXCELLENT", label: "Used - Excellent" },
  { value: "USED_GOOD", label: "Used - Good" },
  { value: "USED_FAIR", label: "Used - Fair" },
];

const LISTING_TYPES = [
  { value: "FIXED", label: "Fixed Price", desc: "Buyers can cop it instantly at your price." },
  { value: "AUCTION", label: "Auction", desc: "Buyers bid; highest offer after 5 days wins." },
  { value: "PREORDER", label: "Pre-order", desc: "Reserve now, ships once authenticated." },
];

export function SellWizard() {
  const router = useRouter();
  const [step, setStep] = useState(0);
  const [category, setCategory] = useState("");
  const [product, setProduct] = useState<PickedProduct | null>(null);
  const [condition, setCondition] = useState("NEW");
  const [photos, setPhotos] = useState<string[]>([]);
  const [price, setPrice] = useState("");
  const [listingType, setListingType] = useState("FIXED");
  const [size, setSize] = useState("");
  const [quantity, setQuantity] = useState("1");

  const initialState: CreateListingState = {};
  const [state, formAction, pending] = useActionState(createListing, initialState);

  useEffect(() => {
    if (state.success) {
      toast.success("Listing submitted for authentication.");
    }
  }, [state.success]);

  function next() {
    if (step === 0 && !category) return toast.error("Choose a category.");
    if (step === 1 && !product) return toast.error("Select a product from the catalog.");
    if (step === 2 && photos.length === 0) return toast.error("Upload at least one inspection photo.");
    if (step === 3 && (!price || Number(price) <= 0)) return toast.error("Enter a valid price.");
    setStep((s) => Math.min(STEPS.length - 1, s + 1));
  }

  if (state.success) {
    return (
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className="mx-auto flex max-w-md flex-col items-center gap-4 py-16 text-center"
      >
        <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ type: "spring", stiffness: 260, damping: 18, delay: 0.1 }}>
          <CheckCircle2 className="size-16 text-acid" />
        </motion.div>
        <h1 className="font-display text-3xl tracking-wide">PENDING AUTHENTICATION</h1>
        <p className="text-sm text-muted-foreground">
          Your listing is in the vault authentication queue. We&apos;ll notify you once it&apos;s cleared and live.
        </p>
        <Button onClick={() => router.push("/dashboard/seller/listings")}>View My Listings</Button>
      </motion.div>
    );
  }

  return (
    <div className="mx-auto max-w-2xl">
      <StepProgress steps={STEPS} current={step} />

      <div className="mt-10">
        <AnimatePresence mode="wait">
          {step === 0 && (
            <motion.div key="cat" initial={{ opacity: 0, x: 16 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -16 }} className="grid grid-cols-2 gap-3 sm:grid-cols-3">
              {CATEGORY_NAV.map((c) => (
                <button
                  key={c.slug}
                  onClick={() => setCategory(c.slug)}
                  className={cn(
                    "border p-5 text-center font-display text-lg tracking-wide transition",
                    category === c.slug ? "border-acid bg-acid/10 text-acid" : "border-border hover:border-acid/50"
                  )}
                >
                  {c.label}
                </button>
              ))}
            </motion.div>
          )}

          {step === 1 && (
            <motion.div key="item" initial={{ opacity: 0, x: 16 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -16 }}>
              <ProductPicker categorySlug={category} value={product} onChange={setProduct} />
            </motion.div>
          )}

          {step === 2 && (
            <motion.div key="condition" initial={{ opacity: 0, x: 16 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -16 }} className="flex flex-col gap-5">
              <div className="flex flex-col gap-1.5">
                <Label>Condition</Label>
                <Select value={condition} onValueChange={setCondition}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {CONDITIONS.map((c) => (
                      <SelectItem key={c.value} value={c.value}>{c.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="flex flex-col gap-1.5">
                <Label>Inspection Photos</Label>
                <PhotoUploader urls={photos} onChange={setPhotos} />
              </div>
            </motion.div>
          )}

          {step === 3 && product && (
            <motion.div key="pricing" initial={{ opacity: 0, x: 16 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -16 }} className="flex flex-col gap-4">
              <PriceSuggestion productId={product.id} />
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="price-input">Your price (₹)</Label>
                <Input id="price-input" type="number" value={price} onChange={(e) => setPrice(e.target.value)} min={1} />
              </div>
            </motion.div>
          )}

          {step === 4 && (
            <motion.div key="type" initial={{ opacity: 0, x: 16 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -16 }} className="flex flex-col gap-5">
              <div className="grid gap-3 sm:grid-cols-3">
                {LISTING_TYPES.map((t) => (
                  <button
                    key={t.value}
                    onClick={() => setListingType(t.value)}
                    className={cn(
                      "flex flex-col gap-1 border p-4 text-left transition",
                      listingType === t.value ? "border-acid bg-acid/5" : "border-border hover:border-acid/50"
                    )}
                  >
                    <span className="font-mono text-xs uppercase tracking-widest text-acid">{t.label}</span>
                    <span className="text-xs text-muted-foreground">{t.desc}</span>
                  </button>
                ))}
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="flex flex-col gap-1.5">
                  <Label htmlFor="size">Size / Variant (optional)</Label>
                  <Input id="size" value={size} onChange={(e) => setSize(e.target.value)} placeholder="UK9" />
                </div>
                <div className="flex flex-col gap-1.5">
                  <Label htmlFor="quantity">Quantity</Label>
                  <Input id="quantity" type="number" min={1} value={quantity} onChange={(e) => setQuantity(e.target.value)} />
                </div>
              </div>
            </motion.div>
          )}

          {step === 5 && product && (
            <motion.form
              key="review"
              action={formAction}
              initial={{ opacity: 0, x: 16 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -16 }}
              className="flex flex-col gap-4"
            >
              <input type="hidden" name="productId" value={product.id} />
              <input type="hidden" name="price" value={price} />
              <input type="hidden" name="condition" value={condition} />
              <input type="hidden" name="listingType" value={listingType} />
              <input type="hidden" name="size" value={size} />
              <input type="hidden" name="quantity" value={quantity} />
              {photos.map((p) => (
                <input key={p} type="hidden" name="photoUrl" value={p} />
              ))}

              <div className="flex flex-col gap-2 border border-border bg-card p-4 font-mono text-sm">
                <Row label="Product" value={product.name} />
                <Row label="Condition" value={condition.replace(/_/g, " ")} />
                <Row label="Price" value={`₹${Number(price || 0).toLocaleString("en-IN")}`} />
                <Row label="Type" value={listingType} />
                {size && <Row label="Size" value={size} />}
                <Row label="Quantity" value={quantity} />
                <Row label="Photos" value={`${photos.length} uploaded`} />
              </div>

              {state.error && <p className="text-sm text-hype">{state.error}</p>}

              <p className="font-mono text-[11px] text-muted-foreground">
                Submitting sends this listing to the Flex Vault authentication queue. It won&apos;t be purchasable until approved.
              </p>

              <div className="flex justify-between">
                <Button type="button" variant="outline" onClick={() => setStep((s) => s - 1)}>
                  Back
                </Button>
                <Button type="submit" disabled={pending}>
                  {pending ? "Submitting..." : "Submit for Authentication"}
                </Button>
              </div>
            </motion.form>
          )}
        </AnimatePresence>
      </div>

      {step < STEPS.length - 1 && (
        <div className="mt-8 flex justify-between">
          {step > 0 ? (
            <Button variant="outline" onClick={() => setStep((s) => s - 1)}>
              Back
            </Button>
          ) : (
            <span />
          )}
          <Button onClick={next}>Continue</Button>
        </div>
      )}
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between">
      <span className="text-muted-foreground">{label}</span>
      <span>{value}</span>
    </div>
  );
}
