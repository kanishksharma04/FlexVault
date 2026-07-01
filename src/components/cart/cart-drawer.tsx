"use client";

import Image from "next/image";
import Link from "next/link";
import { X } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { useCart } from "./cart-context";

export function CartDrawer() {
  const { items, isOpen, close, removeItem, subtotal } = useCart();

  return (
    <Sheet open={isOpen} onOpenChange={(open) => !open && close()}>
      <SheetContent side="right" className="flex w-full flex-col gap-0 border-border bg-vault p-0 sm:max-w-md">
        <SheetHeader className="border-b border-border px-5 py-4">
          <SheetTitle className="font-display text-2xl tracking-wide">
            YOUR VAULT ({items.length})
          </SheetTitle>
        </SheetHeader>

        <div className="flex-1 overflow-y-auto px-5 py-4">
          {items.length === 0 ? (
            <div className="flex h-full flex-col items-center justify-center gap-2 text-center text-muted-foreground">
              <p className="font-display text-lg tracking-wide text-foreground">
                VAULT&apos;S EMPTY
              </p>
              <p className="text-sm">Cop something before it drops out of stock.</p>
            </div>
          ) : (
            <ul className="flex flex-col gap-4">
              <AnimatePresence initial={false}>
                {items.map((item) => (
                  <motion.li
                    key={item.listingId}
                    layout
                    initial={{ opacity: 0, x: 24 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: 24 }}
                    className="flex gap-3 border border-border bg-card p-3"
                  >
                    <div className="relative size-20 shrink-0 overflow-hidden bg-vault-3">
                      <Image src={item.image} alt={item.productName} fill className="object-cover" />
                    </div>
                    <div className="flex flex-1 flex-col justify-between">
                      <div>
                        <p className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
                          {item.brand}
                        </p>
                        <p className="line-clamp-1 text-sm font-semibold">{item.productName}</p>
                        <p className="text-xs text-muted-foreground">
                          {item.condition.replace(/_/g, " ")}
                          {item.size ? ` · ${item.size}` : ""} · Sold by {item.sellerName}
                        </p>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-sm font-bold text-acid">
                          ₹{item.price.toLocaleString("en-IN")}
                        </span>
                        <button
                          onClick={() => removeItem(item.listingId)}
                          className="text-muted-foreground transition hover:text-hype"
                          aria-label="Remove from cart"
                        >
                          <X className="size-4" />
                        </button>
                      </div>
                    </div>
                  </motion.li>
                ))}
              </AnimatePresence>
            </ul>
          )}
        </div>

        {items.length > 0 && (
          <div className="border-t border-border px-5 py-4">
            <div className="mb-3 flex items-center justify-between font-mono text-sm">
              <span className="text-muted-foreground">Subtotal</span>
              <span className="font-bold">₹{subtotal.toLocaleString("en-IN")}</span>
            </div>
            <Button asChild size="lg" className="w-full" onClick={close}>
              <Link href="/checkout">Checkout</Link>
            </Button>
          </div>
        )}
      </SheetContent>
    </Sheet>
  );
}
