"use client";

import { ShoppingBag } from "lucide-react";
import { AnimatePresence, motion } from "framer-motion";
import { Button } from "@/components/ui/button";
import { useCart } from "./cart-context";

export function CartButton() {
  const { items, toggle } = useCart();

  return (
    <Button
      variant="ghost"
      size="icon"
      onClick={toggle}
      aria-label={`Open cart, ${items.length} items`}
      className="relative"
    >
      <ShoppingBag className="size-5" />
      <AnimatePresence>
        {items.length > 0 && (
          <motion.span
            key={items.length}
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            exit={{ scale: 0 }}
            transition={{ type: "spring", stiffness: 500, damping: 20 }}
            className="absolute -right-1 -top-1 flex size-4 items-center justify-center rounded-full bg-acid text-[10px] font-bold text-acid-foreground"
          >
            {items.length}
          </motion.span>
        )}
      </AnimatePresence>
    </Button>
  );
}
