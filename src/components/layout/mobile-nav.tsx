"use client";

import { useState } from "react";
import Link from "next/link";
import { Menu } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import { CATEGORY_NAV, PRIMARY_NAV } from "@/lib/nav";

export function MobileNav() {
  const [open, setOpen] = useState(false);

  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger asChild>
        <Button variant="ghost" size="icon" className="lg:hidden" aria-label="Open menu">
          <Menu className="size-5" />
        </Button>
      </SheetTrigger>
      <SheetContent side="left" className="w-full max-w-xs border-border bg-vault">
        <SheetHeader>
          <SheetTitle className="font-display text-xl tracking-wide">MENU</SheetTitle>
        </SheetHeader>
        <nav className="flex flex-col gap-1 px-4 pb-6">
          <p className="mt-2 font-mono text-[11px] uppercase tracking-widest text-muted-foreground">
            Categories
          </p>
          {CATEGORY_NAV.map((c) => (
            <Link
              key={c.slug}
              href={`/browse/${c.slug}`}
              onClick={() => setOpen(false)}
              className="rounded px-2 py-2 font-display text-lg tracking-wide hover:bg-vault-3 hover:text-acid"
            >
              {c.label}
            </Link>
          ))}
          <p className="mt-4 font-mono text-[11px] uppercase tracking-widest text-muted-foreground">
            Vault
          </p>
          {PRIMARY_NAV.map((n) => (
            <Link
              key={n.href}
              href={n.href}
              onClick={() => setOpen(false)}
              className="rounded px-2 py-2 text-sm text-foreground hover:bg-vault-3 hover:text-acid"
            >
              {n.label}
            </Link>
          ))}
        </nav>
      </SheetContent>
    </Sheet>
  );
}
