import Link from "next/link";
import { Search, ShieldCheck } from "lucide-react";
import { auth } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import { CATEGORY_NAV, PRIMARY_NAV } from "@/lib/nav";
import { UserMenu, AuthButtons } from "./user-menu";
import { MobileNav } from "./mobile-nav";
import { CartButton } from "@/components/cart/cart-button";
import { CartDrawer } from "@/components/cart/cart-drawer";

export async function SiteHeader() {
  const session = await auth();

  return (
    <header className="sticky top-0 z-40 border-b border-border bg-vault/90 backdrop-blur">
      <div className="mx-auto flex h-16 max-w-7xl items-center gap-4 px-4 sm:px-6">
        <MobileNav />

        <Link href="/" className="flex items-center gap-1.5 font-display text-xl tracking-wide">
          <ShieldCheck className="size-5 text-acid" />
          FLEX <span className="text-acid">VAULT</span>
        </Link>

        <nav className="ml-4 hidden items-center gap-5 lg:flex">
          {CATEGORY_NAV.map((c) => (
            <Link
              key={c.slug}
              href={`/browse/${c.slug}`}
              className="font-mono text-xs uppercase tracking-wider text-muted-foreground transition hover:text-acid"
            >
              {c.label}
            </Link>
          ))}
          <span className="h-4 w-px bg-border" />
          {PRIMARY_NAV.map((n) => (
            <Link
              key={n.href}
              href={n.href}
              className="font-mono text-xs uppercase tracking-wider text-muted-foreground transition hover:text-acid"
            >
              {n.label}
            </Link>
          ))}
        </nav>

        <div className="ml-auto flex items-center gap-1">
          <Button asChild variant="ghost" size="icon" aria-label="Search">
            <Link href="/search">
              <Search className="size-5" />
            </Link>
          </Button>
          <CartButton />
          {session?.user ? <UserMenu user={session.user} /> : <AuthButtons />}
        </div>
      </div>
      <CartDrawer />
    </header>
  );
}
