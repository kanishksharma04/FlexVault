import Link from "next/link";
import { ShieldCheck } from "lucide-react";
import { CATEGORY_NAV } from "@/lib/nav";

const FOOTER_COLUMNS = [
  {
    title: "Shop",
    links: CATEGORY_NAV.map((c) => ({ label: c.label, href: `/browse/${c.slug}` })),
  },
  {
    title: "Flex Vault",
    links: [
      { label: "How It Works", href: "/how-it-works" },
      { label: "Authentication Process", href: "/authentication" },
      { label: "About", href: "/about" },
      { label: "Editorial", href: "/blog" },
    ],
  },
  {
    title: "Sell",
    links: [
      { label: "Start Selling", href: "/sell" },
      { label: "Seller Dashboard", href: "/dashboard/seller" },
      { label: "Flex Vault Pro", href: "/pro" },
    ],
  },
  {
    title: "Support",
    links: [
      { label: "FAQ", href: "/faq" },
      { label: "Contact", href: "/contact" },
    ],
  },
];

export function SiteFooter() {
  return (
    <footer className="border-t border-border bg-vault-2">
      <div className="mx-auto max-w-7xl px-4 py-12 sm:px-6">
        <div className="grid grid-cols-2 gap-8 md:grid-cols-5">
          <div className="col-span-2 md:col-span-1">
            <div className="flex items-center gap-1.5 font-display text-lg tracking-wide">
              <ShieldCheck className="size-5 text-acid" />
              FLEX <span className="text-acid">VAULT</span>
            </div>
            <p className="mt-3 font-mono text-xs leading-relaxed text-muted-foreground">
              Drip. Verified. Delivered.
            </p>
          </div>
          {FOOTER_COLUMNS.map((col) => (
            <div key={col.title}>
              <p className="font-mono text-[11px] uppercase tracking-widest text-muted-foreground">
                {col.title}
              </p>
              <ul className="mt-3 flex flex-col gap-2">
                {col.links.map((l) => (
                  <li key={l.href}>
                    <Link
                      href={l.href}
                      className="text-sm text-foreground/80 transition hover:text-acid"
                    >
                      {l.label}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
        <div className="mt-10 flex flex-col items-start justify-between gap-2 border-t border-border pt-6 font-mono text-[11px] text-muted-foreground sm:flex-row sm:items-center">
          <p>© {new Date().getFullYear()} Flex Vault. India&apos;s authenticated hype marketplace.</p>
          <p>Built for demo purposes — every certificate hash is simulated.</p>
        </div>
      </div>
    </footer>
  );
}
