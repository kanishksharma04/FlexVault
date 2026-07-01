"use client";

import { useRouter, usePathname, useSearchParams } from "next/navigation";
import { CATEGORY_NAV } from "@/lib/nav";
import { cn } from "@/lib/utils";

export function CategoryFilterTabs() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const active = searchParams.get("category") ?? "";

  function select(slug: string) {
    const params = new URLSearchParams(searchParams.toString());
    if (slug) params.set("category", slug);
    else params.delete("category");
    router.push(`${pathname}?${params.toString()}`, { scroll: false });
  }

  return (
    <div className="flex flex-wrap gap-2">
      <button
        onClick={() => select("")}
        className={cn(
          "rounded-full border px-3 py-1.5 font-mono text-xs uppercase tracking-wider transition",
          active === "" ? "border-acid bg-acid text-acid-foreground" : "border-border text-muted-foreground hover:border-acid/50"
        )}
      >
        All
      </button>
      {CATEGORY_NAV.map((c) => (
        <button
          key={c.slug}
          onClick={() => select(c.slug)}
          className={cn(
            "rounded-full border px-3 py-1.5 font-mono text-xs uppercase tracking-wider transition",
            active === c.slug ? "border-acid bg-acid text-acid-foreground" : "border-border text-muted-foreground hover:border-acid/50"
          )}
        >
          {c.label}
        </button>
      ))}
    </div>
  );
}
