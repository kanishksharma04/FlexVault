"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";

export type DashboardNavItem = { href: string; label: string; icon: React.ReactNode; exact?: boolean };

export function DashboardShell({
  title,
  subtitle,
  nav,
  children,
}: {
  title: string;
  subtitle?: string;
  nav: DashboardNavItem[];
  children: React.ReactNode;
}) {
  const pathname = usePathname();

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6">
      <div className="mb-8">
        <p className="font-mono text-xs uppercase tracking-widest text-acid">{subtitle}</p>
        <h1 className="font-display text-3xl tracking-wide sm:text-4xl">{title}</h1>
      </div>

      <div className="flex flex-col gap-8 lg:flex-row">
        <aside className="flex gap-1 overflow-x-auto lg:w-52 lg:shrink-0 lg:flex-col lg:overflow-visible">
          {nav.map((item) => {
            const active = item.exact ? pathname === item.href : pathname.startsWith(item.href);
            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  "flex shrink-0 items-center gap-2 whitespace-nowrap rounded-sm border px-3 py-2 text-sm transition lg:whitespace-normal",
                  active
                    ? "border-acid bg-acid/10 text-acid"
                    : "border-transparent text-muted-foreground hover:border-border hover:text-foreground"
                )}
              >
                {item.icon}
                {item.label}
              </Link>
            );
          })}
        </aside>

        <div className="min-w-0 flex-1">{children}</div>
      </div>
    </div>
  );
}
