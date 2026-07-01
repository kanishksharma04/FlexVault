import Link from "next/link";
import Image from "next/image";
import { PackageOpen } from "lucide-react";
import { db } from "@/lib/db";
import { SectionHeading } from "@/components/vault/section-heading";
import { EmptyState } from "@/components/vault/empty-state";
import { Badge } from "@/components/ui/badge";

export const dynamic = "force-dynamic";

export default async function DropsPage() {
  const drops = await db.drop.findMany({ orderBy: { dropDate: "desc" } });

  return (
    <div className="mx-auto max-w-6xl px-4 py-10 sm:px-6">
      <SectionHeading eyebrow="Drops" title="VAULT DROPS" description="Curated pre-order runs, refreshed regularly." className="mb-8" />

      {drops.length === 0 ? (
        <EmptyState icon={PackageOpen} title="NO DROPS YET" description="Check back soon for the next curated run." />
      ) : (
        <div className="grid gap-4 sm:grid-cols-2">
          {drops.map((d) => (
            <Link
              key={d.id}
              href={`/drops/${d.slug}`}
              className="card-hype group relative flex flex-col overflow-hidden border border-border bg-card"
            >
              <div className="relative aspect-[16/9] w-full overflow-hidden bg-vault-3">
                <Image src={d.coverImage} alt={d.title} fill className="object-cover" />
                {d.isActive && (
                  <Badge variant="hype" className="absolute left-3 top-3">
                    Active
                  </Badge>
                )}
              </div>
              <div className="flex flex-col gap-1 p-4">
                <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                  {new Date(d.dropDate).toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" })}
                </p>
                <p className="font-display text-xl tracking-wide">{d.title}</p>
                <p className="line-clamp-2 text-sm text-muted-foreground">{d.description}</p>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
