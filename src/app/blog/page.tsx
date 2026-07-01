import Link from "next/link";
import Image from "next/image";
import { Newspaper } from "lucide-react";
import { db } from "@/lib/db";
import { SectionHeading } from "@/components/vault/section-heading";
import { EmptyState } from "@/components/vault/empty-state";

export const dynamic = "force-dynamic";

export default async function BlogIndexPage() {
  const posts = await db.blogPost.findMany({
    where: { publishedAt: { not: null } },
    orderBy: { publishedAt: "desc" },
    include: { author: { select: { name: true } } },
  });

  return (
    <div className="mx-auto max-w-6xl px-4 py-10 sm:px-6">
      <SectionHeading eyebrow="Editorial" title="THE VAULT DESK" description="Drop coverage, authentication breakdowns, and market commentary." className="mb-8" />

      {posts.length === 0 ? (
        <EmptyState icon={Newspaper} title="NO POSTS YET" description="Editorial content will appear here soon." />
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {posts.map((post) => (
            <Link key={post.id} href={`/blog/${post.slug}`} className="card-hype group flex flex-col overflow-hidden border border-border bg-card">
              <div className="relative aspect-[16/9] w-full overflow-hidden bg-vault-3">
                <Image src={post.coverImage} alt={post.title} fill className="object-cover" />
              </div>
              <div className="flex flex-col gap-2 p-4">
                <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                  {post.author.name} · {new Date(post.publishedAt!).toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" })}
                </p>
                <p className="font-display text-lg tracking-wide">{post.title}</p>
                <p className="line-clamp-2 text-sm text-muted-foreground">{post.excerpt}</p>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
