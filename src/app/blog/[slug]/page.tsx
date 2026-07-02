import { notFound } from "next/navigation";
import Link from "next/link";
import type { Metadata } from "next";
import { db } from "@/lib/db";
import { FallbackImage } from "@/components/ui/fallback-image";

export const dynamic = "force-dynamic";

type Props = { params: Promise<{ slug: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { slug } = await params;
  const post = await db.blogPost.findUnique({ where: { slug } });
  if (!post) return {};
  return { title: `${post.title} | Flex Vault Editorial`, description: post.excerpt };
}

export default async function BlogPostPage({ params }: Props) {
  const { slug } = await params;
  const post = await db.blogPost.findUnique({ where: { slug }, include: { author: { select: { name: true } } } });
  if (!post || !post.publishedAt) notFound();

  return (
    <article className="mx-auto max-w-2xl px-4 py-12 sm:px-6">
      <Link href="/blog" className="font-mono text-xs uppercase tracking-widest text-acid hover:underline">
        ← Editorial
      </Link>
      <h1 className="mt-3 font-display text-4xl tracking-wide">{post.title}</h1>
      <p className="mt-2 font-mono text-xs text-muted-foreground">
        {post.author.name} · {new Date(post.publishedAt).toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" })}
      </p>
      <div className="relative mt-6 aspect-[16/9] w-full overflow-hidden rounded-md border border-border bg-vault-3">
        <FallbackImage src={post.coverImage} fallbackSeed={post.title} alt={post.title} fill className="object-cover" />
      </div>
      <div className="mt-8 whitespace-pre-line text-sm leading-relaxed text-foreground/90">
        {post.content}
      </div>
    </article>
  );
}
