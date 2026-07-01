import { db } from "@/lib/db";
import { BlogTable } from "@/components/admin/blog-table";

export const dynamic = "force-dynamic";

export default async function AdminBlogPage() {
  const posts = await db.blogPost.findMany({ orderBy: { createdAt: "desc" } });
  return <BlogTable posts={posts} />;
}
