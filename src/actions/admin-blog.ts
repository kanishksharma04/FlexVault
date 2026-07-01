"use server";

import { revalidatePath } from "next/cache";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { mockProductImages } from "@/lib/mock-image";

async function assertAdmin() {
  const session = await auth();
  if (!session?.user || session.user.role !== "ADMIN") return null;
  return session;
}

function slugify(s: string) {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
}

export type BlogFormState = { error?: string; success?: boolean };

export async function createBlogPost(_prev: BlogFormState, formData: FormData): Promise<BlogFormState> {
  const session = await assertAdmin();
  if (!session) return { error: "Not authorized." };

  const title = String(formData.get("title") ?? "").trim();
  const excerpt = String(formData.get("excerpt") ?? "").trim();
  const content = String(formData.get("content") ?? "").trim();
  const publish = formData.get("publish") === "on";

  if (!title || !excerpt || !content) return { error: "Title, excerpt, and content are required." };

  await db.blogPost.create({
    data: {
      title,
      slug: slugify(`${title}-${Date.now()}`),
      excerpt,
      content,
      coverImage: mockProductImages(title, title, 1)[0],
      authorId: session.user.id,
      publishedAt: publish ? new Date() : null,
    },
  });

  revalidatePath("/dashboard/admin/blog");
  revalidatePath("/blog");
  return { success: true };
}

export async function updateBlogPost(
  id: string,
  data: { title?: string; excerpt?: string; content?: string; published?: boolean }
) {
  if (!(await assertAdmin())) return { error: "Not authorized." };

  await db.blogPost.update({
    where: { id },
    data: {
      title: data.title,
      excerpt: data.excerpt,
      content: data.content,
      publishedAt: data.published === undefined ? undefined : data.published ? new Date() : null,
    },
  });

  revalidatePath("/dashboard/admin/blog");
  revalidatePath("/blog");
  return { success: true };
}

export async function deleteBlogPost(id: string) {
  if (!(await assertAdmin())) return { error: "Not authorized." };
  await db.blogPost.delete({ where: { id } });
  revalidatePath("/dashboard/admin/blog");
  revalidatePath("/blog");
  return { success: true };
}
