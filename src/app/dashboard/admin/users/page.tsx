import { db } from "@/lib/db";
import { UsersTable } from "@/components/admin/users-table";
import { AdminSearchBar } from "@/components/admin/admin-search-bar";

export const dynamic = "force-dynamic";

type Props = { searchParams: Promise<{ q?: string }> };

export default async function AdminUsersPage({ searchParams }: Props) {
  const { q } = await searchParams;

  const users = await db.user.findMany({
    where: {
      archivedAt: null,
      ...(q ? { OR: [{ name: { contains: q, mode: "insensitive" } }, { email: { contains: q, mode: "insensitive" } }] } : {}),
    },
    orderBy: { createdAt: "desc" },
    take: 50,
    // Select only what UsersTable (a Client Component) needs — it's a plain
    // findMany otherwise, and every field including passwordHash would be
    // serialized into the RSC payload sent to the admin's browser.
    select: { id: true, name: true, email: true, role: true, sellerTier: true, isProMember: true },
  });

  return (
    <div className="flex flex-col gap-4">
      <AdminSearchBar placeholder="Search users..." />
      <UsersTable users={users} />
    </div>
  );
}
