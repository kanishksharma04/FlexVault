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
  });

  return (
    <div className="flex flex-col gap-4">
      <AdminSearchBar placeholder="Search users..." />
      <UsersTable users={users} />
    </div>
  );
}
