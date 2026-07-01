import { db } from "@/lib/db";
import { AdminListingsTable } from "@/components/admin/admin-listings-table";
import { AdminSearchBar } from "@/components/admin/admin-search-bar";

export const dynamic = "force-dynamic";

type Props = { searchParams: Promise<{ q?: string }> };

export default async function AdminListingsPage({ searchParams }: Props) {
  const { q } = await searchParams;

  const listings = await db.listing.findMany({
    where: {
      archivedAt: null,
      ...(q ? { product: { name: { contains: q, mode: "insensitive" } } } : {}),
    },
    orderBy: { createdAt: "desc" },
    take: 50,
    include: { product: { select: { name: true, images: true } }, seller: { select: { name: true } } },
  });

  return (
    <div className="flex flex-col gap-4">
      <AdminSearchBar placeholder="Search listings by product..." />
      <AdminListingsTable listings={listings} />
    </div>
  );
}
