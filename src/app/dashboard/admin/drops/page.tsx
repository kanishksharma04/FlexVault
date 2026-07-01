import { db } from "@/lib/db";
import { DropsTable } from "@/components/admin/drops-table";

export const dynamic = "force-dynamic";

export default async function AdminDropsPage() {
  const drops = await db.drop.findMany({
    orderBy: { dropDate: "desc" },
    include: { featuredProducts: { include: { product: { select: { id: true, name: true, images: true } } } } },
  });

  return <DropsTable drops={drops} />;
}
