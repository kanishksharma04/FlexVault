import { db } from "@/lib/db";
import { OrdersTable } from "@/components/admin/orders-table";

export const dynamic = "force-dynamic";

export default async function AdminOrdersPage() {
  const orders = await db.order.findMany({
    orderBy: { createdAt: "desc" },
    take: 50,
    include: {
      buyer: { select: { name: true } },
      listing: { include: { product: { select: { name: true } }, seller: { select: { name: true } } } },
      reviews: { select: { id: true, reason: true, status: true } },
    },
  });

  return <OrdersTable orders={orders} />;
}
