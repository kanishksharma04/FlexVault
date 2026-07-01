import { db } from "@/lib/db";

export async function getSellerListings(sellerId: string) {
  return db.listing.findMany({
    where: { sellerId, archivedAt: null },
    orderBy: { createdAt: "desc" },
    include: {
      product: true,
      authenticationRecord: true,
      orders: true,
      bids: { orderBy: { amount: "desc" }, take: 1 },
    },
  });
}

export async function getSellerOrders(sellerId: string) {
  return db.order.findMany({
    where: { listing: { sellerId } },
    orderBy: { createdAt: "desc" },
    include: { listing: { include: { product: true } }, buyer: { select: { name: true } } },
  });
}

export async function getSellerStats(sellerId: string) {
  const [activeListings, pendingAuth, orders, listings] = await Promise.all([
    db.listing.count({ where: { sellerId, status: "ACTIVE", archivedAt: null } }),
    db.listing.count({ where: { sellerId, status: "PENDING_AUTH", archivedAt: null } }),
    db.order.findMany({ where: { listing: { sellerId } }, select: { price: true, commissionRate: true, status: true } }),
    db.listing.count({ where: { sellerId, archivedAt: null } }),
  ]);

  const totalSales = orders.length;
  const grossRevenue = orders.reduce((sum, o) => sum + o.price, 0);
  const netPayout = orders.reduce((sum, o) => sum + o.price * (1 - o.commissionRate), 0);

  return { activeListings, pendingAuth, totalListings: listings, totalSales, grossRevenue, netPayout };
}

export async function getSellerSalesByDay(sellerId: string, days = 14) {
  const since = new Date(Date.now() - days * 86_400_000);
  const orders = await db.order.findMany({
    where: { listing: { sellerId }, createdAt: { gte: since } },
    select: { createdAt: true, price: true },
  });

  const buckets = new Map<string, number>();
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(Date.now() - i * 86_400_000);
    buckets.set(d.toISOString().slice(0, 10), 0);
  }
  for (const o of orders) {
    const key = o.createdAt.toISOString().slice(0, 10);
    if (buckets.has(key)) buckets.set(key, (buckets.get(key) ?? 0) + o.price);
  }
  return Array.from(buckets.entries()).map(([date, total]) => ({ date, total }));
}
