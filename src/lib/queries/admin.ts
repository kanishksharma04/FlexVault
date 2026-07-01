import { db } from "@/lib/db";

export async function getAdminStats() {
  const [pendingAuth, activeListings, totalUsers, totalOrders, openDisputes, gmv] = await Promise.all([
    db.listing.count({ where: { status: "PENDING_AUTH", archivedAt: null } }),
    db.listing.count({ where: { status: "ACTIVE", archivedAt: null } }),
    db.user.count({ where: { archivedAt: null } }),
    db.order.count(),
    db.review.count({ where: { status: { in: ["OPEN", "UNDER_REVIEW"] } } }),
    db.order.aggregate({ _sum: { price: true } }),
  ]);

  return {
    pendingAuth,
    activeListings,
    totalUsers,
    totalOrders,
    openDisputes,
    gmv: gmv._sum.price ?? 0,
  };
}

export async function getAuthQueue() {
  return db.authenticationRecord.findMany({
    where: { status: "PENDING" },
    orderBy: { createdAt: "asc" },
    include: {
      listing: {
        include: {
          product: true,
          seller: { select: { name: true, sellerTier: true } },
        },
      },
    },
  });
}
