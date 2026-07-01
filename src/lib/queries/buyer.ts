import { db } from "@/lib/db";

export async function getBuyerOrders(userId: string) {
  return db.order.findMany({
    where: { buyerId: userId },
    orderBy: { createdAt: "desc" },
    include: {
      listing: {
        include: {
          product: true,
          seller: { select: { name: true, sellerTier: true } },
          authenticationRecord: true,
        },
      },
      address: true,
      reviews: true,
    },
  });
}

export async function getBuyerVaultItems(userId: string) {
  return db.order.findMany({
    where: { buyerId: userId, status: "DELIVERED" },
    orderBy: { createdAt: "desc" },
    include: {
      listing: { include: { product: true, authenticationRecord: true } },
    },
  });
}

export async function getBuyerWatchlist(userId: string) {
  return db.watchlistItem.findMany({
    where: { userId },
    orderBy: { createdAt: "desc" },
    include: {
      product: {
        include: {
          listings: { where: { status: "ACTIVE" }, orderBy: { price: "asc" }, take: 1 },
          trendHistory: { orderBy: { calculatedAt: "desc" }, take: 1 },
        },
      },
    },
  });
}

export async function getBuyerBids(userId: string) {
  return db.bid.findMany({
    where: { bidderId: userId },
    orderBy: { createdAt: "desc" },
    include: {
      listing: { include: { product: true, bids: { orderBy: { amount: "desc" }, take: 1 } } },
    },
  });
}

export async function getBuyerStats(userId: string) {
  const [orderCount, activeBids, watchlistCount, vaultCount] = await Promise.all([
    db.order.count({ where: { buyerId: userId } }),
    db.bid.count({ where: { bidderId: userId, status: "ACTIVE" } }),
    db.watchlistItem.count({ where: { userId } }),
    db.order.count({ where: { buyerId: userId, status: "DELIVERED" } }),
  ]);
  return { orderCount, activeBids, watchlistCount, vaultCount };
}
