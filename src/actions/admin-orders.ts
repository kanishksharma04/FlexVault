"use server";

import { revalidatePath } from "next/cache";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import type { OrderStatus, Prisma } from "@prisma/client";

async function assertAdmin() {
  const session = await auth();
  if (!session?.user || session.user.role !== "ADMIN") return null;
  return session;
}

export async function updateOrderStatus(orderId: string, status: OrderStatus) {
  if (!(await assertAdmin())) return { error: "Not authorized." };

  const order = await db.order.findUnique({ where: { id: orderId } });
  if (!order) return { error: "Order not found." };

  const trackingEvents = (Array.isArray(order.trackingEvents) ? order.trackingEvents : []) as Prisma.InputJsonValue[];
  await db.order.update({
    where: { id: orderId },
    data: {
      status,
      trackingEvents: [
        ...trackingEvents,
        { status, label: `Status updated to ${status} by admin`, at: new Date().toISOString() },
      ],
    },
  });

  revalidatePath("/dashboard/admin/orders");
  return { success: true };
}

export async function resolveDispute(reviewId: string, resolution: "RESOLVED_BUYER" | "RESOLVED_SELLER", note: string) {
  if (!(await assertAdmin())) return { error: "Not authorized." };

  const review = await db.review.findUnique({ where: { id: reviewId } });
  if (!review) return { error: "Dispute not found." };

  await db.review.update({
    where: { id: reviewId },
    data: {
      status: resolution,
      resolution: note,
      refundIssued: resolution === "RESOLVED_BUYER",
      resolvedAt: new Date(),
    },
  });

  await db.order.update({
    where: { id: review.orderId },
    data: { status: resolution === "RESOLVED_BUYER" ? "RETURNED" : "DELIVERED" },
  });

  revalidatePath("/dashboard/admin/orders");
  return { success: true };
}
