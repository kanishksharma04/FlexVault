"use server";

import { revalidatePath } from "next/cache";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { generateCertificateHash } from "@/lib/business/certificate";

export async function reviewAuthentication(
  recordId: string,
  decision: "APPROVED" | "REJECTED",
  notes: string
) {
  const session = await auth();
  if (!session?.user || (session.user.role !== "ADMIN" && session.user.role !== "AUTHENTICATOR")) {
    return { error: "Not authorized." };
  }
  if (decision === "REJECTED" && !notes.trim()) {
    return { error: "A reason is required to reject a listing." };
  }

  const record = await db.authenticationRecord.findUnique({ where: { id: recordId } });
  if (!record || record.status !== "PENDING") return { error: "This item has already been reviewed." };

  await db.authenticationRecord.update({
    where: { id: recordId },
    data: {
      status: decision,
      notes,
      authenticatorId: session.user.id,
      reviewedAt: new Date(),
      certificateHash: decision === "APPROVED" ? generateCertificateHash(record.listingId) : null,
    },
  });

  await db.listing.update({
    where: { id: record.listingId },
    data: { status: decision === "APPROVED" ? "ACTIVE" : "REJECTED" },
  });

  revalidatePath("/dashboard/admin/authentication");
  revalidatePath("/dashboard/admin");
  return { success: true };
}
