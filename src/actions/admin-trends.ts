"use server";

import { revalidatePath } from "next/cache";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";

async function assertAdmin() {
  const session = await auth();
  if (!session?.user || session.user.role !== "ADMIN") return null;
  return session;
}

export async function updateTrendWeights(formData: FormData) {
  if (!(await assertAdmin())) return { error: "Not authorized." };

  const mentionVelocityWeight = Number(formData.get("mentionVelocityWeight"));
  const sentimentWeight = Number(formData.get("sentimentWeight"));
  const engagementWeight = Number(formData.get("engagementWeight"));

  if (![mentionVelocityWeight, sentimentWeight, engagementWeight].every(Number.isFinite)) {
    return { error: "Enter valid numeric weights." };
  }

  const existing = await db.trendWeightConfig.findFirst();
  if (existing) {
    await db.trendWeightConfig.update({
      where: { id: existing.id },
      data: { mentionVelocityWeight, sentimentWeight, engagementWeight },
    });
  } else {
    await db.trendWeightConfig.create({ data: { mentionVelocityWeight, sentimentWeight, engagementWeight } });
  }

  revalidatePath("/dashboard/admin/trends");
  return { success: true };
}

export async function overrideTrendScore(productId: string, score: number, reasonSummary: string) {
  if (!(await assertAdmin())) return { error: "Not authorized." };

  if (!Number.isFinite(score) || score < 0 || score > 100) {
    return { error: "Score must be a number between 0 and 100." };
  }

  await db.trendScore.create({
    data: {
      productId,
      score,
      mentionVelocity: score,
      sentimentScore: score,
      engagementGrowth: score,
      reasonSummary: reasonSummary || "Manually adjusted by admin",
    },
  });

  revalidatePath("/dashboard/admin/trends");
  revalidatePath("/trend");
  return { success: true };
}
