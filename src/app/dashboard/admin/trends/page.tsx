import { db } from "@/lib/db";
import { DEFAULT_TREND_WEIGHTS } from "@/lib/business/constants";
import { TrendWeightsForm } from "@/components/admin/trend-weights-form";
import { TrendOverrideForm } from "@/components/admin/trend-override-form";

export const dynamic = "force-dynamic";

export default async function AdminTrendsPage() {
  const config = await db.trendWeightConfig.findFirst();

  return (
    <div className="flex flex-col gap-6">
      <TrendWeightsForm weights={config ?? DEFAULT_TREND_WEIGHTS} />
      <TrendOverrideForm />
    </div>
  );
}
