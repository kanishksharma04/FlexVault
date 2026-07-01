"use client";

import { useTransition } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { updateTrendWeights } from "@/actions/admin-trends";

export function TrendWeightsForm({
  weights,
}: {
  weights: { mentionVelocityWeight: number; sentimentWeight: number; engagementWeight: number };
}) {
  const [pending, startTransition] = useTransition();

  return (
    <form
      action={(formData) =>
        startTransition(async () => {
          const res = await updateTrendWeights(formData);
          if ("error" in res && res.error) {
            toast.error(res.error);
            return;
          }
          toast.success("Trend weights updated.");
        })
      }
      className="flex flex-col gap-4 border border-border bg-card p-5"
    >
      <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
        Trend Score Formula Weights — should sum to 1.0
      </p>
      <div className="grid gap-4 sm:grid-cols-3">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="mentionVelocityWeight">Mention Velocity</Label>
          <Input id="mentionVelocityWeight" name="mentionVelocityWeight" type="number" step="0.05" min={0} max={1} defaultValue={weights.mentionVelocityWeight} />
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="sentimentWeight">Sentiment</Label>
          <Input id="sentimentWeight" name="sentimentWeight" type="number" step="0.05" min={0} max={1} defaultValue={weights.sentimentWeight} />
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="engagementWeight">Engagement Growth</Label>
          <Input id="engagementWeight" name="engagementWeight" type="number" step="0.05" min={0} max={1} defaultValue={weights.engagementWeight} />
        </div>
      </div>
      <Button type="submit" className="w-fit" disabled={pending}>
        {pending ? "Saving..." : "Save Weights"}
      </Button>
    </form>
  );
}
