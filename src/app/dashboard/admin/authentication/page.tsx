import { ShieldCheck } from "lucide-react";
import { getAuthQueue } from "@/lib/queries/admin";
import { EmptyState } from "@/components/vault/empty-state";
import { AuthQueueCard } from "@/components/admin/auth-queue-card";

export const dynamic = "force-dynamic";

export default async function AuthQueuePage() {
  const queue = await getAuthQueue();

  if (queue.length === 0) {
    return <EmptyState icon={ShieldCheck} title="QUEUE CLEAR" description="No listings waiting on authentication." />;
  }

  return (
    <div className="flex flex-col gap-4">
      <p className="font-mono text-xs text-muted-foreground">{queue.length} item{queue.length === 1 ? "" : "s"} awaiting review</p>
      {queue.map((entry) => (
        <AuthQueueCard key={entry.id} entry={entry} />
      ))}
    </div>
  );
}
