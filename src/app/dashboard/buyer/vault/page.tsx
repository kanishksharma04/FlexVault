import Image from "next/image";
import { ShieldOff, ShieldCheck } from "lucide-react";
import { auth } from "@/lib/auth";
import { getBuyerVaultItems } from "@/lib/queries/buyer";
import { EmptyState } from "@/components/vault/empty-state";

export const dynamic = "force-dynamic";

export default async function DigitalVaultPage() {
  const session = await auth();
  if (!session?.user) return null;
  const items = await getBuyerVaultItems(session.user.id);

  if (items.length === 0) {
    return (
      <EmptyState
        icon={ShieldOff}
        title="YOUR VAULT IS EMPTY"
        description="Delivered, authenticated items appear here as your permanent collection."
      />
    );
  }

  return (
    <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-4">
      {items.map((order) => (
        <div key={order.id} className="card-hype group relative flex flex-col overflow-hidden border border-border bg-card">
          <div className="relative aspect-square w-full overflow-hidden bg-vault-3">
            <Image src={order.listing.product.images[0]} alt={order.listing.product.name} fill className="object-cover" />
            <div className="absolute right-2 top-2 flex items-center gap-1 rounded-full border border-acid/40 bg-vault/80 px-2 py-1 font-mono text-[9px] uppercase tracking-wider text-acid backdrop-blur">
              <ShieldCheck className="size-3" />
              Verified
            </div>
          </div>
          <div className="flex flex-col gap-1 p-3">
            <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">{order.listing.product.brand}</p>
            <p className="line-clamp-2 text-sm font-semibold">{order.listing.product.name}</p>
            <p className="font-mono text-[10px] text-muted-foreground">
              Delivered {new Date(order.updatedAt).toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" })}
            </p>
            {order.listing.authenticationRecord?.certificateHash && (
              <p className="truncate font-mono text-[9px] text-muted-foreground/70">
                {order.listing.authenticationRecord.certificateHash.slice(0, 24)}...
              </p>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
