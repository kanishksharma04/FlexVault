import { PackagePlus } from "lucide-react";
import { auth } from "@/lib/auth";
import { getSellerListings } from "@/lib/queries/seller";
import { EmptyState } from "@/components/vault/empty-state";
import { ListingsTable } from "@/components/dashboard/listings-table";
import { Button } from "@/components/ui/button";
import Link from "next/link";

export const dynamic = "force-dynamic";

export default async function SellerListingsPage() {
  const session = await auth();
  if (!session?.user) return null;
  const listings = await getSellerListings(session.user.id);

  if (listings.length === 0) {
    return (
      <EmptyState
        icon={PackagePlus}
        title="NO LISTINGS YET"
        description="Create your first listing to start selling on Flex Vault."
        action={
          <Button asChild className="mt-2">
            <Link href="/sell">Create a Listing</Link>
          </Button>
        }
      />
    );
  }

  return <ListingsTable listings={listings} />;
}
