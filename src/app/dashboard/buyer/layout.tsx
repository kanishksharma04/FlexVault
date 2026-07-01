import { LayoutDashboard, Package, ShieldCheck, Heart, Gavel } from "lucide-react";
import { DashboardShell, type DashboardNavItem } from "@/components/dashboard/dashboard-shell";

const iconClass = "size-4 shrink-0";

const NAV: DashboardNavItem[] = [
  { href: "/dashboard/buyer", label: "Overview", icon: <LayoutDashboard className={iconClass} />, exact: true },
  { href: "/dashboard/buyer/orders", label: "Orders", icon: <Package className={iconClass} /> },
  { href: "/dashboard/buyer/vault", label: "Digital Vault", icon: <ShieldCheck className={iconClass} /> },
  { href: "/dashboard/buyer/watchlist", label: "Watchlist", icon: <Heart className={iconClass} /> },
  { href: "/dashboard/buyer/bids", label: "Active Bids", icon: <Gavel className={iconClass} /> },
];

export default function BuyerDashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <DashboardShell title="MY VAULT" subtitle="Buyer Dashboard" nav={NAV}>
      {children}
    </DashboardShell>
  );
}
