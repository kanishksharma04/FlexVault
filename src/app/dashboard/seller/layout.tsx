import { LayoutDashboard, Tag, Package, Wallet, Crown } from "lucide-react";
import { DashboardShell, type DashboardNavItem } from "@/components/dashboard/dashboard-shell";

const iconClass = "size-4 shrink-0";

const NAV: DashboardNavItem[] = [
  { href: "/dashboard/seller", label: "Overview", icon: <LayoutDashboard className={iconClass} />, exact: true },
  { href: "/dashboard/seller/listings", label: "Listings", icon: <Tag className={iconClass} /> },
  { href: "/dashboard/seller/orders", label: "Sales", icon: <Package className={iconClass} /> },
  { href: "/dashboard/seller/payouts", label: "Payouts", icon: <Wallet className={iconClass} /> },
  { href: "/dashboard/seller/pro", label: "Flex Vault Pro", icon: <Crown className={iconClass} /> },
];

export default function SellerDashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <DashboardShell title="SELLER HUB" subtitle="Seller Dashboard" nav={NAV}>
      {children}
    </DashboardShell>
  );
}
