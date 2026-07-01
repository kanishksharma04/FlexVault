import {
  LayoutDashboard,
  ShieldCheck,
  Package,
  Layers,
  Users,
  ClipboardList,
  Tag,
  TrendingUp,
  Sparkles,
  Newspaper,
} from "lucide-react";
import { DashboardShell, type DashboardNavItem } from "@/components/dashboard/dashboard-shell";

const iconClass = "size-4 shrink-0";

const NAV: DashboardNavItem[] = [
  { href: "/dashboard/admin", label: "Overview", icon: <LayoutDashboard className={iconClass} />, exact: true },
  { href: "/dashboard/admin/authentication", label: "Auth Queue", icon: <ShieldCheck className={iconClass} /> },
  { href: "/dashboard/admin/products", label: "Products", icon: <Package className={iconClass} /> },
  { href: "/dashboard/admin/listings", label: "Listings", icon: <Tag className={iconClass} /> },
  { href: "/dashboard/admin/categories", label: "Categories", icon: <Layers className={iconClass} /> },
  { href: "/dashboard/admin/users", label: "Users", icon: <Users className={iconClass} /> },
  { href: "/dashboard/admin/orders", label: "Orders", icon: <ClipboardList className={iconClass} /> },
  { href: "/dashboard/admin/drops", label: "Drops", icon: <Sparkles className={iconClass} /> },
  { href: "/dashboard/admin/trends", label: "Trend Weights", icon: <TrendingUp className={iconClass} /> },
  { href: "/dashboard/admin/blog", label: "Editorial", icon: <Newspaper className={iconClass} /> },
];

export default function AdminDashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <DashboardShell title="AUTHENTICATION HUB" subtitle="Admin Dashboard" nav={NAV}>
      {children}
    </DashboardShell>
  );
}
