"use client";

import Link from "next/link";
import { signOut } from "next-auth/react";
import { LayoutDashboard, LogOut, ShieldCheck, Store, User as UserIcon } from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";

type SessionUser = {
  name?: string | null;
  email?: string | null;
  image?: string | null;
  role: string;
};

const DASHBOARD_BY_ROLE: Record<string, { href: string; label: string; icon: typeof LayoutDashboard }> = {
  BUYER: { href: "/dashboard/buyer", label: "My Vault", icon: LayoutDashboard },
  SELLER: { href: "/dashboard/seller", label: "Seller Dashboard", icon: Store },
  ADMIN: { href: "/dashboard/admin", label: "Admin Hub", icon: ShieldCheck },
  AUTHENTICATOR: { href: "/dashboard/admin/authentication", label: "Auth Queue", icon: ShieldCheck },
};

export function UserMenu({ user }: { user: SessionUser }) {
  const dash = DASHBOARD_BY_ROLE[user.role] ?? DASHBOARD_BY_ROLE.BUYER;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button className="flex items-center gap-2 rounded-full border border-border p-0.5 pr-2 transition hover:border-acid">
          <Avatar className="size-7">
            <AvatarImage src={user.image ?? undefined} />
            <AvatarFallback className="bg-vault-3 text-xs">
              {user.name?.[0]?.toUpperCase() ?? <UserIcon className="size-3.5" />}
            </AvatarFallback>
          </Avatar>
          <span className="hidden font-mono text-xs text-muted-foreground sm:inline">
            {user.name?.split(" ")[0]}
          </span>
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-56">
        <DropdownMenuLabel className="font-normal">
          <p className="text-sm font-semibold">{user.name}</p>
          <p className="truncate text-xs text-muted-foreground">{user.email}</p>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem asChild>
          <Link href={dash.href}>
            <dash.icon className="mr-2 size-4" />
            {dash.label}
          </Link>
        </DropdownMenuItem>
        {user.role !== "SELLER" && (
          <DropdownMenuItem asChild>
            <Link href="/dashboard/buyer/vault">
              <ShieldCheck className="mr-2 size-4" />
              Digital Vault
            </Link>
          </DropdownMenuItem>
        )}
        <DropdownMenuSeparator />
        <DropdownMenuItem
          onClick={() => signOut({ callbackUrl: "/" })}
          className="text-hype focus:text-hype"
        >
          <LogOut className="mr-2 size-4" />
          Sign out
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export function AuthButtons() {
  return (
    <div className="flex items-center gap-1 sm:gap-2">
      <Button asChild variant="ghost" size="sm" className="hidden sm:inline-flex">
        <Link href="/login">Log in</Link>
      </Button>
      <Button asChild size="sm">
        <Link href="/signup">Sign up</Link>
      </Button>
    </div>
  );
}
