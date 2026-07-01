import { NextResponse } from "next/server";
import NextAuth from "next-auth";
import { authConfig } from "@/lib/auth.config";

// Edge-safe auth instance — built only from the lightweight config so this
// middleware's bundle doesn't pull in Prisma Client / bcryptjs (see auth.config.ts).
const { auth } = NextAuth(authConfig);

const ROLE_PREFIXES: { prefix: string; roles: string[] }[] = [
  { prefix: "/dashboard/buyer", roles: ["BUYER", "ADMIN"] },
  { prefix: "/dashboard/seller", roles: ["SELLER", "ADMIN"] },
  { prefix: "/dashboard/admin", roles: ["ADMIN", "AUTHENTICATOR"] },
  { prefix: "/sell", roles: ["SELLER", "ADMIN"] },
];

const AUTH_ONLY_PREFIXES = ["/checkout"];

export default auth((req) => {
  const { pathname, origin } = req.nextUrl;

  const roleMatch = ROLE_PREFIXES.find((r) => pathname.startsWith(r.prefix));
  const authOnlyMatch = AUTH_ONLY_PREFIXES.some((p) => pathname.startsWith(p));

  if (!roleMatch && !authOnlyMatch) return NextResponse.next();

  const role = req.auth?.user?.role;
  if (!req.auth || !role) {
    const loginUrl = new URL("/login", origin);
    loginUrl.searchParams.set("callbackUrl", pathname);
    return NextResponse.redirect(loginUrl);
  }
  if (roleMatch && !roleMatch.roles.includes(role)) {
    return NextResponse.redirect(new URL("/", origin));
  }
  return NextResponse.next();
});

export const config = {
  matcher: ["/dashboard/:path*", "/sell/:path*", "/checkout/:path*"],
};
