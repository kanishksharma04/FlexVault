import type { NextAuthConfig } from "next-auth";

/**
 * Edge-safe subset of the Auth.js config — no Prisma adapter, no
 * bcrypt/DB-touching providers. Middleware runs on the Edge runtime with a
 * strict bundle size limit, so it must only pull in this file, not the full
 * config in `auth.ts` (which drags in Prisma Client + bcryptjs).
 */
export const authConfig = {
  session: { strategy: "jwt" },
  pages: { signIn: "/login" },
  providers: [],
  callbacks: {
    jwt: async ({ token, user }) => {
      if (user) {
        token.id = user.id as string;
        token.role = user.role as string;
        token.sellerTier = user.sellerTier as string;
        token.isProMember = user.isProMember as boolean;
      }
      return token;
    },
    session: async ({ session, token }) => {
      if (session.user) {
        session.user.id = token.id as string;
        session.user.role = token.role as "BUYER" | "SELLER" | "ADMIN" | "AUTHENTICATOR";
        session.user.sellerTier = token.sellerTier as string;
        session.user.isProMember = token.isProMember as boolean;
      }
      return session;
    },
  },
} satisfies NextAuthConfig;
