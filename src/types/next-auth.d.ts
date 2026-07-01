import type { DefaultSession } from "next-auth";

declare module "next-auth" {
  interface Session {
    user: {
      id: string;
      role: "BUYER" | "SELLER" | "ADMIN" | "AUTHENTICATOR";
      sellerTier: string;
      isProMember: boolean;
    } & DefaultSession["user"];
  }

  interface User {
    role?: string;
    sellerTier?: string;
    isProMember?: boolean;
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    id: string;
    role: string;
    sellerTier: string;
    isProMember: boolean;
  }
}
