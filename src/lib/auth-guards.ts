import { auth } from "@/lib/auth";

/** Resolves the current session, or `null` if the user isn't an authenticated admin. */
export async function assertAdmin() {
  const session = await auth();
  if (!session?.user || session.user.role !== "ADMIN") return null;
  return session;
}
