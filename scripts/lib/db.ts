import path from "node:path";
import fs from "node:fs";
import dotenv from "dotenv";
import { PrismaClient } from "@prisma/client";

// Standalone scripts (invoked via `node`/`tsx`, not `next dev`) don't get Next.js's
// automatic .env.local > .env precedence, so a plain `new PrismaClient()` here would
// silently fall back to whatever's in `.env` — historically the disposable local
// Postgres instance, not the real database the app actually runs against.
//
// Default target: .env.local (the real DB, same one `next dev` and production use).
// Escape hatch: USE_LOCAL_DB=1 to explicitly opt into `.env` for local dry-runs.
const root = path.resolve(import.meta.dirname, "../..");
const useLocal = process.env.USE_LOCAL_DB === "1";
const envFile = useLocal ? ".env" : ".env.local";
const envPath = path.join(root, envFile);

if (!fs.existsSync(envPath)) {
  throw new Error(
    `[scripts/lib/db] Expected ${envFile} at ${envPath} but it doesn't exist. ` +
      `Set USE_LOCAL_DB=1 to target .env instead, or create the missing file.`
  );
}

dotenv.config({ path: envPath, override: true });

if (!process.env.DATABASE_URL) {
  throw new Error(`[scripts/lib/db] DATABASE_URL is not set after loading ${envFile}.`);
}

console.log(`[scripts/lib/db] Using DATABASE_URL from ${envFile}${useLocal ? " (local, via USE_LOCAL_DB=1)" : ""}.`);

export const db = new PrismaClient();
