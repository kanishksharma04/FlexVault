# Flex Vault

**Drip. Verified. Delivered.**

India's authenticated marketplace for hype culture — sneakers, streetwear, diecast collectibles,
watches, and accessories — built as a full-stack Next.js app with real multi-layer authentication,
trend detection, bidding, and PAN-India delivery tracking.

## Tech Stack

- **Framework:** Next.js 16 (App Router, TypeScript, Server Actions)
- **Styling:** Tailwind CSS v4 + hand-authored Radix-based UI primitives ("Vault Streetwear" design system)
- **Animation:** Framer Motion (respects `prefers-reduced-motion` globally via `MotionConfig`)
- **Database:** PostgreSQL via Prisma ORM
- **Auth:** Auth.js (NextAuth v5) — email/password + optional Google OAuth, role-based access
- **Data fetching:** React Server Components + TanStack Query for client interactivity (search, cart)
- **File uploads:** `UploadAdapter` interface — Vercel Blob when `BLOB_READ_WRITE_TOKEN` is set, local disk otherwise (dev only)
- **Validation:** Zod

## Getting Started

### 1. Prerequisites

- Node.js 20+
- A local PostgreSQL server (or any reachable Postgres instance)

### 2. Install dependencies

```bash
npm install
```

### 3. Configure environment variables

Copy `.env.example` to `.env` and fill in the values:

```bash
cp .env.example .env
```

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string |
| `AUTH_SECRET` | Random secret for Auth.js — generate with `npx auth secret` |
| `NEXTAUTH_URL` | App URL, e.g. `http://localhost:3000` |
| `AUTH_GOOGLE_ID` / `AUTH_GOOGLE_SECRET` | Optional — leave blank to disable Google sign-in |
| `BLOB_READ_WRITE_TOKEN` | Optional — leave blank to fall back to local-disk uploads in dev; set automatically when a Blob store is connected on Vercel |

### 4. Set up the database

```bash
npx prisma migrate dev   # creates the schema
npm run db:seed          # seeds ~60 products, 190+ listings, users, orders, trend history, a blog, and a drop
```

### 5. Run the dev server

```bash
npm run dev
```

Visit [http://localhost:3000](http://localhost:3000).

## Demo Accounts

All seeded accounts share the password **`FlexVault@123`**.

| Role | Email | Notes |
|---|---|---|
| Admin | `admin@flexvault.in` | Full Authentication Hub access |
| Authenticator | `authenticator@flexvault.in` | Auth queue access |
| Seller (Bronze) | `seller.bronze@flexvault.in` | |
| Seller (Silver) | `seller.silver@flexvault.in` | |
| Seller (Gold) | `seller.gold@flexvault.in` | |
| Seller (Platinum, Pro) | `seller.platinum@flexvault.in` | |
| Buyer | `buyer@flexvault.in` | |
| Buyer (Pro) | `buyer.pro@flexvault.in` | |
| Buyer | `buyer.vault@flexvault.in` | Has a delivered order for Digital Vault demo |

## Project Structure

```
src/
  actions/          Server actions (auth, checkout, listings, admin CRUD, bids, watchlist...)
  app/               App Router routes
    (auth)/          Login, signup, forgot password
    browse/[category] Filterable/sortable/paginated catalog
    product/[slug]   PDP — gallery, listings, trend gauge, certificate, related items
    checkout/        3-step wizard (shipping → payment → review) with animated confirmation
    sell/            6-step seller listing flow with AI price suggestion + photo upload
    dashboard/
      buyer/         Orders, Digital Vault, watchlist, active bids
      seller/        Listings CRUD, sales, payouts, tier progress, Pro upsell
      admin/         Auth queue, full CRUD for products/listings/categories/users/orders/drops,
                      trend weight config, editorial CRUD
    trend/           Public live Hype Feed (spike alerts + trending grid)
    blog/            Public editorial pages
  components/        UI primitives, landing sections, dashboard/admin/sell/checkout components
  lib/
    business/        Trend score formula, pricing suggestion, commission tiers, certificate hashing
    queries/         Server-side Prisma query helpers
prisma/
  schema.prisma      Full data model (Users, Products, Listings, Orders, Bids, TrendScore, ...)
  seed.ts            Deterministic-ish demo data generator
```

## Business Logic

- **Trend Score:** `score = w1·mentionVelocity + w2·sentimentScore + w3·engagementGrowth`, with
  admin-configurable weights (`/dashboard/admin/trends`) and a manual override tool.
- **Seller tiers:** Bronze → Platinum, decreasing commission (10% → 8%) and faster payouts, with a
  Flex Vault Pro membership stacking an additional commission discount.
- **Pricing suggestion:** heuristic blend of recent sold comps and current trend score, shown live
  during the seller listing flow.
- **Authentication workflow:** every listing starts `PENDING_AUTH` → reviewed in the admin queue with
  inspection photos → `APPROVED` (mock certificate hash + QR generated) or `REJECTED` (reason required).
- **Insurance:** opt-in, recommended by default for items ≥ ₹10,000, cost bundled into checkout total.

## Testing

```bash
npm run test
```

## Notes

- This is a demo build: payments, email sending, and certificate hashes are simulated — no real
  transactions or blockchain writes occur.
- Product photography is generated as deterministic gradient placeholders (`src/lib/mock-image.ts`)
  rather than scraped brand assets.
