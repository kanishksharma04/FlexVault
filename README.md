# Flex Vault

**Drip. Verified. Delivered.**

India's authenticated marketplace for hype culture — sneakers, streetwear, diecast collectibles,
watches, and accessories — built as a full-stack Next.js app with real multi-layer authentication,
trend detection, bidding, and PAN-India delivery tracking.

[![CI](https://github.com/kanishksharma04/FlexVault/actions/workflows/ci.yml/badge.svg)](https://github.com/kanishksharma04/FlexVault/actions/workflows/ci.yml)

---

## Table of Contents

- [Overview](#overview)
- [Core Features](#core-features)
- [Architecture](#architecture)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Environment Variables](#environment-variables)
- [Database](#database)
- [Available Scripts](#available-scripts)
- [Authentication Flow](#authentication-flow)
- [API Routes](#api-routes)
- [Business Logic](#business-logic)
- [Testing](#testing)
- [Security](#security)
- [Deployment](#deployment)
- [Design Decisions & Philosophy](#design-decisions--philosophy)
- [Known Limitations](#known-limitations)
- [Future Improvements](#future-improvements)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgements](#acknowledgements)

---

## Overview

Flex Vault is a demo full-stack marketplace that simulates the operational model of authenticated
resale platforms (StockX, Grailed, Chrono24): every listing passes through a human authentication
queue before it goes live, sellers are ranked into commission tiers, and pricing is guided by a live
trend score computed from mention velocity, sentiment, and engagement signals.

It is built entirely on the Next.js App Router with Server Actions as the primary mutation layer —
there is no separate REST/GraphQL backend. Four roles (`BUYER`, `SELLER`, `ADMIN`, `AUTHENTICATOR`)
share one codebase, gated by role-aware dashboards and server-side authorization checks.

## Core Features

| Area | What it does |
|---|---|
| **Catalog & browse** | Filterable, sortable, paginated product browsing by category, brand, size, condition, price, and trend score |
| **Product detail** | Image gallery, all active listings for a product, live trend gauge, authentication certificate preview, related items |
| **Checkout** | 3-step wizard (shipping → payment → review) with server-side price/commission/insurance calculation and transactional, race-safe listing claims |
| **Selling** | 6-step listing flow with an AI-style price suggestion (recent comps + trend score) and photo upload with server-side image validation |
| **Bidding** | Live auctions with Serializable-transaction bid placement so two concurrent bids can't both "win" |
| **Authentication queue** | Every listing starts `PENDING_AUTH`; admins/authenticators approve (issuing a certificate hash + QR) or reject with a required reason |
| **Seller tiers & Pro membership** | Bronze → Platinum tiers with decreasing commission and faster payouts; a Pro membership stacks an additional discount |
| **Trend intelligence** | Configurable weighted trend score, a public "Hype Feed" of trending products, and an admin override tool |
| **Dashboards** | Role-specific dashboards for buyers (orders, Digital Vault, watchlist, bids), sellers (listings, sales, payouts), and admins (full CRUD + authentication hub) |
| **Editorial** | A lightweight blog/CMS for admin-authored articles |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Next.js App Router                          │
│                                                                    │
│  Server Components (RSC)  ──►  Prisma  ──►  PostgreSQL             │
│         │                                                          │
│         ├──  Server Actions  ──►  Prisma  ──►  PostgreSQL          │
│         │        (all writes: checkout, bids, admin CRUD, auth)    │
│         │                                                          │
│         └──  Route Handlers (/api/*)  ──►  Prisma / Upstash        │
│                  (search, pricing suggestion, uploads)              │
│                                                                     │
│  src/proxy.ts  ──►  optimistic role-gate redirect (UX only)        │
│  Auth.js (JWT sessions)  ──►  Prisma adapter                       │
└─────────────────────────────────────────────────────────────────┘
```

There is no client-side data-mutation library (no Redux/Zustand mutations, no REST client for
writes) — forms post directly to Server Actions via `useActionState`/`useTransition`, and
TanStack Query is used only for a handful of client-driven reads (live search, the price-suggestion
poll, the product picker).

**Defense in depth:** the role-gated proxy on `/dashboard/*`, `/sell`, and `/checkout` is a UX
redirect, not the security boundary — every mutating Server Action independently re-checks the
caller's role and resource ownership against the database before touching data.

## Technology Stack

| Layer | Choice |
|---|---|
| Framework | Next.js 16 (App Router, TypeScript, Server Actions, Turbopack) |
| UI | Tailwind CSS v4 + hand-authored Radix UI primitives ("Vault Streetwear" design system) |
| Animation | Framer Motion (respects `prefers-reduced-motion` globally via `MotionConfig`) |
| Database | PostgreSQL via Prisma ORM 6 |
| Auth | Auth.js (NextAuth v5) — credentials (bcrypt) + optional Google OAuth, JWT sessions, role-based access |
| Client data fetching | React Server Components for reads; TanStack Query for a small set of client-driven reads |
| File uploads | `UploadAdapter` interface — Vercel Blob when `BLOB_READ_WRITE_TOKEN` is set, local disk otherwise (dev only) |
| Rate limiting | Upstash Redis + `@upstash/ratelimit`, per-IP, no-op until Upstash env vars are set |
| Validation | Zod (auth forms) + explicit server-side checks in every Server Action |
| Testing | Vitest + Testing Library (jsdom) |
| CI | GitHub Actions — typecheck, lint, test, build on every push/PR to `main` |

## Project Structure

```
src/
  actions/            Server actions — the app's only write path
    admin-*.ts         Admin CRUD (users, products, categories, listings, orders, drops, trends, blog)
    auth.ts            Signup
    authentication.ts  Authentication-queue review (approve/reject a listing)
    bids.ts            Auction bidding
    checkout.ts        Order placement
    create-listing.ts  Seller listing creation
    listings.ts        Seller listing edit/archive
    membership.ts       Pro membership upgrade
    watchlist.ts        Watchlist toggle
  app/                 App Router routes
    (auth)/             Login, signup, forgot password
    browse/[category]/  Filterable/sortable/paginated catalog
    product/[slug]/     PDP — gallery, listings, trend gauge, certificate, related items
    checkout/           3-step wizard with animated confirmation
    sell/                6-step seller listing flow
    dashboard/
      buyer/             Orders, Digital Vault, watchlist, active bids
      seller/             Listings CRUD, sales, payouts, tier progress, Pro upsell
      admin/               Auth queue, full CRUD, trend weight config, editorial CRUD
    trend/                Public live Hype Feed
    blog/                 Public editorial pages
    api/                  Route handlers (auth, search, pricing-suggestion, uploads)
  components/           UI primitives, landing sections, dashboard/admin/sell/checkout components
  lib/
    business/            Trend score formula, pricing suggestion, commission tiers, certificate hashing
    queries/              Server-side Prisma query helpers, grouped by dashboard/area
    validations/           Zod schemas
    auth.ts, auth.config.ts  Auth.js setup (config split for Edge-safe proxy bundling)
    auth-guards.ts        Shared server-action authorization helpers
    db.ts                 Prisma client singleton
    rate-limit.ts          Upstash-backed per-IP rate limiting
    uploads.ts             Upload storage adapter (Vercel Blob / local disk)
    file-signature.ts       Magic-byte image type sniffing
  proxy.ts              Optimistic role-gate redirect (Next.js 16 Proxy convention)
prisma/
  schema.prisma          Full data model (17 models, 10 enums)
  seed.ts                 Deterministic-ish demo data generator
  migrations/              SQL migration history
scripts/                 One-off/maintenance data scripts (category backfills, orphan-listing fixes)
```

## Getting Started

### Prerequisites

- Node.js 20 or later (CI runs on Node 22)
- A reachable PostgreSQL instance (local or hosted)

### 1. Install dependencies

```bash
npm install
```

### 2. Configure environment variables

```bash
cp .env.example .env
```

See [Environment Variables](#environment-variables) below for what each value does.

### 3. Set up the database

```bash
npx prisma migrate dev   # creates the schema
npm run db:seed          # seeds ~60 products, 190+ listings, users, orders, trend history, a blog, and a drop
```

### 4. Run the dev server

```bash
npm run dev
```

Visit [http://localhost:3000](http://localhost:3000).

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `AUTH_SECRET` | Yes | Random secret for Auth.js — generate with `npx auth secret` |
| `NEXTAUTH_URL` | Yes | App URL, e.g. `http://localhost:3000` |
| `AUTH_GOOGLE_ID` / `AUTH_GOOGLE_SECRET` | No | Leave blank to disable Google sign-in |
| `BLOB_READ_WRITE_TOKEN` | No | Leave blank to fall back to local-disk uploads in dev; set automatically when a Blob store is connected on Vercel |
| `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN` | No | Leave blank to disable rate limiting in dev; set via the Vercel Storage tab or Upstash console to throttle login/signup/search/bid/upload endpoints per IP |

All variables are documented in [`.env.example`](.env.example). The app is designed to run with only
`DATABASE_URL`, `AUTH_SECRET`, and `NEXTAUTH_URL` set — every optional integration degrades
gracefully (uploads fall back to local disk, rate limiting no-ops, Google sign-in is hidden).

## Database

PostgreSQL via Prisma. The schema (`prisma/schema.prisma`) models the marketplace end to end:

| Domain | Models |
|---|---|
| Identity | `User`, `Account`, `Session`, `Address` |
| Catalog | `Category`, `Product` |
| Marketplace | `Listing`, `AuthenticationRecord`, `WatchlistItem`, `Bid`, `Order`, `Review` |
| Trend intelligence | `TrendScore`, `TrendWeightConfig` |
| Editorial | `BlogPost`, `Drop`, `DropProduct` |

Enums (`Role`, `SellerTier`, `ListingType`, `ListingStatus`, `AuthDecision`, `OrderStatus`,
`BidStatus`, `DisputeStatus`, `CategoryPhase`, `Condition`) drive nearly every state machine in the
app — listing lifecycle, order status, dispute resolution, and authentication decisions are all
enum-typed rather than free-text strings.

Prisma configuration lives in `prisma.config.ts` (the modern replacement for the deprecated
`package.json#prisma` field), which also wires up the seed command.

## Available Scripts

| Script | Description |
|---|---|
| `npm run dev` | Start the Next.js dev server (Turbopack) |
| `npm run build` | Production build |
| `npm run start` | Serve a production build |
| `npm run lint` | Run ESLint |
| `npm test` | Run the Vitest suite once |
| `npm run db:seed` | Seed the database via `prisma/seed.ts` |
| `npm run db:migrate` | Run `prisma migrate dev` |
| `npm run db:studio` | Open Prisma Studio |

`npx tsc --noEmit` runs a standalone typecheck (also enforced in CI, separately from `next build`'s
own type-checking pass).

## Authentication Flow

- **Sign up** (`registerUser` in `src/actions/auth.ts`): Zod-validated (`src/lib/validations/auth.ts`),
  rate-limited, bcrypt-hashed password, restricted to self-service `BUYER`/`SELLER` roles only —
  `ADMIN`/`AUTHENTICATOR` accounts can't be created through the public form.
- **Sign in**: Auth.js Credentials provider (rate-limited, bcrypt compare) or optional Google OAuth,
  backed by the Prisma adapter. Sessions are JWT-based, carrying `role`, `sellerTier`, and
  `isProMember` so most authorization checks don't need a database round trip.
- **Edge-safe config split**: `src/lib/auth.config.ts` holds only the JWT/session callbacks (no
  Prisma or bcrypt), so `src/proxy.ts` — which runs on the Edge runtime — can build a lightweight
  `NextAuth` instance without pulling in Node-only dependencies. The full config
  (`src/lib/auth.ts`, adapter + providers) is only ever imported from Server Actions/Components.
- **Authorization boundary**: the proxy's role check is an optimistic UX redirect. The actual
  security boundary is in every Server Action, most of which call a shared `assertAdmin()`
  (`src/lib/auth-guards.ts`) or an inline ownership check against the requested resource's
  `sellerId`/`buyerId` before mutating anything.

## API Routes

Almost all mutations go through Server Actions, not route handlers. The few route handlers that
exist serve client-driven reads or file uploads:

| Route | Method | Purpose |
|---|---|---|
| `/api/auth/[...nextauth]` | — | Auth.js session/callback handling |
| `/api/search` | `GET` | Live product search (name/brand/subcategory, optionally scoped to a category) |
| `/api/pricing-suggestion` | `GET` | Suggested price range for a product, from recent sold comps + trend score |
| `/api/uploads` | `POST` | Authenticated image upload — magic-byte MIME sniffing, size/type limits, rate-limited |

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
- **Checkout concurrency:** order creation runs in a single DB transaction, and each listing flips
  `ACTIVE` → `SOLD` via a conditional update — so two buyers checking out the same listing at once
  can't both win it.
- **Bidding concurrency:** the top-bid check and the write happen inside one Serializable-isolation
  transaction, so two bids racing to beat the same top bid can't both succeed.

## Testing

```bash
npm test
```

Covers business logic (trend score, pricing suggestion, seller tiers), auth validation schemas, and
the checkout/bidding server actions (commission math, insurance rules, concurrency-conflict handling).
CI runs the full suite — typecheck, lint, test, build — on every push and pull request to `main`
(see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

## Security

- **Rate limiting:** per-IP throttling (via Upstash) on login, signup, bidding, search, pricing
  suggestions, and uploads.
- **Upload validation:** files are sniffed by magic bytes, not just the client-supplied MIME type,
  before being written to storage; the on-disk filename is a random UUID with a whitelisted
  extension, never derived from the client-supplied filename.
- **Authorization:** every mutating server action re-checks role/ownership against the database —
  the role-gated proxy (`src/proxy.ts`) on `/dashboard/*`, `/sell`, and `/checkout` is a UX redirect,
  not the security boundary. Update actions build explicit, whitelisted Prisma `data` payloads
  rather than forwarding caller-supplied objects as-is.
- **Response headers:** `X-Content-Type-Options: nosniff`, a restrictive `Permissions-Policy`, and
  `Referrer-Policy: strict-origin-when-cross-origin` are set on every route (`next.config.ts`); the
  image pipeline enforces `sandbox` + `script-src 'none'` on served SVGs.
- **Least-privilege queries:** list/table views that render in Client Components explicitly `select`
  only the fields the UI needs, rather than serializing full database rows (e.g. never exposing
  `passwordHash`) into the RSC payload.

## Deployment

The project is configured for [Vercel](https://vercel.com) (see `.vercel/`), which is the natural
target given the framework and the optional Vercel Blob/Upstash integrations, but nothing in the
app is Vercel-specific beyond those two optional integrations:

1. Provision a PostgreSQL database and set `DATABASE_URL`.
2. Set `AUTH_SECRET` and `NEXTAUTH_URL` (your production origin).
3. Optionally connect Vercel Blob (`BLOB_READ_WRITE_TOKEN`) and Upstash Redis
   (`UPSTASH_REDIS_REST_URL`/`UPSTASH_REDIS_REST_TOKEN`) for durable uploads and rate limiting —
   without them the app still runs, just with local-disk uploads and no throttling.
4. Run `npx prisma migrate deploy` against the production database before or during your build step.
5. `npm run build && npm start`, or deploy via Vercel's Next.js integration.

## Design Decisions & Philosophy

- **Server Actions as the only write path.** There's no parallel REST/GraphQL API to keep in sync
  with the UI — every mutation is a typed function co-located with its authorization and validation
  logic, callable directly from a form or `useTransition`.
- **Server-side re-validation over client trust.** Every price, commission rate, and quantity used in
  a transaction is re-read from the database inside the Server Action, never trusted from client
  input, even when the client-side form already validated it.
- **Config/runtime split for Auth.js.** Splitting `auth.config.ts` (Edge-safe) from `auth.ts` (full,
  Node-only) exists specifically so the proxy's bundle stays small — a deliberate tradeoff to avoid
  pulling Prisma Client and bcrypt into the Edge runtime.
- **Graceful degradation for optional infrastructure.** Rate limiting and durable uploads are treated
  as enhancements, not requirements — the app is fully functional in local dev with only a database
  and an auth secret configured.

## Known Limitations

- This is a demo build: payments, email sending, and certificate hashes are simulated — no real
  transactions, payment processor calls, or blockchain writes occur.
- Product photography is generated as deterministic gradient placeholders
  (`src/lib/mock-image.ts`) rather than real or scraped brand assets, except for a handful of
  blog/drop cover images in `public/images/`.
- There's no automated end-to-end (browser) test suite — Vitest covers business logic and server
  actions, but UI flows are verified manually.
- Local-disk uploads (`src/lib/uploads.ts`'s `LocalUploadAdapter`) don't survive a redeploy or
  serverless cold start; it's a dev-only fallback, not suitable for production without Vercel Blob
  configured.

## Future Improvements

- Automated end-to-end tests for the checkout and bidding flows (e.g. Playwright).
- Real payment integration (currently orders settle instantly into an "escrow" state).
- Transactional email (order confirmations, outbid notifications, authentication decisions).
- Image optimization pass on the committed `public/images/` assets.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Environment variable not found: DATABASE_URL` | `.env` missing or not loaded | `cp .env.example .env` and fill in a real connection string |
| Google sign-in button doesn't appear | `AUTH_GOOGLE_ID`/`AUTH_GOOGLE_SECRET` unset | Expected — Google OAuth is optional and hidden when unconfigured |
| Uploads disappear after a redeploy | No Blob store connected | Connect Vercel Blob, or accept that local-disk uploads are dev-only |
| Rate limiting seems to do nothing locally | Upstash env vars unset | Expected in dev — rate limiting is a no-op without `UPSTASH_REDIS_REST_URL`/`TOKEN` |
| `prisma migrate dev` can't reach the database | `DATABASE_URL` points to an unreachable host | Confirm Postgres is running and the connection string/credentials are correct |
| `npm run db:seed` run directly doesn't pick up `.env.local` | `tsx prisma/seed.ts` doesn't get Next.js's automatic env loading | Export `DATABASE_URL` in your shell first, or invoke through a tool that loads `.env.local` |

## FAQ

**Why Server Actions instead of a REST API?**
The whole app is a single Next.js deployment with no external API consumers, so a separate API
surface would just be indirection. Server Actions give typed, co-located mutation + authorization
logic without hand-rolling request parsing.

**Is this connected to real payment/shipping providers?**
No — see [Known Limitations](#known-limitations). Checkout, escrow, and delivery tracking are
simulated for demo purposes.

**Can I run it without Vercel Blob or Upstash?**
Yes. Both are optional; the app falls back to local-disk uploads and no-op rate limiting
respectively. See [Environment Variables](#environment-variables).

## Contributing

This started as a personal/portfolio project rather than a community one, so there's no formal
contribution process yet. If you'd like to contribute:

1. Fork the repository and create a feature branch.
2. Run `npm run lint`, `npx tsc --noEmit`, and `npm test` before opening a PR — CI runs all three
   plus a production build.
3. Keep Server Actions consistent with the existing pattern: validate input, re-check
   authorization/ownership against the database, and build explicit (whitelisted) Prisma `data`
   payloads rather than forwarding caller-supplied objects as-is.
4. Open a pull request describing what changed and why.

## License

No license file is currently included in this repository, so default copyright law applies — all
rights are reserved by the author. If you're the maintainer and intend to open-source this project,
add a `LICENSE` file (e.g. MIT) and update this section accordingly.

## Acknowledgements

Built with [Next.js](https://nextjs.org), [Prisma](https://www.prisma.io),
[Auth.js](https://authjs.dev), [Radix UI](https://www.radix-ui.com),
[shadcn/ui](https://ui.shadcn.com) conventions, [Tailwind CSS](https://tailwindcss.com), and
[Framer Motion](https://www.framer.com/motion/).
