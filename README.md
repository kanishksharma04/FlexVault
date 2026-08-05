# Flex Vault

**Drip. Verified. Delivered.**

Flex Vault is India's authenticated marketplace for hype culture — sneakers, streetwear, diecast
collectibles, watches, and accessories. It's a full-stack web app where every item is checked by a
human before it's allowed to sell, sellers earn better rates the more they sell, and prices are
guided by how "trending" an item currently is.

[![CI](https://github.com/kanishksharma04/FlexVault/actions/workflows/ci.yml/badge.svg)](https://github.com/kanishksharma04/FlexVault/actions/workflows/ci.yml)

---

## Table of Contents

- [Overview](#overview)
- [Core Features](#core-features)
- [How It's Built (Architecture)](#how-its-built-architecture)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Environment Variables](#environment-variables)
- [Database](#database)
- [Available Scripts](#available-scripts)
- [Authentication Flow](#authentication-flow)
- [API Routes](#api-routes)
- [Business Logic](#business-logic)
- [SEO](#seo)
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

Think of platforms like StockX, Grailed, or Chrono24 — marketplaces where every item is inspected
and verified before it's sold, so buyers can trust what they're getting. Flex Vault simulates that
same model, but for the Indian market: every listing goes through a human "authentication queue"
before it goes live, sellers move up commission tiers the more they sell, and prices are guided by
a live "trend score" that tracks how much buzz an item is currently getting.

It's built as a single Next.js application — there's no separate backend server or API to keep in
sync. All the logic for reading and writing data lives in the same codebase as the pages themselves.
Four types of users share this one app: **buyers**, **sellers**, **admins**, and
**authenticators** (the people who inspect and approve listings). Each role sees a different
dashboard, and the server checks every request to make sure a user is only allowed to see or change
what their role permits.

## Core Features

| Area | What it does |
|---|---|
| **Browse & search** | Filter and sort products by category, brand, size, condition, price, or trend score |
| **Product page** | Photo gallery, every active listing for that product, a live "trend" gauge, a preview of the authentication certificate, and similar items |
| **Cart & checkout** | Add multiple listings to a cart (saved in your browser), then check out in a 3-step flow (shipping → payment → review). Prices, commission, and insurance are all recalculated on the server so nothing can be tampered with from the browser |
| **Selling** | A 6-step guided flow for listing an item, with an automatic price suggestion (based on recent sales and current trend) and photo upload with server-side checks that the files are really images |
| **Bidding** | Live auctions. The database guarantees two people can't both "win" the same bid at the same instant |
| **Authentication queue** | Every new listing starts as "pending" until an admin or authenticator reviews it — approving it (which issues a certificate + QR code) or rejecting it with a reason |
| **Seller tiers & Pro membership** | Sellers move from Bronze to Platinum as they sell more, unlocking lower fees and faster payouts. A paid "Pro" membership adds an extra discount on top |
| **Trend intelligence** | A configurable formula scores how "hot" each product is right now, shown across the site and in a public "Hype Feed" |
| **Dashboards** | A different dashboard for each role — buyers see orders/wishlist/bids, sellers see their listings/sales/payouts, admins see everything plus the authentication queue |
| **Editorial** | A simple blog that admins can write and publish articles to |
| **Light & dark mode** | A theme toggle in the header (and mobile menu) switches the whole site between a light and a dark color scheme. Your choice is remembered on your next visit |

## How It's Built (Architecture)

```
┌─────────────────────────────────────────────────────────────────┐
│                      Next.js App Router                          │
│                                                                    │
│  Server Components  ──►  Prisma (database toolkit)  ──►  PostgreSQL │
│         │                                                          │
│         ├──  Server Actions  ──►  Prisma  ──►  PostgreSQL          │
│         │        (every write: checkout, bids, admin edits, etc.)  │
│         │                                                          │
│         └──  API routes (/api/*)  ──►  Prisma / Upstash            │
│                  (search, price suggestions, file uploads)          │
│                                                                     │
│  src/proxy.ts  ──►  quick "are you allowed here?" redirect (UX only)│
│  Auth.js (login sessions)  ──►  Prisma                             │
└─────────────────────────────────────────────────────────────────┘
```

A quick explanation of the unusual terms above:

- **Server Component** — a React component that runs on the server and never sends its code to the
  browser. It's how most pages fetch and display data.
- **Server Action** — a regular-looking function that actually runs on the server, not in the
  browser. Forms call these directly to save data, instead of the app talking to a separate API.

There's no separate system for saving data on the client side (no Redux, no calls to a REST API for
writes). Forms call Server Actions directly. The only place the app fetches data from the client
side is for things that need to feel instant while typing — live search, price suggestions while
listing an item, and a product picker.

**Why the security check happens twice:** the app blocks access to `/dashboard/*`, `/sell`, and
`/checkout` for the wrong role right at the door (in `src/proxy.ts`), which makes the UI feel
correct immediately. But that check alone isn't trusted for security — every Server Action that
changes data independently re-checks, against the database, that the person making the request is
actually allowed to.

## Technology Stack

| Layer | Choice | In plain terms |
|---|---|---|
| Framework | Next.js 16 (App Router, TypeScript, Turbopack) | The framework that runs both the pages and the server logic |
| UI | Tailwind CSS v4 + hand-built Radix UI components ("Vault Streetwear" design system) | Styling utility classes + accessible, unstyled building blocks (dropdowns, dialogs, etc.) that we skin ourselves |
| Animation | Framer Motion | Powers the site's motion — automatically turns off for people who've asked their OS to reduce motion |
| Database | PostgreSQL via Prisma ORM | Prisma is a toolkit that lets us write database queries as typed JavaScript instead of raw SQL |
| Login/accounts | Auth.js (NextAuth v5) | Email+password login (with Google sign-in as an option), sessions stored as signed tokens |
| Client-side data fetching | TanStack Query, used sparingly | For the handful of things that need live updates without a full page reload |
| File uploads | A small "storage adapter" — uses Vercel Blob if configured, otherwise saves to local disk in development | So uploads work out of the box locally, without needing a cloud account |
| Rate limiting | Upstash Redis | Slows down repeated requests (login attempts, searches, etc.) from the same IP address. Does nothing if not configured |
| Validation | Zod, plus manual checks in every Server Action | Zod checks that form data is shaped correctly before it's used |
| Testing | Vitest + Testing Library | Runs the automated test suite |
| CI | GitHub Actions | Automatically type-checks, lints, tests, and builds the app on every push/PR to `main` |

## Project Structure

```
src/
  actions/            Server Actions — every write to the database goes through here
    admin-*.ts         Admin tools (managing users, products, categories, listings, orders, drops, trends, blog)
    auth.ts            Sign-up
    authentication.ts  Reviewing a listing in the authentication queue (approve/reject)
    bids.ts            Placing auction bids
    checkout.ts        Placing an order
    create-listing.ts  Creating a new listing as a seller
    listings.ts        Editing or archiving a seller's existing listing
    membership.ts       Upgrading to Pro membership
    watchlist.ts        Adding/removing an item from your watchlist
  app/                 Every page and route, following Next.js's folder-based routing
    (auth)/             Login, sign-up, forgot password
    browse/[category]/  The filterable, sortable product catalog
    product/[slug]/     A single product's page — photos, listings, trend gauge, certificate, related items
    checkout/           The cart checkout flow
    sell/                The step-by-step "list an item" flow
    dashboard/
      buyer/             Orders, saved items ("Digital Vault"), watchlist, active bids
      seller/             Listings, sales, payouts, tier progress, Pro upsell
      admin/               Authentication queue, full admin tools, trend settings, blog editing
    trend/                The public "Hype Feed" of trending items
    blog/                 Public blog pages
    api/                  A few routes for things that need a plain HTTP endpoint (search, uploads, etc.)
  components/           Every reusable UI piece — buttons, cards, dashboard widgets, and so on
  lib/
    business/            The actual formulas — trend score, price suggestions, commission tiers, certificate hashing
    queries/              Reusable database queries, grouped by which dashboard/page uses them
    validations/           Zod schemas (the rules that check form input is valid)
    auth.ts, auth.config.ts  Login setup (split into two files — explained in Authentication Flow below)
    auth-guards.ts        Shared "is this user allowed to do this?" helper functions
    db.ts                 The single shared database connection
    rate-limit.ts          The Upstash-based rate limiter
    uploads.ts             Picks where uploaded files get saved (cloud storage or local disk)
    file-signature.ts       Checks that an uploaded file really is an image, not just labeled as one
    theme.ts                Small helper that flips the site between light and dark mode
  hooks/
    use-theme.ts           Reads the current light/dark theme so components can react to it
  proxy.ts              The "are you allowed on this page?" redirect mentioned above
prisma/
  schema.prisma          The full database design (17 tables, 10 enums/categories)
  seed.ts                 Fills the database with realistic demo data
  migrations/              The history of database schema changes
scripts/                 One-off maintenance scripts (fixing data, backfills, etc.)
```

## Getting Started

### What you need first

- Node.js 20 or newer (the CI pipeline uses Node 22)
- A PostgreSQL database you can connect to (local or hosted — a free one from
  [Neon](https://neon.tech) or [Supabase](https://supabase.com) works fine)

### 1. Install dependencies

```bash
npm install
```

### 2. Set up your environment variables

```bash
cp .env.example .env
```

Then open `.env` and fill in the values. See [Environment Variables](#environment-variables) below
for what each one is for.

### 3. Set up the database

```bash
npx prisma migrate dev   # creates all the tables
npm run db:seed          # fills them with demo data — ~60 products, 190+ listings, users, orders, and more
```

### 4. Start the app

```bash
npm run dev
```

Then open [http://localhost:3000](http://localhost:3000) in your browser.

## Environment Variables

| Variable | Do you need it? | What it's for |
|---|---|---|
| `DATABASE_URL` | Yes | The connection string for your PostgreSQL database |
| `AUTH_SECRET` | Yes | A random secret used to sign login sessions — generate one with `npx auth secret` |
| `NEXTAUTH_URL` | Yes | The URL your app runs at, e.g. `http://localhost:3000` |
| `AUTH_GOOGLE_ID` / `AUTH_GOOGLE_SECRET` | No | Leave blank and the "Sign in with Google" button just won't show up |
| `BLOB_READ_WRITE_TOKEN` | No | Leave blank and file uploads save to your local disk instead. Vercel sets this automatically if you connect a Blob store |
| `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN` | No | Leave blank and rate limiting is simply skipped. Set these (via Vercel's Storage tab or the Upstash console) to throttle repeated login/search/bid/upload requests |

Every variable is documented in [`.env.example`](.env.example). You only strictly need
`DATABASE_URL`, `AUTH_SECRET`, and `NEXTAUTH_URL` to run the app — every optional feature above
quietly turns itself off if it's not configured, instead of crashing.

## Database

The app uses PostgreSQL, accessed through Prisma (a toolkit that lets us describe the database in
one file, `prisma/schema.prisma`, and get type-safe JavaScript queries automatically).

| Group | Tables |
|---|---|
| Accounts & people | `User`, `Account`, `Session`, `Address` |
| Catalog | `Category`, `Product` |
| Marketplace | `Listing`, `AuthenticationRecord`, `WatchlistItem`, `Bid`, `Order`, `Review` |
| Trend engine | `TrendScore`, `TrendWeightConfig` |
| Editorial | `BlogPost`, `Drop`, `DropProduct` |

The app also defines a set of fixed categories (called "enums") for things like a listing's status,
an order's status, or a dispute's status — instead of using free-form text, each of these fields can
only ever be one of a known set of values. This makes the state of any listing or order predictable
and easy to check.

The database configuration itself lives in `prisma.config.ts` — the current recommended way to
configure Prisma, replacing the older `package.json`-based setup.

## Available Scripts

| Script | What it does |
|---|---|
| `npm run dev` | Starts the app locally (with Turbopack, for fast rebuilds) |
| `npm run build` | Builds the app for production |
| `npm run start` | Runs a production build you've already built |
| `npm run lint` | Checks the code style with ESLint |
| `npm test` | Runs the automated test suite once |
| `npm run db:seed` | Fills the database with demo data |
| `npm run db:migrate` | Applies database schema changes |
| `npm run db:studio` | Opens Prisma Studio — a visual browser for your database |

There's also `npx tsc --noEmit`, which checks that all the TypeScript types are correct without
building anything. CI runs this separately from the build step.

## Authentication Flow

- **Signing up** (`registerUser` in `src/actions/auth.ts`): the form is validated with Zod, rate
  limited, and the password is hashed with bcrypt before it's stored (so the real password is never
  saved anywhere). The public sign-up form can only create `BUYER` or `SELLER` accounts — you can't
  create an admin or authenticator account this way.
- **Signing in**: either email + password, or Google, if it's configured. Sessions are stored as
  signed JWTs (a token that proves who you are without the server needing to look you up on every
  request) and carry your role, seller tier, and Pro membership status, so most permission checks
  don't need a database lookup at all.
- **Why the login config is split in two**: `src/lib/auth.config.ts` holds only the lightweight
  parts of the login setup, so `src/proxy.ts` — which runs on Next.js's fast "Edge" runtime — can
  check who's logged in without pulling in the database library or the password-hashing library
  (neither of which work in that lightweight runtime). The full setup, including the database
  connection, lives in `src/lib/auth.ts` and is only ever used from the server side.
- **Where the real security check happens**: the redirect in `src/proxy.ts` is just for a smooth
  user experience. The actual permission check happens inside every Server Action, most of which
  call a shared `assertAdmin()` helper (`src/lib/auth-guards.ts`) or directly check that the
  logged-in user owns the thing they're trying to change.

## API Routes

Almost everything that changes data goes through a Server Action, not a traditional API route. The
few plain HTTP routes that do exist are for things a browser needs to call directly, like live
search or file uploads:

| Route | Method | What it's for |
|---|---|---|
| `/api/auth/[...nextauth]` | — | Handles login sessions (managed by Auth.js) |
| `/api/search` | `GET` | Live product search by name, brand, or subcategory |
| `/api/pricing-suggestion` | `GET` | Suggests a price range for a product, based on recent sales and its current trend score |
| `/api/uploads` | `POST` | Uploads an image — checks the file is really an image, checks its size, and requires the uploader to be logged in |

## Business Logic

- **Trend score** — a formula: `score = w1·mentionVelocity + w2·sentimentScore + w3·engagementGrowth`.
  In plain terms: how fast people are talking about it, how positive that talk is, and how fast
  interest is growing. Admins can adjust the weights (`w1`, `w2`, `w3`) at `/dashboard/admin/trends`,
  or override a score manually.
- **Seller tiers** — sellers move from Bronze up to Platinum as they sell more. Higher tiers pay a
  lower commission (10% down to 8%) and get paid out faster. A paid Flex Vault Pro membership stacks
  an extra discount on top of whatever tier a seller is at.
- **Price suggestions** — a blend of what similar items recently sold for, and the item's current
  trend score, shown live while someone is listing an item for sale.
- **Authentication workflow** — every new listing starts in a `PENDING_AUTH` state. An admin or
  authenticator reviews the inspection photos and either approves it (which generates a fake
  certificate hash + QR code, since this is a demo) or rejects it with a required reason.
- **Insurance** — optional at checkout, turned on by default for items worth ₹10,000 or more, and
  added into the checkout total.
- **Why two buyers can't both "win" the same item** — placing an order runs inside a single database
  transaction (a set of changes that either all happen or none do), and a listing can only flip from
  `ACTIVE` to `SOLD` once. If two people try to buy the same listing at the same instant, the
  database itself guarantees only one of them succeeds.
- **Why two bids can't both "win" an auction** — checking the current top bid and placing a new one
  happen inside one transaction at the database's strictest isolation level (called "Serializable"),
  which is a technical way of saying: even under a race between two bidders, only one bid can
  actually land as the new top bid.

## SEO

Product pages include structured data — a hidden block of JSON, following the
[schema.org](https://schema.org) format, that tells search engines exactly what's on the page: the
product's name, description, brand, category, and its current price or price range. This is the
same format used by real e-commerce sites so that results can show up as rich search results (with
price and availability visible directly in Google), rather than as a plain blue link.

## Testing

```bash
npm test
```

The test suite covers the business logic described above (trend score, price suggestions, seller
tiers), the sign-up form's validation rules, and the checkout/bidding Server Actions (commission
math, insurance rules, and what happens when two requests conflict). CI runs the full suite —
type-checking, linting, tests, and a production build — on every push and pull request to `main`
(see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

## Security

- **Rate limiting** — repeated requests from the same IP address to login, sign-up, bidding, search,
  price suggestions, or uploads get slowed down (via Upstash), to make brute-force and spam attempts
  harder.
- **Upload safety** — uploaded files are checked by reading their actual bytes (not just trusting the
  file type the browser claims), and saved under a random name rather than the name the uploader
  gave the file. This closes off a few common ways file uploads get abused.
- **Permission checks** — as covered above, every Server Action that changes data re-checks the
  user's role and ownership against the database itself — the role-based redirect on
  `/dashboard/*`, `/sell`, and `/checkout` is only there for a smooth user experience, not as the
  actual security boundary. When an admin edits something, the server builds the exact set of fields
  allowed to change, rather than blindly saving whatever the browser sent.
- **Response headers** — every page sets a few extra HTTP headers that reduce common attack surface:
  `X-Content-Type-Options: nosniff`, a restrictive `Permissions-Policy`, and
  `Referrer-Policy: strict-origin-when-cross-origin` (all set in `next.config.ts`). Uploaded SVG
  images are served with extra restrictions so they can't run embedded scripts.
- **Only sending what's needed** — pages that show tables of data (like admin lists) explicitly
  choose which database fields to send to the browser, instead of sending the whole database record.
  This means things like a user's hashed password never leave the server, even by accident.

## Deployment

This project is set up for [Vercel](https://vercel.com) (see the `.vercel/` folder), which pairs
naturally with Next.js and with the two optional integrations (Vercel Blob and Upstash). Nothing
else about the app is tied to Vercel specifically:

1. Set up a PostgreSQL database and set `DATABASE_URL`.
2. Set `AUTH_SECRET` and `NEXTAUTH_URL` (your live site's URL).
3. Optionally connect Vercel Blob (`BLOB_READ_WRITE_TOKEN`) and Upstash Redis
   (`UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN`) for uploads that survive redeploys and for
   rate limiting — without them, the app still works, just with local-disk uploads and no rate
   limiting.
4. Run `npx prisma migrate deploy` against your production database as part of your build/deploy
   step.
5. Run `npm run build && npm start`, or just deploy through Vercel's Next.js integration.

## Design Decisions & Philosophy

- **Server Actions instead of a separate API.** There's only one codebase to keep in sync, and every
  write to the database is a typed function that lives right next to its own validation and
  permission checks — no separate REST or GraphQL layer to maintain alongside it.
- **Never trust the browser for numbers that matter.** Every price, commission rate, and quantity
  used in an order is re-read from the database inside the Server Action itself. The client-side
  form might already have validated the same number, but the server checks it again anyway, in case
  the request was tampered with.
- **Splitting the login config in two.** As explained above, this keeps the fast "Edge" redirect
  lightweight by not pulling database or password-hashing code into a runtime that can't use them.
- **Optional infrastructure degrades gracefully.** Rate limiting and cloud file storage are treated
  as enhancements, not requirements. The app runs completely locally with nothing more than a
  database and a login secret configured.

## Known Limitations

Because this is a demo/portfolio project, a few things are intentionally simulated rather than real:

- Payments, sending real emails, and certificate hashes are all faked — no real money moves, no
  real emails get sent, and no blockchain is involved.
- Product photos are generated as gradient placeholders (`src/lib/mock-image.ts`) rather than real
  product photography, except for a handful of blog/drop cover images in `public/images/`.
- There's no automated browser testing (like Playwright) yet — the test suite covers the business
  logic and Server Actions, but full user flows are checked manually.
- Uploads saved to local disk (used automatically in development, in `src/lib/uploads.ts`) don't
  survive a redeploy or a serverless cold start — this fallback is meant for local development only,
  not production, unless Vercel Blob is connected.

## Future Improvements

- Automated end-to-end browser tests for the checkout and bidding flows (e.g. with Playwright).
- Real payment processing (orders currently settle instantly into a simulated "escrow" state).
- Real transactional emails (order confirmations, outbid notifications, authentication decisions).
- An image optimization pass on the images already committed to `public/images/`.

## Troubleshooting

| What you're seeing | Likely cause | How to fix it |
|---|---|---|
| `Environment variable not found: DATABASE_URL` | You haven't created a `.env` file yet, or it's not being loaded | Run `cp .env.example .env` and fill in a real connection string |
| The "Sign in with Google" button doesn't show up | `AUTH_GOOGLE_ID` / `AUTH_GOOGLE_SECRET` aren't set | This is expected — Google sign-in is optional and hides itself when not configured |
| Uploaded images disappear after a redeploy | No cloud storage (Vercel Blob) is connected | Connect Vercel Blob, or accept that local-disk uploads are for development only |
| Rate limiting doesn't seem to do anything locally | Upstash environment variables aren't set | This is expected in development — rate limiting quietly does nothing without `UPSTASH_REDIS_REST_URL`/`TOKEN` |
| `prisma migrate dev` can't reach the database | `DATABASE_URL` points somewhere unreachable | Make sure Postgres is actually running and the connection string/credentials are correct |
| `npm run db:seed` doesn't pick up `.env.local` when run directly | `tsx prisma/seed.ts` doesn't automatically load env files the way Next.js does | Export `DATABASE_URL` in your shell first, or run it through a tool that loads `.env.local` for you |

## FAQ

**Why Server Actions instead of a REST API?**
The whole app is one Next.js deployment with no outside apps calling into it, so a separate API
layer would just add extra steps without adding any real benefit. Server Actions give typed,
co-located logic — the validation and permission checks live right next to the code that saves the
data.

**Is this connected to real payments or real shipping?**
No — see [Known Limitations](#known-limitations) above. Checkout, escrow, and delivery tracking are
all simulated for demo purposes.

**Can I run it without Vercel Blob or Upstash?**
Yes, both are entirely optional. The app falls back to saving uploads locally and skips rate
limiting if they're not configured. See [Environment Variables](#environment-variables).

## Contributing

This started as a personal/portfolio project, so there's no formal contribution process yet. If
you'd still like to contribute:

1. Fork the repository and create a new branch for your change.
2. Before opening a pull request, run `npm run lint`, `npx tsc --noEmit`, and `npm test` — CI runs
   all three, plus a production build, on every pull request.
3. Follow the existing pattern in Server Actions: validate the input, re-check the user's
   permission/ownership against the database, and explicitly list which fields are allowed to
   change (rather than saving whatever the browser sent as-is).
4. Open a pull request explaining what changed and why.

## License

There's no license file in this repository yet, so by default all rights are reserved by the
author. If you're the maintainer and want to open-source this project, add a `LICENSE` file (for
example, the MIT license) and update this section.

## Acknowledgements

Built with [Next.js](https://nextjs.org), [Prisma](https://www.prisma.io),
[Auth.js](https://authjs.dev), [Radix UI](https://www.radix-ui.com),
[shadcn/ui](https://ui.shadcn.com) conventions, [Tailwind CSS](https://tailwindcss.com), and
[Framer Motion](https://www.framer.com/motion/).
