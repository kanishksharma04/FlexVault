import { describe, it, expect, vi, beforeEach, type Mock } from "vitest";
import { auth } from "@/lib/auth";
import { rateLimitAction } from "@/lib/rate-limit";
import { placeBid } from "../bids";

// `auth` is typed for both its RSC and middleware-wrapper overloads; the mock
// only needs to stand in for the no-args `() => Promise<Session | null>` form
// actions actually call.
const mockAuth = auth as unknown as Mock;

const { mockDb } = vi.hoisted(() => ({
  mockDb: {
    listing: { findUnique: vi.fn() },
    bid: { updateMany: vi.fn(), create: vi.fn() },
    $transaction: vi.fn(),
  },
}));

vi.mock("@/lib/db", () => ({ db: mockDb }));
vi.mock("@/lib/auth", () => ({ auth: vi.fn() }));
vi.mock("next/cache", () => ({ revalidatePath: vi.fn() }));
vi.mock("@/lib/rate-limit", () => ({ rateLimitAction: vi.fn() }));

const session = {
  user: { id: "bidder1", role: "BUYER" as const, sellerTier: "BRONZE", isProMember: false, name: "", email: "" },
};

function formData(entries: Record<string, string>) {
  const fd = new FormData();
  for (const [key, value] of Object.entries(entries)) fd.set(key, value);
  return fd;
}

function mockActiveAuction(overrides: { price: number; topBid?: number; auctionEndsAt?: Date | null }) {
  mockDb.listing.findUnique.mockResolvedValue({
    listingType: "AUCTION",
    status: "ACTIVE",
    price: overrides.price,
    auctionEndsAt: overrides.auctionEndsAt ?? null,
    bids: overrides.topBid !== undefined ? [{ amount: overrides.topBid }] : [],
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(rateLimitAction).mockResolvedValue(null);
  mockDb.$transaction.mockImplementation(async (arg: unknown) => {
    if (typeof arg === "function") return (arg as (tx: typeof mockDb) => unknown)(mockDb);
    return Promise.all(arg as Promise<unknown>[]);
  });
});

describe("placeBid", () => {
  it("requires login", async () => {
    mockAuth.mockResolvedValue(null);
    const result = await placeBid({}, formData({ listingId: "l1", amount: "100" }));
    expect(result.error).toMatch(/log in/i);
  });

  it("is rate limited per IP before touching the database", async () => {
    mockAuth.mockResolvedValue(session);
    vi.mocked(rateLimitAction).mockResolvedValue("Too many attempts. Please slow down and try again shortly.");

    const result = await placeBid({}, formData({ listingId: "l1", amount: "100" }));

    expect(result.error).toMatch(/too many attempts/i);
    expect(mockDb.listing.findUnique).not.toHaveBeenCalled();
  });

  it("rejects a non-positive or non-numeric amount", async () => {
    mockAuth.mockResolvedValue(session);
    const result = await placeBid({}, formData({ listingId: "l1", amount: "0" }));
    expect(result.error).toMatch(/valid bid amount/i);
  });

  it("rejects bidding on a listing that isn't an active auction", async () => {
    mockAuth.mockResolvedValue(session);
    mockDb.listing.findUnique.mockResolvedValue({
      listingType: "FIXED",
      status: "ACTIVE",
      price: 1000,
      auctionEndsAt: null,
      bids: [],
    });

    const result = await placeBid({}, formData({ listingId: "l1", amount: "900" }));
    expect(result.error).toMatch(/no longer active/i);
  });

  it("rejects bidding after the auction has ended", async () => {
    mockAuth.mockResolvedValue(session);
    mockActiveAuction({ price: 1000, auctionEndsAt: new Date(Date.now() - 1000) });

    const result = await placeBid({}, formData({ listingId: "l1", amount: "900" }));
    expect(result.error).toMatch(/auction has ended/i);
  });

  it("rejects a bid at or below the current top bid", async () => {
    mockAuth.mockResolvedValue(session);
    mockActiveAuction({ price: 1000, topBid: 1000 });

    const result = await placeBid({}, formData({ listingId: "l1", amount: "1000" }));
    expect(result.error).toMatch(/must be higher/i);
  });

  it("falls back to 80% of listing price as the floor when there are no bids yet", async () => {
    mockAuth.mockResolvedValue(session);
    mockActiveAuction({ price: 1000 }); // no bids -> floor is 800

    const result = await placeBid({}, formData({ listingId: "l1", amount: "800" }));
    expect(result.error).toBe("Bid must be higher than ₹800.");
  });

  it("places a winning bid and outbids the previous top bid", async () => {
    mockAuth.mockResolvedValue(session);
    mockActiveAuction({ price: 1000, topBid: 1000 });
    mockDb.bid.updateMany.mockResolvedValue({ count: 1 });
    mockDb.bid.create.mockResolvedValue({ id: "bid1" });

    const result = await placeBid({}, formData({ listingId: "l1", amount: "1100", productSlug: "some-sneaker" }));

    expect(result.success).toBe(true);
    expect(mockDb.bid.updateMany).toHaveBeenCalledWith({
      where: { listingId: "l1", status: "ACTIVE" },
      data: { status: "OUTBID" },
    });
    expect(mockDb.bid.create).toHaveBeenCalledWith({
      data: { listingId: "l1", bidderId: "bidder1", amount: 1100, status: "ACTIVE" },
    });
  });
});
