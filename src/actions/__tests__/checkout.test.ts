import { describe, it, expect, vi, beforeEach, type Mock } from "vitest";
import { auth } from "@/lib/auth";
import { submitOrder } from "../checkout";

// `auth` is typed for both its RSC and middleware-wrapper overloads; the mock
// only needs to stand in for the no-args `() => Promise<Session | null>` form
// actions actually call.
const mockAuth = auth as unknown as Mock;

const { mockDb } = vi.hoisted(() => ({
  mockDb: {
    listing: {
      findMany: vi.fn(),
      updateMany: vi.fn(),
    },
    address: {
      create: vi.fn(),
    },
    order: {
      create: vi.fn(),
    },
    $transaction: vi.fn(),
  },
}));

vi.mock("@/lib/db", () => ({ db: mockDb }));
vi.mock("@/lib/auth", () => ({ auth: vi.fn() }));
vi.mock("next/cache", () => ({ revalidatePath: vi.fn() }));

const session = {
  user: { id: "buyer1", role: "BUYER" as const, sellerTier: "BRONZE", isProMember: false, name: "", email: "" },
};

const SHIPPING_FIELDS = {
  fullName: "Aditya Sharma",
  line1: "123 MG Road",
  city: "Bengaluru",
  state: "Karnataka",
  pincode: "560001",
  phone: "9876543210",
};

function formData(entries: Record<string, string | string[]>) {
  const fd = new FormData();
  for (const [key, value] of Object.entries(entries)) {
    for (const v of Array.isArray(value) ? value : [value]) fd.append(key, v);
  }
  return fd;
}

function mockListing(overrides: { price: number; sellerTier: string; isProMember: boolean }) {
  mockDb.listing.findMany.mockResolvedValue([
    { id: "l1", price: overrides.price, seller: { sellerTier: overrides.sellerTier, isProMember: overrides.isProMember } },
  ]);
  mockDb.address.create.mockResolvedValue({ id: "addr1" });
  mockDb.order.create.mockImplementation(({ data }: { data: Record<string, unknown> }) =>
    Promise.resolve({ id: "order1", ...data })
  );
  mockDb.listing.updateMany.mockResolvedValue({ count: 1 });
}

beforeEach(() => {
  vi.clearAllMocks();
  mockDb.$transaction.mockImplementation(async (arg: unknown) => {
    if (typeof arg === "function") return (arg as (tx: typeof mockDb) => unknown)(mockDb);
    return Promise.all(arg as Promise<unknown>[]);
  });
});

describe("submitOrder", () => {
  it("requires login", async () => {
    mockAuth.mockResolvedValue(null);
    const result = await submitOrder({}, formData({ listingId: "l1", ...SHIPPING_FIELDS }));
    expect(result.error).toMatch(/logged in/i);
  });

  it("rejects an empty cart", async () => {
    mockAuth.mockResolvedValue(session);
    const result = await submitOrder({}, formData({ ...SHIPPING_FIELDS }));
    expect(result.error).toMatch(/cart is empty/i);
  });

  it("requires all shipping fields", async () => {
    mockAuth.mockResolvedValue(session);
    const result = await submitOrder({}, formData({ listingId: "l1", fullName: "Aditya" }));
    expect(result.error).toMatch(/shipping fields/i);
  });

  it("rejects when a listing is no longer active", async () => {
    mockAuth.mockResolvedValue(session);
    mockDb.listing.findMany.mockResolvedValue([]); // requested 1, got 0 back
    const result = await submitOrder({}, formData({ listingId: "l1", ...SHIPPING_FIELDS }));
    expect(result.error).toMatch(/no longer available/i);
  });

  it("applies the seller's tier commission with no pro discount", async () => {
    mockAuth.mockResolvedValue(session);
    mockListing({ price: 5000, sellerTier: "BRONZE", isProMember: false });

    const result = await submitOrder({}, formData({ listingId: "l1", ...SHIPPING_FIELDS }));

    expect(result.success).toBe(true);
    expect(mockDb.order.create).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ commissionRate: 0.1 }) })
    );
  });

  it("discounts commission for pro members, clamped to a 2% floor", async () => {
    mockAuth.mockResolvedValue(session);
    mockListing({ price: 5000, sellerTier: "PLATINUM", isProMember: true });

    await submitOrder({}, formData({ listingId: "l1", ...SHIPPING_FIELDS }));

    // PLATINUM base commission 0.08 minus a 0.02 pro discount = 0.06, above the 0.02 floor.
    expect(mockDb.order.create).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ commissionRate: 0.06 }) })
    );
  });

  it("charges insurance above the price threshold when opted in", async () => {
    mockAuth.mockResolvedValue(session);
    mockListing({ price: 20000, sellerTier: "BRONZE", isProMember: false });

    await submitOrder({}, formData({ listingId: "l1", insuranceListingId: "l1", ...SHIPPING_FIELDS }));

    expect(mockDb.order.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ insuranceOpted: true, insuranceFee: Math.round(20000 * 0.015) }),
      })
    );
  });

  it("skips insurance below the price threshold even if opted in", async () => {
    mockAuth.mockResolvedValue(session);
    mockListing({ price: 5000, sellerTier: "BRONZE", isProMember: false });

    await submitOrder({}, formData({ listingId: "l1", insuranceListingId: "l1", ...SHIPPING_FIELDS }));

    expect(mockDb.order.create).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ insuranceOpted: false, insuranceFee: 0 }) })
    );
  });

  it("returns a friendly error and skips order creation when a listing is claimed mid-checkout", async () => {
    mockAuth.mockResolvedValue(session);
    mockListing({ price: 5000, sellerTier: "BRONZE", isProMember: false });
    mockDb.listing.updateMany.mockResolvedValue({ count: 0 }); // someone else bought it first

    const result = await submitOrder({}, formData({ listingId: "l1", ...SHIPPING_FIELDS }));

    expect(result.error).toMatch(/purchased by someone else/i);
    expect(mockDb.order.create).not.toHaveBeenCalled();
  });
});
