import { PrismaClient, ListingType, ListingStatus, AuthDecision, Condition, OrderStatus, BidStatus, DisputeStatus, CategoryPhase, Role, SellerTier } from "@prisma/client";
import bcrypt from "bcryptjs";
import { mockProductImages } from "../src/lib/mock-image";
import { PRODUCT_IMAGE_OVERRIDES } from "../src/lib/product-images";
import { calcTrendScore, trendReasonSummary } from "../src/lib/business/trend";
import { generateCertificateHash } from "../src/lib/business/certificate";
import { SELLER_TIER_COMMISSION, INSURANCE_THRESHOLD_INR } from "../src/lib/business/constants";

const db = new PrismaClient();

// ── small deterministic-ish RNG helpers ─────────────────────────────────
function randInt(min: number, max: number) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
function randFloat(min: number, max: number) {
  return Math.round((Math.random() * (max - min) + min) * 10) / 10;
}
function pick<T>(arr: T[]): T {
  return arr[randInt(0, arr.length - 1)];
}
function pickMany<T>(arr: T[], n: number): T[] {
  const copy = [...arr];
  const out: T[] = [];
  for (let i = 0; i < n && copy.length > 0; i++) {
    out.push(copy.splice(randInt(0, copy.length - 1), 1)[0]);
  }
  return out;
}
function slugify(s: string) {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "");
}

const PASSWORD = "FlexVault@123";

async function main() {
  console.log("Clearing existing data...");
  await db.$transaction([
    db.dropProduct.deleteMany(),
    db.drop.deleteMany(),
    db.blogPost.deleteMany(),
    db.review.deleteMany(),
    db.order.deleteMany(),
    db.bid.deleteMany(),
    db.watchlistItem.deleteMany(),
    db.authenticationRecord.deleteMany(),
    db.listing.deleteMany(),
    db.trendScore.deleteMany(),
    db.trendWeightConfig.deleteMany(),
    db.product.deleteMany(),
    db.category.deleteMany(),
    db.address.deleteMany(),
    db.session.deleteMany(),
    db.account.deleteMany(),
    db.user.deleteMany(),
  ]);

  // ── Users ────────────────────────────────────────────────────────────
  console.log("Seeding users...");
  const passwordHash = await bcrypt.hash(PASSWORD, 10);

  const admin = await db.user.create({
    data: { name: "Vault Admin", email: "admin@flexvault.in", passwordHash, role: Role.ADMIN },
  });
  const authenticator = await db.user.create({
    data: { name: "Priya Authenticator", email: "authenticator@flexvault.in", passwordHash, role: Role.AUTHENTICATOR },
  });

  const demoSellers = await Promise.all([
    db.user.create({ data: { name: "Rohan Kicks", email: "seller.bronze@flexvault.in", passwordHash, role: Role.SELLER, sellerTier: SellerTier.BRONZE } }),
    db.user.create({ data: { name: "Ananya Drip Co.", email: "seller.silver@flexvault.in", passwordHash, role: Role.SELLER, sellerTier: SellerTier.SILVER } }),
    db.user.create({ data: { name: "Vikram Vault House", email: "seller.gold@flexvault.in", passwordHash, role: Role.SELLER, sellerTier: SellerTier.GOLD } }),
    db.user.create({ data: { name: "Kabir Hypebeast Store", email: "seller.platinum@flexvault.in", passwordHash, role: Role.SELLER, sellerTier: SellerTier.PLATINUM, isProMember: true } }),
  ]);

  const demoBuyers = await Promise.all([
    db.user.create({ data: { name: "Aditya Sharma", email: "buyer@flexvault.in", passwordHash, role: Role.BUYER } }),
    db.user.create({ data: { name: "Meera Nair", email: "buyer.pro@flexvault.in", passwordHash, role: Role.BUYER, isProMember: true } }),
    db.user.create({ data: { name: "Ishaan Kapoor", email: "buyer.vault@flexvault.in", passwordHash, role: Role.BUYER } }),
  ]);

  const fillerSellerNames = ["Sneaker Souk", "Delhi Drip Dealers", "Bombay Boxlogo", "Bangalore Bids", "Hyderabad Heat", "Pune Plugs", "Chennai Cops", "Jaipur Jewels", "Kolkata Kicks", "Chandigarh Certified", "Goa Grails", "Lucknow Legacy"];
  const fillerSellers = await Promise.all(
    fillerSellerNames.map((name, i) =>
      db.user.create({
        data: {
          name,
          email: `${slugify(name)}@sellers.flexvault.in`,
          passwordHash,
          role: Role.SELLER,
          sellerTier: [SellerTier.BRONZE, SellerTier.SILVER, SellerTier.GOLD, SellerTier.PLATINUM][i % 4],
        },
      })
    )
  );
  const allSellers = [...demoSellers, ...fillerSellers];

  const fillerBuyerNames = ["Sara Khan", "Dev Patel", "Nisha Rao", "Arjun Menon", "Tara Bose", "Karan Malhotra", "Riya Iyer", "Yash Verma", "Zara Ali", "Amit Joshi"];
  const fillerBuyers = await Promise.all(
    fillerBuyerNames.map((name) =>
      db.user.create({ data: { name, email: `${slugify(name)}@buyers.flexvault.in`, passwordHash, role: Role.BUYER } })
    )
  );
  const allBuyers = [...demoBuyers, ...fillerBuyers];

  // ── Categories ───────────────────────────────────────────────────────
  console.log("Seeding categories...");
  const sneakers = await db.category.create({ data: { name: "Sneakers", slug: "sneakers", phase: CategoryPhase.PHASE_1, icon: "footprints" } });
  const diecast = await db.category.create({ data: { name: "Diecast", slug: "diecast", phase: CategoryPhase.PHASE_1, icon: "car" } });
  const streetwear = await db.category.create({ data: { name: "Streetwear", slug: "streetwear", phase: CategoryPhase.PHASE_2, icon: "shirt" } });
  const accessories = await db.category.create({ data: { name: "Accessories", slug: "accessories", phase: CategoryPhase.PHASE_2, icon: "gem" } });
  const watches = await db.category.create({ data: { name: "Watches", slug: "watches", phase: CategoryPhase.PHASE_3, icon: "watch" } });
  const perfumes = await db.category.create({ data: { name: "Perfumes", slug: "perfumes", phase: CategoryPhase.PHASE_3, icon: "flask-conical" } });

  await db.category.createMany({
    data: [
      { name: "Basketball", slug: "sneakers-basketball", phase: CategoryPhase.PHASE_1, parentId: sneakers.id, icon: "footprints" },
      { name: "Running", slug: "sneakers-running", phase: CategoryPhase.PHASE_1, parentId: sneakers.id, icon: "footprints" },
      { name: "Hoodies", slug: "streetwear-hoodies", phase: CategoryPhase.PHASE_2, parentId: streetwear.id, icon: "shirt" },
    ],
  });

  // ── Products ─────────────────────────────────────────────────────────
  console.log("Seeding products...");
  type SeedProduct = { name: string; brand: string; categoryId: string; subcategory?: string; priceRange: [number, number] };

  const catalog: SeedProduct[] = [
    // Sneakers
    { name: "Dunk Low Panda", brand: "Nike", categoryId: sneakers.id, subcategory: "Basketball", priceRange: [9000, 14000] },
    { name: "Dunk Low Michigan", brand: "Nike", categoryId: sneakers.id, subcategory: "Basketball", priceRange: [12000, 19000] },
    { name: "Air Force 1 '07 Triple White", brand: "Nike", categoryId: sneakers.id, subcategory: "Basketball", priceRange: [7000, 11000] },
    { name: "Air Force 1 '07 Triple Black", brand: "Nike", categoryId: sneakers.id, subcategory: "Basketball", priceRange: [7500, 11500] },
    { name: "Air Max 1 Patta Waves", brand: "Nike", categoryId: sneakers.id, subcategory: "Running", priceRange: [18000, 32000] },
    { name: "SB Dunk Low Travis Scott", brand: "Nike", categoryId: sneakers.id, subcategory: "Basketball", priceRange: [55000, 95000] },
    { name: "Air Jordan 1 Retro High Chicago", brand: "Jordan", categoryId: sneakers.id, subcategory: "Basketball", priceRange: [25000, 42000] },
    { name: "Air Jordan 1 Retro High Bred Toe", brand: "Jordan", categoryId: sneakers.id, subcategory: "Basketball", priceRange: [20000, 34000] },
    { name: "Air Jordan 4 Retro White Cement", brand: "Jordan", categoryId: sneakers.id, subcategory: "Basketball", priceRange: [22000, 36000] },
    { name: "Air Jordan 3 Retro Fire Red", brand: "Jordan", categoryId: sneakers.id, subcategory: "Basketball", priceRange: [18000, 29000] },
    { name: "Air Jordan 11 Retro Cool Grey", brand: "Jordan", categoryId: sneakers.id, subcategory: "Basketball", priceRange: [24000, 40000] },
    { name: "Air Jordan 4 Retro Black Cat", brand: "Jordan", categoryId: sneakers.id, subcategory: "Basketball", priceRange: [24000, 40000] },
    { name: "Yeezy Boost 350 V2 Zebra", brand: "Adidas", categoryId: sneakers.id, subcategory: "Running", priceRange: [16000, 26000] },
    { name: "Yeezy Boost 350 V2 Bone", brand: "Adidas", categoryId: sneakers.id, subcategory: "Running", priceRange: [15000, 24000] },
    { name: "Samba OG Cloud White", brand: "Adidas", categoryId: sneakers.id, priceRange: [6500, 9500] },
    { name: "Campus 00s Core Black", brand: "Adidas", categoryId: sneakers.id, priceRange: [7000, 10500] },
    { name: "Gazelle Indoor Navy", brand: "Adidas", categoryId: sneakers.id, priceRange: [7500, 11000] },
    { name: "550 White Green", brand: "New Balance", categoryId: sneakers.id, priceRange: [7500, 11000] },
    { name: "990v6 Grey", brand: "New Balance", categoryId: sneakers.id, subcategory: "Running", priceRange: [14000, 21000] },
    { name: "2002R Protection Pack", brand: "New Balance", categoryId: sneakers.id, subcategory: "Running", priceRange: [13000, 20000] },
    { name: "9060 Black", brand: "New Balance", categoryId: sneakers.id, priceRange: [13000, 19000] },
    { name: "Gel-Kayano 14 Silver", brand: "ASICS", categoryId: sneakers.id, subcategory: "Running", priceRange: [8500, 13000] },
    { name: "Suede Classic XXI", brand: "Puma", categoryId: sneakers.id, priceRange: [4500, 7000] },
    // Diecast
    { name: "RLC Datsun 240Z", brand: "Hot Wheels", categoryId: diecast.id, priceRange: [4500, 9000] },
    { name: "RLC Nissan Skyline GT-R", brand: "Hot Wheels", categoryId: diecast.id, priceRange: [5000, 10500] },
    { name: "Boulevard Porsche 930", brand: "Hot Wheels", categoryId: diecast.id, priceRange: [1800, 3500] },
    { name: "Premium Fast & Furious Supra", brand: "Hot Wheels", categoryId: diecast.id, priceRange: [2200, 4200] },
    { name: "Nissan GT-R Nismo", brand: "Mini GT", categoryId: diecast.id, priceRange: [2500, 4800] },
    { name: "Porsche 911 GT3 RS", brand: "Mini GT", categoryId: diecast.id, priceRange: [2800, 5200] },
    { name: "Toyota AE86 Initial D", brand: "Tarmac Works", categoryId: diecast.id, priceRange: [3500, 6500] },
    { name: "Honda NSX Type R", brand: "Tomica Limited Vintage", categoryId: diecast.id, priceRange: [2000, 4000] },
    { name: "Team Transport Camaro Set", brand: "Hot Wheels", categoryId: diecast.id, priceRange: [3200, 6000] },
    { name: "Lamborghini Countach LP500S", brand: "Kyosho", categoryId: diecast.id, priceRange: [8500, 15000] },
    { name: "Nissan Skyline GT-R R34 Z-Tune", brand: "Tarmac Works", categoryId: diecast.id, priceRange: [4000, 8000] },
    { name: "Toyota GR Supra LB-Works", brand: "Mini GT", categoryId: diecast.id, priceRange: [2800, 5500] },
    // Streetwear
    { name: "Box Logo Hoodie Black", brand: "Supreme", categoryId: streetwear.id, subcategory: "Hoodies", priceRange: [28000, 55000] },
    { name: "Box Logo Tee White", brand: "Supreme", categoryId: streetwear.id, priceRange: [9000, 16000] },
    { name: "Tri-Ferg Hoodie", brand: "Palace", categoryId: streetwear.id, subcategory: "Hoodies", priceRange: [14000, 24000] },
    { name: "8-Ball Fleece Crewneck", brand: "Stussy", categoryId: streetwear.id, priceRange: [8000, 13000] },
    { name: "Shark Full-Zip Hoodie Green", brand: "BAPE", categoryId: streetwear.id, subcategory: "Hoodies", priceRange: [22000, 38000] },
    { name: "Camo Tee", brand: "A Bathing Ape", categoryId: streetwear.id, priceRange: [6500, 11000] },
    { name: "Classic Logo Hoodie", brand: "Kith", categoryId: streetwear.id, subcategory: "Hoodies", priceRange: [12000, 20000] },
    { name: "Essentials Hoodie Cream", brand: "Fear of God", categoryId: streetwear.id, subcategory: "Hoodies", priceRange: [9000, 15000] },
    { name: "Detroit Jacket", brand: "Carhartt WIP", categoryId: streetwear.id, priceRange: [11000, 18000] },
    { name: "Crewneck Navy", brand: "Aime Leon Dore", categoryId: streetwear.id, priceRange: [13000, 22000] },
    { name: "Alcatraz Hoodie Triple Black", brand: "Corteiz", categoryId: streetwear.id, subcategory: "Hoodies", priceRange: [12000, 20000] },
    { name: "Cotton Wreath Sweatshirt Black", brand: "Denim Tears", categoryId: streetwear.id, priceRange: [15000, 25000] },
    // Accessories
    { name: "Neverfull MM Monogram", brand: "Louis Vuitton", categoryId: accessories.id, priceRange: [150000, 220000] },
    { name: "Industrial Belt", brand: "Off-White", categoryId: accessories.id, priceRange: [18000, 28000] },
    { name: "GG Marmont Bag", brand: "Gucci", categoryId: accessories.id, priceRange: [120000, 180000] },
    { name: "Shopping Bag Medium Black", brand: "Telfar", categoryId: accessories.id, priceRange: [16000, 26000] },
    { name: "Cross Ring", brand: "Chrome Hearts", categoryId: accessories.id, priceRange: [35000, 60000] },
    { name: "Le Chiquito Bag", brand: "Jacquemus", categoryId: accessories.id, priceRange: [45000, 70000] },
    { name: "St Louis Tote PM", brand: "Goyard", categoryId: accessories.id, priceRange: [90000, 140000] },
    { name: "Re-Nylon Crossbody", brand: "Prada", categoryId: accessories.id, priceRange: [70000, 110000] },
    { name: "Saddle Bag", brand: "Dior", categoryId: accessories.id, priceRange: [90000, 140000] },
    // Watches
    { name: "Submariner Date Black", brand: "Rolex", categoryId: watches.id, priceRange: [950000, 1300000] },
    { name: "Daytona Panda", brand: "Rolex", categoryId: watches.id, priceRange: [1800000, 2600000] },
    { name: "Speedmaster Moonwatch", brand: "Omega", categoryId: watches.id, priceRange: [420000, 620000] },
    { name: "G-Shock DW5600", brand: "Casio", categoryId: watches.id, priceRange: [4500, 8000] },
    { name: "Royal Oak 41mm", brand: "Audemars Piguet", categoryId: watches.id, priceRange: [3500000, 5200000] },
    { name: "Nautilus 5711", brand: "Patek Philippe", categoryId: watches.id, priceRange: [6000000, 9000000] },
    { name: "5 Sports SRPD Automatic", brand: "Seiko", categoryId: watches.id, priceRange: [18000, 28000] },
    { name: "Black Bay Fifty-Eight", brand: "Tudor", categoryId: watches.id, priceRange: [280000, 380000] },
    // Perfumes
    { name: "Aventus EDP 100ml", brand: "Creed", categoryId: perfumes.id, priceRange: [22000, 32000] },
    { name: "Sauvage Elixir 60ml", brand: "Dior", categoryId: perfumes.id, priceRange: [8500, 13000] },
    { name: "Tobacco Vanille 50ml", brand: "Tom Ford", categoryId: perfumes.id, priceRange: [16000, 24000] },
    { name: "Naxos EDP 50ml", brand: "Xerjoff", categoryId: perfumes.id, priceRange: [18000, 26000] },
    { name: "Layton EDP 125ml", brand: "Parfums de Marly", categoryId: perfumes.id, priceRange: [14000, 20000] },
    { name: "Jazz Club EDT 100ml", brand: "Maison Margiela", categoryId: perfumes.id, priceRange: [6000, 9500] },
    { name: "Baccarat Rouge 540 EDP 70ml", brand: "Maison Francis Kurkdjian", categoryId: perfumes.id, priceRange: [24000, 34000] },
    { name: "Black Opium EDP 90ml", brand: "YSL", categoryId: perfumes.id, priceRange: [9000, 14000] },
  ];

  const products = [];
  for (const item of catalog) {
    const fullName = `${item.brand} ${item.name}`;
    const slug = slugify(`${fullName}-${randInt(1000, 9999)}`);
    const releaseDaysAgo = randInt(20, 900);
    const product = await db.product.create({
      data: {
        name: fullName,
        slug,
        brand: item.brand,
        categoryId: item.categoryId,
        subcategory: item.subcategory,
        images: PRODUCT_IMAGE_OVERRIDES[fullName] ?? mockProductImages(fullName, item.name, 4),
        description: `Authenticated ${fullName}, verified by Flex Vault's multi-layer inspection process. Every unit is cross-checked against ${item.brand}'s construction, materials, and packaging references before it clears the vault.`,
        releaseDate: new Date(Date.now() - releaseDaysAgo * 86_400_000),
        sku: `FV-${slugify(item.brand)}-${randInt(10000, 99999)}`.toUpperCase(),
        baseTrendScore: randFloat(35, 90),
      },
    });
    products.push({ product, priceRange: item.priceRange });
  }

  // ── Trend weight config + trend history ─────────────────────────────
  console.log("Seeding trend history...");
  await db.trendWeightConfig.create({ data: {} });

  for (const { product } of products) {
    let mv = randFloat(30, 70);
    let sent = randFloat(30, 70);
    let eng = randFloat(30, 70);
    const entries = [];
    for (let day = 13; day >= 0; day--) {
      mv = Math.max(0, Math.min(100, mv + randFloat(-12, 12)));
      sent = Math.max(0, Math.min(100, sent + randFloat(-10, 10)));
      eng = Math.max(0, Math.min(100, eng + randFloat(-12, 12)));
      const score = calcTrendScore({ mentionVelocity: mv, sentimentScore: sent, engagementGrowth: eng });
      entries.push({
        productId: product.id,
        score,
        mentionVelocity: mv,
        sentimentScore: sent,
        engagementGrowth: eng,
        reasonSummary: trendReasonSummary({ mentionVelocity: mv, sentimentScore: sent, engagementGrowth: eng }),
        calculatedAt: new Date(Date.now() - day * 86_400_000),
      });
    }
    await db.trendScore.createMany({ data: entries });
  }

  // ── Listings, authentication records, orders, bids ──────────────────
  console.log("Seeding listings, authentications, orders, and bids...");
  const conditions = [Condition.NEW, Condition.LIKE_NEW, Condition.USED_EXCELLENT, Condition.USED_GOOD, Condition.USED_FAIR];
  let listingCount = 0;

  for (const { product, priceRange } of products) {
    const numListings = randInt(2, 4);
    for (let i = 0; i < numListings; i++) {
      const seller = pick(allSellers);
      const price = randInt(priceRange[0], priceRange[1]);
      const listingType = Math.random() < 0.15 ? ListingType.AUCTION : Math.random() < 0.28 ? ListingType.PREORDER : ListingType.FIXED;
      const statusRoll = Math.random();
      const status =
        statusRoll < 0.55 ? ListingStatus.ACTIVE : statusRoll < 0.72 ? ListingStatus.SOLD : statusRoll < 0.9 ? ListingStatus.PENDING_AUTH : ListingStatus.REJECTED;

      const listing = await db.listing.create({
        data: {
          sellerId: seller.id,
          productId: product.id,
          price,
          condition: pick(conditions),
          listingType,
          status,
          size: product.categoryId === sneakers.id ? pick(["UK6", "UK7", "UK8", "UK9", "UK10", "UK11"]) : null,
          quantity: 1,
          auctionEndsAt: listingType === ListingType.AUCTION ? new Date(Date.now() + randInt(1, 5) * 86_400_000) : null,
          preorderShipsAt: listingType === ListingType.PREORDER ? new Date(Date.now() + randInt(7, 30) * 86_400_000) : null,
        },
      });
      listingCount++;

      // Authentication record
      if (status === ListingStatus.ACTIVE || status === ListingStatus.SOLD) {
        await db.authenticationRecord.create({
          data: {
            listingId: listing.id,
            authenticatorId: authenticator.id,
            status: AuthDecision.APPROVED,
            inspectionPhotos: product.images.slice(0, 2),
            notes: "Stitching, materials, and packaging match verified reference set. Cleared for listing.",
            certificateHash: generateCertificateHash(listing.id),
            reviewedAt: new Date(),
          },
        });
      } else if (status === ListingStatus.REJECTED) {
        await db.authenticationRecord.create({
          data: {
            listingId: listing.id,
            authenticatorId: authenticator.id,
            status: AuthDecision.REJECTED,
            inspectionPhotos: product.images.slice(0, 2),
            notes: pick([
              "Stitching pattern inconsistent with authentic reference pairs.",
              "Box label font and spacing do not match verified batch.",
              "Material texture failed tactile inspection.",
            ]),
            reviewedAt: new Date(),
          },
        });
      } else {
        await db.authenticationRecord.create({
          data: {
            listingId: listing.id,
            status: AuthDecision.PENDING,
            inspectionPhotos: product.images.slice(0, 2),
          },
        });
      }

      // Bids for active auctions
      if (listingType === ListingType.AUCTION && status === ListingStatus.ACTIVE) {
        const bidders = pickMany(allBuyers, randInt(2, 5));
        let currentAmount = Math.round(price * 0.8);
        for (let b = 0; b < bidders.length; b++) {
          currentAmount = Math.round(currentAmount * randFloat(1.03, 1.12));
          await db.bid.create({
            data: {
              listingId: listing.id,
              bidderId: bidders[b].id,
              amount: currentAmount,
              status: b === bidders.length - 1 ? BidStatus.ACTIVE : BidStatus.OUTBID,
              createdAt: new Date(Date.now() - (bidders.length - b) * 3_600_000),
            },
          });
        }
      }

      // Orders for sold listings
      if (status === ListingStatus.SOLD) {
        const buyer = pick(allBuyers);
        const commissionRate = SELLER_TIER_COMMISSION[seller.sellerTier];
        const insuranceOpted = price >= INSURANCE_THRESHOLD_INR && Math.random() < 0.6;
        const insuranceFee = insuranceOpted ? Math.round(price * 0.015) : 0;
        const orderStatusRoll = Math.random();
        const orderStatus =
          orderStatusRoll < 0.15 ? OrderStatus.AUTHENTICATED :
          orderStatusRoll < 0.35 ? OrderStatus.SHIPPED :
          orderStatusRoll < 0.85 ? OrderStatus.DELIVERED :
          orderStatusRoll < 0.93 ? OrderStatus.DISPUTED : OrderStatus.RETURNED;

        const placedAt = new Date(Date.now() - randInt(2, 60) * 86_400_000);
        const trackingEvents = [
          { status: "PLACED", label: "Order placed & payment secured in escrow", at: placedAt.toISOString() },
        ];
        trackingEvents.push({ status: "AUTHENTICATED", label: "Item passed vault authentication", at: new Date(placedAt.getTime() + 1 * 86_400_000).toISOString() });
        if ((orderStatus as OrderStatus) === OrderStatus.SHIPPED || (orderStatus as OrderStatus) === OrderStatus.DELIVERED) {
          trackingEvents.push({ status: "SHIPPED", label: "Dispatched from Flex Vault hub", at: new Date(placedAt.getTime() + 2 * 86_400_000).toISOString() });
        }
        if (orderStatus === OrderStatus.DELIVERED) {
          trackingEvents.push({ status: "DELIVERED", label: "Delivered to buyer", at: new Date(placedAt.getTime() + 4 * 86_400_000).toISOString() });
        }

        const order = await db.order.create({
          data: {
            buyerId: buyer.id,
            listingId: listing.id,
            price,
            commissionRate,
            insuranceOpted,
            insuranceFee,
            status: orderStatus,
            trackingEvents,
            createdAt: placedAt,
          },
        });

        if (orderStatus === OrderStatus.DISPUTED) {
          await db.review.create({
            data: {
              orderId: order.id,
              raisedById: buyer.id,
              reason: pick([
                "Item condition does not match listing description.",
                "Received item appears different from certificate photos.",
                "Box and accessories missing from the shipment.",
              ]),
              status: DisputeStatus.UNDER_REVIEW,
            },
          });
        }
        if (orderStatus === OrderStatus.RETURNED) {
          await db.review.create({
            data: {
              orderId: order.id,
              raisedById: buyer.id,
              reason: "Buyer requested return within window.",
              resolution: "Item re-inspected, found genuine; buyer covered return shipping.",
              status: DisputeStatus.RESOLVED_SELLER,
              resolvedAt: new Date(),
            },
          });
        }

        // Watchlist a few sold items too, to show cross-cutting behaviour
        if (Math.random() < 0.2) {
          await db.watchlistItem.upsert({
            where: { userId_productId: { userId: buyer.id, productId: product.id } },
            update: {},
            create: { userId: buyer.id, productId: product.id },
          });
        }
      }
    }
  }

  // Watchlist entries for demo buyers specifically, so their dashboards have content
  for (const buyer of demoBuyers) {
    const picks = pickMany(products, 4);
    for (const { product } of picks) {
      await db.watchlistItem.upsert({
        where: { userId_productId: { userId: buyer.id, productId: product.id } },
        update: {},
        create: { userId: buyer.id, productId: product.id },
      });
    }
  }

  // Guarantee each demo buyer owns at least one delivered order (Digital Vault content)
  for (const buyer of demoBuyers) {
    const soldListing = await db.listing.findFirst({
      where: { status: ListingStatus.SOLD, orders: { none: {} } },
    });
    if (soldListing) {
      await db.order.create({
        data: {
          buyerId: buyer.id,
          listingId: soldListing.id,
          price: soldListing.price,
          commissionRate: 0.09,
          status: OrderStatus.DELIVERED,
          trackingEvents: [
            { status: "PLACED", label: "Order placed & payment secured in escrow", at: new Date(Date.now() - 10 * 86_400_000).toISOString() },
            { status: "AUTHENTICATED", label: "Item passed vault authentication", at: new Date(Date.now() - 9 * 86_400_000).toISOString() },
            { status: "SHIPPED", label: "Dispatched from Flex Vault hub", at: new Date(Date.now() - 7 * 86_400_000).toISOString() },
            { status: "DELIVERED", label: "Delivered to buyer", at: new Date(Date.now() - 5 * 86_400_000).toISOString() },
          ],
          createdAt: new Date(Date.now() - 10 * 86_400_000),
        },
      });
    }
  }

  // ── Blog posts ───────────────────────────────────────────────────────
  console.log("Seeding blog posts...");
  const posts = [
    { title: "Top 5 Drops This Month", excerpt: "The five releases every collector in the vault is watching right now.", published: true },
    { title: "How Flex Vault Authentication Actually Works", excerpt: "A walkthrough of our multi-layer inspection process, from intake to certificate.", published: true },
    { title: "Diecast Is the Next Big Hype Category", excerpt: "RLC drops are trading like sneakers now — here's why.", published: true },
    { title: "Seller Tiers Explained: Bronze to Platinum", excerpt: "What each tier unlocks, and how commission rates change as you grow.", published: true },
    { title: "Inside the Vault: A Fake Jordan 4 Breakdown", excerpt: "Draft — annotated photo breakdown of a rejected pair, pending final review.", published: false },
  ];
  for (const p of posts) {
    await db.blogPost.create({
      data: {
        title: p.title,
        slug: slugify(p.title),
        excerpt: p.excerpt,
        content: `${p.excerpt}\n\nFull editorial content for "${p.title}" goes here — authentication callouts, comparison photography, and market commentary curated by the Flex Vault editorial desk.`,
        coverImage: mockProductImages(p.title, p.title, 1)[0],
        authorId: admin.id,
        publishedAt: p.published ? new Date(Date.now() - randInt(1, 20) * 86_400_000) : null,
      },
    });
  }

  // ── Drop ─────────────────────────────────────────────────────────────
  console.log("Seeding active drop...");
  const dropFeatured = pickMany(products, 5);
  const drop = await db.drop.create({
    data: {
      title: "Vault Selects: Monsoon Heat Drop",
      slug: "vault-selects-monsoon-heat-drop",
      description: "A curated pre-order run of the pieces trending hardest across the vault this week — locked in early, delivered PAN-India.",
      coverImage: "/images/drop-monsoon-heat.jpg",
      dropDate: new Date("2026-07-20T18:00:00+05:30"),
      countdownTarget: new Date("2026-07-20T18:00:00+05:30"),
      isActive: true,
    },
  });
  for (const { product } of dropFeatured) {
    await db.dropProduct.create({ data: { dropId: drop.id, productId: product.id } });
  }

  console.log(`\nSeed complete: ${products.length} products, ${listingCount} listings, ${allSellers.length} sellers, ${allBuyers.length} buyers.\n`);
  console.log("Demo credentials (password for all: FlexVault@123):");
  console.log("  Admin          admin@flexvault.in");
  console.log("  Authenticator  authenticator@flexvault.in");
  console.log("  Seller BRONZE  seller.bronze@flexvault.in");
  console.log("  Seller SILVER  seller.silver@flexvault.in");
  console.log("  Seller GOLD    seller.gold@flexvault.in");
  console.log("  Seller PLATINUM (Pro) seller.platinum@flexvault.in");
  console.log("  Buyer          buyer@flexvault.in");
  console.log("  Buyer (Pro)    buyer.pro@flexvault.in");
  console.log("  Buyer          buyer.vault@flexvault.in");
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await db.$disconnect();
  });
