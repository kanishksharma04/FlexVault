import { db } from "@/lib/db";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from "@/components/ui/select";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { TierBadge } from "@/components/vault/tier-badge";
import { AuthBadge } from "@/components/vault/auth-badge";
import { TrendGauge } from "@/components/vault/trend-gauge";
import { Countdown } from "@/components/vault/countdown";
import { SectionHeading } from "@/components/vault/section-heading";
import { HazardDivider } from "@/components/vault/hazard-divider";
import { ProductCard, type ProductCardData } from "@/components/vault/product-card";

export default async function ComponentShowcasePage() {
  // Fixed offset computed once per server render — fine for this internal
  // sanity-check page, which isn't re-rendered client-side.
  // eslint-disable-next-line react-hooks/purity
  const countdownDemoTarget = new Date(Date.now() + 3 * 86_400_000 + 5 * 3_600_000);

  const products = await db.product.findMany({
    take: 4,
    include: { listings: { where: { status: "ACTIVE" }, orderBy: { price: "asc" }, take: 1 } },
  });

  const cards: ProductCardData[] = products.map((p) => ({
    slug: p.slug,
    name: p.name,
    brand: p.brand,
    images: p.images,
    fromPrice: p.listings[0]?.price ?? null,
    trendScore: p.baseTrendScore,
    listingCount: p.listings.length,
  }));

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-16 px-4 py-16 sm:px-6">
      <SectionHeading eyebrow="Internal" title="COMPONENT SHOWCASE" description="Vault Streetwear primitives — sanity check before wiring real pages." />

      <section className="flex flex-col gap-4">
        <h3 className="font-mono text-xs uppercase tracking-widest text-muted-foreground">Buttons</h3>
        <div className="flex flex-wrap items-center gap-3">
          <Button>Cop It</Button>
          <Button variant="outline">Watch Item</Button>
          <Button variant="secondary">Save Draft</Button>
          <Button variant="ghost">Cancel</Button>
          <Button variant="destructive">Reject</Button>
          <Button variant="link">View certificate</Button>
          <Button size="sm">Small</Button>
          <Button size="lg">Large CTA</Button>
        </div>
      </section>

      <HazardDivider />

      <section className="flex flex-col gap-4">
        <h3 className="font-mono text-xs uppercase tracking-widest text-muted-foreground">Badges</h3>
        <div className="flex flex-wrap items-center gap-3">
          <Badge>Default</Badge>
          <Badge variant="secondary">Secondary</Badge>
          <Badge variant="outline">Outline</Badge>
          <Badge variant="acid">Acid</Badge>
          <Badge variant="gold">Gold</Badge>
          <Badge variant="hype">Hype</Badge>
          <TierBadge tier="BRONZE" />
          <TierBadge tier="SILVER" />
          <TierBadge tier="GOLD" />
          <TierBadge tier="PLATINUM" />
          <AuthBadge status="APPROVED" />
          <AuthBadge status="PENDING" />
          <AuthBadge status="REJECTED" />
        </div>
      </section>

      <section className="flex flex-col gap-4">
        <h3 className="font-mono text-xs uppercase tracking-widest text-muted-foreground">Trend Gauges</h3>
        <div className="flex flex-wrap gap-8">
          <TrendGauge score={22} label="Cold" />
          <TrendGauge score={52} label="Warm" />
          <TrendGauge score={74} label="Hot" />
          <TrendGauge score={94} label="Blazing" />
        </div>
      </section>

      <section className="flex flex-col gap-4">
        <h3 className="font-mono text-xs uppercase tracking-widest text-muted-foreground">Drop Countdown</h3>
        <Countdown target={countdownDemoTarget} />
      </section>

      <section className="flex flex-col gap-4">
        <h3 className="font-mono text-xs uppercase tracking-widest text-muted-foreground">Form Controls</h3>
        <div className="grid max-w-md gap-4">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="showcase-input">Search size</Label>
            <Input id="showcase-input" placeholder="UK 9" />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label>Condition</Label>
            <Select defaultValue="new">
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="new">New</SelectItem>
                <SelectItem value="like_new">Like New</SelectItem>
                <SelectItem value="used_good">Used - Good</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <Progress value={64} />
        </div>
      </section>

      <section className="flex flex-col gap-4">
        <h3 className="font-mono text-xs uppercase tracking-widest text-muted-foreground">Tabs</h3>
        <Tabs defaultValue="buy" className="max-w-md">
          <TabsList>
            <TabsTrigger value="buy">Buy Now</TabsTrigger>
            <TabsTrigger value="bid">Place Bid</TabsTrigger>
            <TabsTrigger value="preorder">Pre-order</TabsTrigger>
          </TabsList>
          <TabsContent value="buy" className="p-3 text-sm text-muted-foreground">Buy now content.</TabsContent>
          <TabsContent value="bid" className="p-3 text-sm text-muted-foreground">Bidding content.</TabsContent>
          <TabsContent value="preorder" className="p-3 text-sm text-muted-foreground">Pre-order content.</TabsContent>
        </Tabs>
      </section>

      <section className="flex flex-col gap-4">
        <h3 className="font-mono text-xs uppercase tracking-widest text-muted-foreground">Card</h3>
        <Card className="max-w-sm">
          <CardHeader>
            <CardTitle>Vault Card</CardTitle>
            <CardDescription>Standard card primitive.</CardDescription>
          </CardHeader>
          <CardContent className="pb-5 text-sm text-muted-foreground">
            Used across dashboards for grouped content.
          </CardContent>
        </Card>
      </section>

      {cards.length > 0 && (
        <section className="flex flex-col gap-4">
          <h3 className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
            Product Card (tilt + image swap on hover)
          </h3>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            {cards.map((c) => (
              <ProductCard key={c.slug} product={c} />
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
