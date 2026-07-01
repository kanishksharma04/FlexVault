import Link from "next/link";
import { ShieldCheck, TrendingUp, Truck } from "lucide-react";
import { SectionHeading } from "@/components/vault/section-heading";
import { HowItWorks } from "@/components/landing/how-it-works";
import { Button } from "@/components/ui/button";

const PILLARS = [
  { icon: ShieldCheck, title: "Trust", desc: "Every listing passes multi-layer authentication before it's purchasable, backed by a digital certificate with a certificate hash and QR." },
  { icon: TrendingUp, title: "Access", desc: "AI-driven trend detection surfaces hype spikes early, plus drops, pre-orders, and auction bidding for grails." },
  { icon: Truck, title: "Speed", desc: "PAN-India delivery in 2–3 days with real-time tracking through every stage of the order." },
];

export default function HowItWorksPage() {
  return (
    <div>
      <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6">
        <SectionHeading eyebrow="Flex Vault" title="HOW IT WORKS" description="Three pillars, one marketplace." className="mb-10" />
        <div className="grid gap-4 sm:grid-cols-3">
          {PILLARS.map((p) => (
            <div key={p.title} className="flex flex-col gap-3 border border-border bg-card p-5">
              <p.icon className="size-6 text-acid" />
              <p className="font-display text-lg tracking-wide">{p.title}</p>
              <p className="text-sm text-muted-foreground">{p.desc}</p>
            </div>
          ))}
        </div>
      </div>
      <HowItWorks />
      <div className="mx-auto max-w-6xl px-4 pb-16 text-center sm:px-6">
        <Button asChild size="lg">
          <Link href="/browse/sneakers">Start Shopping</Link>
        </Button>
      </div>
    </div>
  );
}
