import { SectionHeading } from "@/components/vault/section-heading";

export default function AboutPage() {
  return (
    <div className="mx-auto max-w-2xl px-4 py-16 sm:px-6">
      <SectionHeading eyebrow="About" title="INDIA'S VAULT" className="mb-6" />
      <div className="flex flex-col gap-4 text-sm leading-relaxed text-foreground/90">
        <p>
          Flex Vault exists because hype culture in India deserved better than screenshots, group-chat
          trust, and guesswork. We built a marketplace where every sneaker, streetwear piece, diecast
          collectible, watch, and accessory is authenticated before it ever reaches a buyer — and
          delivered PAN-India in 2–3 days.
        </p>
        <p>
          Three things drive every decision we make: <strong className="text-acid">trust</strong> through
          multi-layer authentication and digital certificates, <strong className="text-acid">access</strong>{" "}
          through AI-driven trend detection and early drops, and <strong className="text-acid">speed</strong>{" "}
          through a logistics network built for India.
        </p>
        <p className="font-display text-2xl tracking-wide text-acid">Drip. Verified. Delivered.</p>
      </div>
    </div>
  );
}
