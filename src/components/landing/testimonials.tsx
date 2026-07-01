"use client";

import { motion } from "framer-motion";
import { Star } from "lucide-react";
import { SectionHeading } from "@/components/vault/section-heading";

const QUOTES = [
  {
    name: "Rehan A.",
    role: "Sneakerhead, Mumbai",
    quote: "Copped a Travis Scott Dunk and the cert QR actually checks out. First platform in India I trust for grails.",
  },
  {
    name: "Simran K.",
    role: "Seller, Gold Tier",
    quote: "Listed my RLC diecast collection and sold out in a week. Payouts hit faster once I hit Gold.",
  },
  {
    name: "Devansh P.",
    role: "Buyer, Bengaluru",
    quote: "2-day delivery on a Yeezy pair from a Delhi seller. Tracking was accurate down to the hour.",
  },
];

export function Testimonials() {
  return (
    <section className="border-y border-border bg-vault-2">
      <div className="mx-auto max-w-7xl px-4 py-16 sm:px-6">
        <SectionHeading eyebrow="Social Proof" title="TRUSTED BY THE CULTURE" align="center" className="mx-auto" />
        <div className="mt-10 grid gap-4 sm:grid-cols-3">
          {QUOTES.map((q, i) => (
            <motion.div
              key={q.name}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.1 }}
              className="flex flex-col gap-3 border border-border bg-card p-5"
            >
              <div className="flex gap-0.5 text-gold">
                {Array.from({ length: 5 }).map((_, s) => (
                  <Star key={s} className="size-3.5 fill-current" />
                ))}
              </div>
              <p className="text-sm text-foreground/90">&ldquo;{q.quote}&rdquo;</p>
              <div>
                <p className="text-sm font-semibold">{q.name}</p>
                <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">{q.role}</p>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
