"use client";

import { motion } from "framer-motion";
import { PackageSearch, Microscope, ShieldCheck, Truck } from "lucide-react";
import { SectionHeading } from "@/components/vault/section-heading";

const STEPS = [
  {
    icon: PackageSearch,
    title: "01 — Intake",
    desc: "Seller ships the item straight to a Flex Vault authentication hub before it ever reaches a buyer.",
  },
  {
    icon: Microscope,
    title: "02 — Inspect",
    desc: "Trained authenticators cross-check stitching, materials, serials, and packaging against verified references.",
  },
  {
    icon: ShieldCheck,
    title: "03 — Certify",
    desc: "Approved items get a digital certificate with a certificate hash and scannable QR — your proof of authenticity.",
  },
  {
    icon: Truck,
    title: "04 — Deliver",
    desc: "Sealed and dispatched PAN-India with 2–3 day delivery and real-time tracking.",
  },
];

export function HowItWorks() {
  return (
    <section className="mx-auto max-w-7xl px-4 py-16 sm:px-6">
      <SectionHeading
        eyebrow="Trust"
        title="HOW AUTHENTICATION WORKS"
        description="Every single listing on Flex Vault passes through this pipeline before it can be bought."
      />
      <div className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {STEPS.map((step, i) => (
          <motion.div
            key={step.title}
            initial={{ opacity: 0, y: 24 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: i * 0.1 }}
            className="card-hype group flex flex-col gap-3 border border-border bg-card p-5"
          >
            <step.icon className="size-6 text-acid transition-transform duration-200 group-hover:scale-110" />
            <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">{step.title}</p>
            <p className="text-sm text-foreground/90">{step.desc}</p>
          </motion.div>
        ))}
      </div>
    </section>
  );
}
