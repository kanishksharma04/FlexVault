"use client";

import Link from "next/link";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";

export function ClosingCta() {
  return (
    <section className="relative overflow-hidden">
      <div className="hazard-stripes h-1.5 w-full opacity-70" />
      <div className="mx-auto max-w-4xl px-4 py-20 text-center sm:px-6">
        <motion.h2
          initial={{ opacity: 0, scale: 0.95 }}
          whileInView={{ opacity: 1, scale: 1 }}
          viewport={{ once: true }}
          className="font-display text-4xl tracking-wide sm:text-6xl"
        >
          DRIP. <span className="text-acid text-glow-acid">VERIFIED.</span> DELIVERED.
        </motion.h2>
        <p className="mt-4 text-muted-foreground">
          Join the vault — buy with certainty, sell with reach.
        </p>
        <div className="mt-6 flex flex-col justify-center gap-3 sm:flex-row">
          <Button asChild size="lg">
            <Link href="/signup">Create your account</Link>
          </Button>
          <Button asChild size="lg" variant="outline">
            <Link href="/how-it-works">Learn how it works</Link>
          </Button>
        </div>
      </div>
      <div className="hazard-stripes h-1.5 w-full opacity-70" />
    </section>
  );
}
