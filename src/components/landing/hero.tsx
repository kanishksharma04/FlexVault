"use client";

import { useRef } from "react";
import Link from "next/link";
import { motion, useMotionValue, useMotionTemplate, useSpring, useReducedMotion } from "framer-motion";
import { Button } from "@/components/ui/button";

const HERO_LINE_1 = "DRIP.";
const HERO_LINE_2 = "VERIFIED.";
const HERO_LINE_3 = "DELIVERED.";

const BRAND_MARQUEE = [
  "NIKE", "JORDAN", "ADIDAS", "SUPREME", "HOT WHEELS", "ROLEX", "NEW BALANCE",
  "BAPE", "OFF-WHITE", "PALACE", "STUSSY", "OMEGA", "GUCCI", "CREED",
];

function AnimatedWord({ text, delay }: { text: string; delay: number }) {
  return (
    <span className="block overflow-hidden">
      <motion.span
        initial={{ y: "100%" }}
        animate={{ y: "0%" }}
        transition={{ duration: 0.7, delay, ease: [0.16, 1, 0.3, 1] }}
        className="block"
      >
        {text}
      </motion.span>
    </span>
  );
}

export function Hero() {
  const ref = useRef<HTMLElement>(null);
  const reducedMotion = useReducedMotion();

  const mvX = useMotionValue(0);
  const mvY = useMotionValue(0);
  const spotX = useSpring(mvX, { stiffness: 120, damping: 25 });
  const spotY = useSpring(mvY, { stiffness: 120, damping: 25 });
  const spotlight = useMotionTemplate`radial-gradient(600px circle at ${spotX}px ${spotY}px, rgba(198, 241, 53, 0.15), transparent 70%)`;

  function onMouseMove(e: React.MouseEvent<HTMLElement>) {
    if (reducedMotion || !ref.current) return;
    const rect = ref.current.getBoundingClientRect();
    mvX.set(e.clientX - rect.left);
    mvY.set(e.clientY - rect.top);
  }

  return (
    <section ref={ref} onMouseMove={onMouseMove} className="relative overflow-hidden border-b border-border">
      <div className="halftone pointer-events-none absolute inset-0 text-vault-3 opacity-40" />
      <div className="pointer-events-none absolute -top-32 right-0 h-96 w-96 rounded-full bg-acid/10 blur-3xl" />
      {!reducedMotion && (
        <motion.div className="pointer-events-none absolute inset-0" style={{ background: spotlight }} />
      )}

      <div className="relative mx-auto flex max-w-7xl flex-col items-center gap-8 px-4 py-20 text-center sm:px-6 sm:py-28">
        <motion.span
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="flex items-center gap-2 rounded-full border border-border bg-vault-2 px-4 py-1.5 font-mono text-xs uppercase tracking-widest text-acid"
        >
          <span className="size-1.5 animate-pulse-glow rounded-full bg-acid" />
          India&apos;s Authenticated Hype Marketplace
        </motion.span>

        <h1 className="font-display text-6xl leading-[0.95] tracking-wide sm:text-8xl md:text-9xl">
          <AnimatedWord text={HERO_LINE_1} delay={0.15} />
          <AnimatedWord text={HERO_LINE_2} delay={0.28} />
          <span className="text-acid text-glow-acid">
            <AnimatedWord text={HERO_LINE_3} delay={0.41} />
          </span>
        </h1>

        <motion.p
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.65 }}
          className="max-w-lg text-balance text-muted-foreground"
        >
          Sneakers, streetwear, diecast, watches, and accessories — every drop cleared through
          multi-layer authentication and delivered PAN-India in 2–3 days.
        </motion.p>

        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.78 }}
          className="flex flex-col gap-3 sm:flex-row"
        >
          <Button asChild size="lg">
            <Link href="/browse/sneakers">Shop the Vault</Link>
          </Button>
          <Button asChild size="lg" variant="outline">
            <Link href="/sell">Start Selling</Link>
          </Button>
        </motion.div>
      </div>

      <div className="relative border-t border-border py-4">
        <div className="flex w-max animate-marquee gap-12 hover:paused">
          {[...BRAND_MARQUEE, ...BRAND_MARQUEE].map((b, i) => (
            <span
              key={i}
              className="shrink-0 font-display text-2xl tracking-wide text-muted-foreground/40 transition-colors duration-200 hover:text-acid sm:text-3xl"
            >
              {b}
            </span>
          ))}
        </div>
      </div>
    </section>
  );
}
