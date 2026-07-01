"use client";

import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { cn } from "@/lib/utils";

function getTimeParts(target: number) {
  const diff = Math.max(0, target - Date.now());
  return {
    days: Math.floor(diff / 86_400_000),
    hours: Math.floor((diff / 3_600_000) % 24),
    minutes: Math.floor((diff / 60_000) % 60),
    seconds: Math.floor((diff / 1000) % 60),
    done: diff <= 0,
  };
}

function Digit({ value }: { value: string }) {
  return (
    <span className="relative inline-block h-[1em] w-[0.62em] overflow-hidden">
      <AnimatePresence mode="popLayout" initial={false}>
        <motion.span
          key={value}
          initial={{ y: "100%", opacity: 0 }}
          animate={{ y: "0%", opacity: 1 }}
          exit={{ y: "-100%", opacity: 0 }}
          transition={{ duration: 0.35, ease: "easeOut" }}
          className="absolute inset-0 flex items-center justify-center"
        >
          {value}
        </motion.span>
      </AnimatePresence>
    </span>
  );
}

function TimeBlock({ value, label }: { value: number; label: string }) {
  const str = value.toString().padStart(2, "0");
  return (
    <div className="flex flex-col items-center gap-1">
      <div className="flex gap-0.5 rounded-md border border-border bg-vault-2 px-3 py-2 font-mono text-2xl font-bold tabular-nums text-acid sm:text-3xl">
        {str.split("").map((d, i) => (
          <Digit key={i} value={d} />
        ))}
      </div>
      <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">{label}</span>
    </div>
  );
}

export function Countdown({ target, className }: { target: Date | string; className?: string }) {
  const targetMs = new Date(target).getTime();
  // Time-dependent value is computed client-side only (post-mount) so the
  // server-rendered markup and the initial client render always match —
  // computing Date.now() during render would diverge between the two and
  // trigger a hydration mismatch.
  const [parts, setParts] = useState<ReturnType<typeof getTimeParts> | null>(null);

  useEffect(() => {
    // Reading the clock (an external system) must happen post-mount, not during render.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setParts(getTimeParts(targetMs));
    const id = setInterval(() => setParts(getTimeParts(targetMs)), 1000);
    return () => clearInterval(id);
  }, [targetMs]);

  if (!parts) {
    return (
      <div className={cn("flex items-center gap-2 sm:gap-3", className)}>
        <TimeBlock value={0} label="Days" />
        <span className="pb-4 font-display text-xl text-muted-foreground">:</span>
        <TimeBlock value={0} label="Hrs" />
        <span className="pb-4 font-display text-xl text-muted-foreground">:</span>
        <TimeBlock value={0} label="Min" />
        <span className="pb-4 font-display text-xl text-muted-foreground">:</span>
        <TimeBlock value={0} label="Sec" />
      </div>
    );
  }

  if (parts.done) {
    return <p className={cn("font-display text-2xl tracking-wide text-acid", className)}>DROPPED</p>;
  }

  return (
    <div className={cn("flex items-center gap-2 sm:gap-3", className)}>
      <TimeBlock value={parts.days} label="Days" />
      <span className="pb-4 font-display text-xl text-muted-foreground">:</span>
      <TimeBlock value={parts.hours} label="Hrs" />
      <span className="pb-4 font-display text-xl text-muted-foreground">:</span>
      <TimeBlock value={parts.minutes} label="Min" />
      <span className="pb-4 font-display text-xl text-muted-foreground">:</span>
      <TimeBlock value={parts.seconds} label="Sec" />
    </div>
  );
}
