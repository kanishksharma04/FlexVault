"use client";

import { motion } from "framer-motion";
import { Check } from "lucide-react";
import { cn } from "@/lib/utils";

export function StepProgress({ steps, current }: { steps: string[]; current: number }) {
  return (
    <div className="flex items-center gap-2">
      {steps.map((label, i) => (
        <div key={label} className="flex flex-1 items-center gap-2">
          <div className="flex flex-col items-center gap-1.5">
            <div
              className={cn(
                "flex size-7 items-center justify-center rounded-full border font-mono text-xs transition-colors",
                i < current
                  ? "border-acid bg-acid text-acid-foreground"
                  : i === current
                  ? "border-acid text-acid"
                  : "border-border text-muted-foreground"
              )}
            >
              {i < current ? <Check className="size-3.5" /> : i + 1}
            </div>
            <span
              className={cn(
                "font-mono text-[10px] uppercase tracking-wider",
                i <= current ? "text-foreground" : "text-muted-foreground"
              )}
            >
              {label}
            </span>
          </div>
          {i < steps.length - 1 && (
            <div className="relative -mt-4 h-px flex-1 bg-border">
              <motion.div
                className="absolute inset-y-0 left-0 bg-acid"
                initial={{ width: "0%" }}
                animate={{ width: i < current ? "100%" : "0%" }}
                transition={{ duration: 0.4 }}
              />
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
