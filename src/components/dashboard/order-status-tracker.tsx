"use client";

import { motion } from "framer-motion";
import { PackageCheck, ShieldCheck, Truck, Home, AlertTriangle, Undo2 } from "lucide-react";
import { cn } from "@/lib/utils";
import type { OrderStatus } from "@prisma/client";

const STAGES = [
  { key: "PLACED", label: "Placed", icon: PackageCheck },
  { key: "AUTHENTICATED", label: "Authenticated", icon: ShieldCheck },
  { key: "SHIPPED", label: "Shipped", icon: Truck },
  { key: "DELIVERED", label: "Delivered", icon: Home },
] as const;

export function OrderStatusTracker({ status }: { status: OrderStatus }) {
  if (status === "DISPUTED" || status === "RETURNED" || status === "CANCELLED") {
    const Icon = status === "RETURNED" ? Undo2 : AlertTriangle;
    return (
      <div className="flex items-center gap-2 rounded-sm border border-hype/40 bg-hype/10 px-3 py-2 text-hype">
        <Icon className="size-4" />
        <span className="font-mono text-xs uppercase tracking-wider">{status}</span>
      </div>
    );
  }

  const currentIndex = STAGES.findIndex((s) => s.key === status);

  return (
    <div className="flex items-center">
      {STAGES.map((stage, i) => {
        const reached = i <= currentIndex;
        return (
          <div key={stage.key} className="flex flex-1 items-center last:flex-none">
            <div className="flex flex-col items-center gap-1">
              <div
                className={cn(
                  "flex size-8 items-center justify-center rounded-full border transition-colors",
                  reached ? "border-acid bg-acid/10 text-acid" : "border-border text-muted-foreground"
                )}
              >
                <stage.icon className="size-4" />
              </div>
              <span
                className={cn(
                  "font-mono text-[9px] uppercase tracking-wider",
                  reached ? "text-foreground" : "text-muted-foreground"
                )}
              >
                {stage.label}
              </span>
            </div>
            {i < STAGES.length - 1 && (
              <div className="relative -mt-4 mx-1 h-px flex-1 bg-border">
                <motion.div
                  className="absolute inset-y-0 left-0 bg-acid"
                  initial={{ width: "0%" }}
                  animate={{ width: i < currentIndex ? "100%" : "0%" }}
                  transition={{ duration: 0.6 }}
                />
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
