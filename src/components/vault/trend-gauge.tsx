"use client";

import { motion, useReducedMotion } from "framer-motion";
import { trendTemperature } from "@/lib/business/trend";
import { cn } from "@/lib/utils";

const TEMP_COLOR: Record<ReturnType<typeof trendTemperature>, string> = {
  cold: "#6ee7ff",
  warm: "#e8b33d",
  hot: "#ff4d1c",
  blazing: "#ff4d1c",
};

export function TrendGauge({
  score,
  size = 120,
  label,
  className,
}: {
  score: number;
  size?: number;
  label?: string;
  className?: string;
}) {
  const reducedMotion = useReducedMotion();
  const radius = size / 2 - 10;
  const circumference = 2 * Math.PI * radius;
  const clamped = Math.max(0, Math.min(100, score));
  const offset = circumference * (1 - clamped / 100);
  const temp = trendTemperature(clamped);
  const color = TEMP_COLOR[temp];

  return (
    <div className={cn("flex flex-col items-center gap-2", className)}>
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90">
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="var(--vault-3)"
            strokeWidth={8}
          />
          <motion.circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth={8}
            strokeLinecap="round"
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            whileInView={{ strokeDashoffset: reducedMotion ? offset : offset }}
            viewport={{ once: true }}
            transition={{ duration: reducedMotion ? 0 : 1.2, ease: "easeOut" }}
            style={{ filter: `drop-shadow(0 0 6px ${color}80)` }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono text-2xl font-bold" style={{ color }}>
            {clamped.toFixed(0)}
          </span>
          <span className="font-mono text-[9px] uppercase tracking-widest text-muted-foreground">
            {temp}
          </span>
        </div>
      </div>
      {label && <p className="text-center text-xs text-muted-foreground">{label}</p>}
    </div>
  );
}
