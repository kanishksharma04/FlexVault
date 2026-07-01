import { cn } from "@/lib/utils";

export function HazardDivider({ className }: { className?: string }) {
  return <div className={cn("hazard-stripes h-2 w-full opacity-80", className)} />;
}
