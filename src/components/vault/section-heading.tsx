import { cn } from "@/lib/utils";

export function SectionHeading({
  eyebrow,
  title,
  description,
  className,
  align = "left",
}: {
  eyebrow?: string;
  title: string;
  description?: string;
  className?: string;
  align?: "left" | "center";
}) {
  return (
    <div className={cn("flex flex-col gap-2", align === "center" && "items-center text-center", className)}>
      {eyebrow && (
        <div className="flex items-center gap-2">
          <span className="h-px w-6 bg-acid" />
          <span className="font-mono text-xs uppercase tracking-[0.2em] text-acid">{eyebrow}</span>
        </div>
      )}
      <h2 className="font-display text-3xl tracking-wide sm:text-4xl">{title}</h2>
      {description && <p className="max-w-xl text-sm text-muted-foreground">{description}</p>}
    </div>
  );
}
