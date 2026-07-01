"use client";

export function SalesBarChart({ data }: { data: { date: string; total: number }[] }) {
  const max = Math.max(...data.map((d) => d.total), 1);
  const hasSales = data.some((d) => d.total > 0);

  if (!hasSales) {
    return (
      <p className="flex h-32 items-center justify-center font-mono text-xs text-muted-foreground">
        No sales in this window yet.
      </p>
    );
  }

  return (
    <div className="flex h-32 items-end gap-1">
      {data.map((d) => (
        <div key={d.date} className="group relative flex flex-1 flex-col items-center justify-end">
          <div
            className="w-full rounded-t-sm bg-acid/70 transition-colors group-hover:bg-acid"
            style={{ height: `${Math.max(2, (d.total / max) * 100)}%` }}
          />
          <div className="pointer-events-none absolute -top-8 hidden whitespace-nowrap rounded-sm border border-border bg-vault-2 px-2 py-1 font-mono text-[10px] group-hover:block">
            ₹{d.total.toLocaleString("en-IN")}
          </div>
        </div>
      ))}
    </div>
  );
}
