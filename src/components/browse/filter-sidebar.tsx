"use client";

import { useRouter, usePathname, useSearchParams } from "next/navigation";
import { useCallback, useTransition } from "react";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

const CONDITIONS = [
  { value: "NEW", label: "New" },
  { value: "LIKE_NEW", label: "Like New" },
  { value: "USED_EXCELLENT", label: "Used - Excellent" },
  { value: "USED_GOOD", label: "Used - Good" },
  { value: "USED_FAIR", label: "Used - Fair" },
];

export function FilterSidebar({ brands, sizes }: { brands: string[]; sizes: string[] }) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const [, startTransition] = useTransition();

  const activeBrands = searchParams.getAll("brand");
  const activeSizes = searchParams.getAll("size");
  const activeConditions = searchParams.getAll("condition");
  const minPrice = searchParams.get("minPrice") ?? "";
  const maxPrice = searchParams.get("maxPrice") ?? "";

  const update = useCallback(
    (mutator: (params: URLSearchParams) => void) => {
      const params = new URLSearchParams(searchParams.toString());
      mutator(params);
      params.delete("page");
      startTransition(() => router.push(`${pathname}?${params.toString()}`, { scroll: false }));
    },
    [pathname, router, searchParams]
  );

  function toggleMulti(key: string, value: string) {
    update((params) => {
      const values = params.getAll(key);
      params.delete(key);
      if (values.includes(value)) {
        values.filter((v) => v !== value).forEach((v) => params.append(key, v));
      } else {
        [...values, value].forEach((v) => params.append(key, v));
      }
    });
  }

  function setPrice(key: "minPrice" | "maxPrice", value: string) {
    update((params) => {
      if (value) params.set(key, value);
      else params.delete(key);
    });
  }

  function clearAll() {
    startTransition(() => router.push(pathname, { scroll: false }));
  }

  return (
    <aside className="flex w-full flex-col gap-6 lg:w-56 lg:shrink-0">
      <div className="flex items-center justify-between">
        <h3 className="font-mono text-xs uppercase tracking-widest text-muted-foreground">Filters</h3>
        <Button variant="link" size="sm" className="h-auto p-0 text-[11px]" onClick={clearAll}>
          Clear all
        </Button>
      </div>

      <div className="flex flex-col gap-2">
        <Label>Price (₹)</Label>
        <div className="flex items-center gap-2">
          <Input
            type="number"
            placeholder="Min"
            defaultValue={minPrice}
            onBlur={(e) => setPrice("minPrice", e.target.value)}
            className="h-9"
          />
          <span className="text-muted-foreground">–</span>
          <Input
            type="number"
            placeholder="Max"
            defaultValue={maxPrice}
            onBlur={(e) => setPrice("maxPrice", e.target.value)}
            className="h-9"
          />
        </div>
      </div>

      {brands.length > 0 && (
        <div className="flex flex-col gap-2">
          <Label>Brand</Label>
          <div className="flex max-h-48 flex-col gap-2 overflow-y-auto pr-1">
            {brands.map((brand) => (
              <label key={brand} className="flex items-center gap-2 text-sm">
                <Checkbox checked={activeBrands.includes(brand)} onCheckedChange={() => toggleMulti("brand", brand)} />
                {brand}
              </label>
            ))}
          </div>
        </div>
      )}

      {sizes.length > 0 && (
        <div className="flex flex-col gap-2">
          <Label>Size</Label>
          <div className="flex flex-wrap gap-1.5">
            {sizes.map((size) => (
              <button
                key={size}
                onClick={() => toggleMulti("size", size)}
                className={
                  "rounded-sm border px-2 py-1 font-mono text-[11px] transition " +
                  (activeSizes.includes(size)
                    ? "border-acid bg-acid text-acid-foreground"
                    : "border-border text-muted-foreground hover:border-acid hover:text-acid")
                }
              >
                {size}
              </button>
            ))}
          </div>
        </div>
      )}

      <div className="flex flex-col gap-2">
        <Label>Condition</Label>
        <div className="flex flex-col gap-2">
          {CONDITIONS.map((c) => (
            <label key={c.value} className="flex items-center gap-2 text-sm">
              <Checkbox
                checked={activeConditions.includes(c.value)}
                onCheckedChange={() => toggleMulti("condition", c.value)}
              />
              {c.label}
            </label>
          ))}
        </div>
      </div>
    </aside>
  );
}
