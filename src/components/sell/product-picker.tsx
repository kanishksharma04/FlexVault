"use client";

import { useEffect, useState } from "react";
import Image from "next/image";
import { useQuery } from "@tanstack/react-query";
import { Search, Check } from "lucide-react";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

export type PickedProduct = { id: string; slug: string; name: string; brand: string; image: string };

type Suggestion = { id: string; slug: string; name: string; brand: string; image: string };

export function ProductPicker({
  categorySlug,
  value,
  onChange,
}: {
  categorySlug: string;
  value: PickedProduct | null;
  onChange: (p: PickedProduct) => void;
}) {
  const [term, setTerm] = useState("");
  const [debounced, setDebounced] = useState("");

  useEffect(() => {
    const id = setTimeout(() => setDebounced(term), 250);
    return () => clearTimeout(id);
  }, [term]);

  const { data, isFetching } = useQuery<{ results: Suggestion[] }>({
    queryKey: ["sell-product-search", categorySlug, debounced],
    queryFn: async () => {
      const res = await fetch(`/api/search?q=${encodeURIComponent(debounced)}&category=${categorySlug}`);
      return res.json();
    },
    enabled: debounced.trim().length >= 2,
  });

  const results = data?.results ?? [];

  return (
    <div className="flex flex-col gap-3">
      <div className="relative">
        <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          value={term}
          onChange={(e) => setTerm(e.target.value)}
          placeholder="Search catalog by model name or brand..."
          className="pl-9"
        />
      </div>

      {value && (
        <div className="flex items-center gap-3 border border-acid bg-acid/5 p-3">
          <div className="relative size-12 shrink-0 overflow-hidden bg-vault-3">
            <Image src={value.image} alt={value.name} fill className="object-cover" />
          </div>
          <div>
            <p className="font-mono text-[10px] uppercase text-muted-foreground">{value.brand}</p>
            <p className="text-sm font-semibold">{value.name}</p>
          </div>
          <Check className="ml-auto size-4 text-acid" />
        </div>
      )}

      {debounced.trim().length >= 2 && (
        <div className="flex flex-col gap-1.5">
          {isFetching && <p className="text-xs text-muted-foreground">Searching...</p>}
          {!isFetching && results.length === 0 && (
            <p className="text-xs text-muted-foreground">
              No catalog match. New products are added by the Flex Vault catalog team — contact support to request one.
            </p>
          )}
          {results.map((r) => (
            <button
              key={r.id}
              type="button"
              onClick={() => onChange(r)}
              className={cn(
                "flex items-center gap-3 border p-2 text-left transition",
                value?.id === r.id ? "border-acid" : "border-border hover:border-acid/50"
              )}
            >
              <div className="relative size-10 shrink-0 overflow-hidden bg-vault-3">
                <Image src={r.image} alt={r.name} fill className="object-cover" />
              </div>
              <div>
                <p className="font-mono text-[10px] uppercase text-muted-foreground">{r.brand}</p>
                <p className="text-sm">{r.name}</p>
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
