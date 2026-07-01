"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import Image from "next/image";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { Search, Loader2 } from "lucide-react";
import { Input } from "@/components/ui/input";

type Suggestion = { slug: string; name: string; brand: string; image: string };

export function SearchBar({ autoFocus = false }: { autoFocus?: boolean }) {
  const router = useRouter();
  const [term, setTerm] = useState("");
  const [debounced, setDebounced] = useState("");
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const id = setTimeout(() => setDebounced(term), 250);
    return () => clearTimeout(id);
  }, [term]);

  useEffect(() => {
    function onClickAway(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onClickAway);
    return () => document.removeEventListener("mousedown", onClickAway);
  }, []);

  const { data, isFetching } = useQuery<{ results: Suggestion[] }>({
    queryKey: ["search-suggest", debounced],
    queryFn: async () => {
      const res = await fetch(`/api/search?q=${encodeURIComponent(debounced)}`);
      return res.json();
    },
    enabled: debounced.trim().length >= 2,
  });

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!term.trim()) return;
    setOpen(false);
    router.push(`/search?q=${encodeURIComponent(term.trim())}`);
  }

  const suggestions = data?.results ?? [];

  return (
    <div ref={containerRef} className="relative w-full">
      <form onSubmit={onSubmit} className="relative">
        <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          autoFocus={autoFocus}
          value={term}
          onChange={(e) => {
            setTerm(e.target.value);
            setOpen(true);
          }}
          onFocus={() => setOpen(true)}
          placeholder="Search sneakers, streetwear, diecast..."
          className="h-11 pl-9"
        />
        {isFetching && <Loader2 className="absolute right-3 top-1/2 size-4 -translate-y-1/2 animate-spin text-muted-foreground" />}
      </form>

      {open && debounced.trim().length >= 2 && suggestions.length > 0 && (
        <div className="absolute z-50 mt-2 w-full overflow-hidden rounded-md border border-border bg-vault-2 shadow-lg">
          {suggestions.map((s) => (
            <Link
              key={s.slug}
              href={`/product/${s.slug}`}
              onClick={() => setOpen(false)}
              className="flex items-center gap-3 px-3 py-2 transition hover:bg-vault-3"
            >
              <div className="relative size-10 shrink-0 overflow-hidden rounded-sm bg-vault-3">
                <Image src={s.image} alt={s.name} fill className="object-cover" />
              </div>
              <div>
                <p className="font-mono text-[10px] uppercase text-muted-foreground">{s.brand}</p>
                <p className="line-clamp-1 text-sm">{s.name}</p>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
