"use client";

import { useState, useRef } from "react";
import Image from "next/image";
import { cn } from "@/lib/utils";

export function ImageGallery({ images, alt }: { images: string[]; alt: string }) {
  const [active, setActive] = useState(0);
  const [zoomStyle, setZoomStyle] = useState<React.CSSProperties>({});
  const [zoomed, setZoomed] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  function onMouseMove(e: React.MouseEvent<HTMLDivElement>) {
    if (!ref.current) return;
    const rect = ref.current.getBoundingClientRect();
    const x = ((e.clientX - rect.left) / rect.width) * 100;
    const y = ((e.clientY - rect.top) / rect.height) * 100;
    setZoomStyle({ transformOrigin: `${x}% ${y}%` });
  }

  return (
    <div className="flex flex-col gap-3">
      <div
        ref={ref}
        onMouseMove={onMouseMove}
        onMouseEnter={() => setZoomed(true)}
        onMouseLeave={() => setZoomed(false)}
        className="relative aspect-square w-full cursor-zoom-in overflow-hidden rounded-md border border-border bg-vault-3"
      >
        <Image
          src={images[active]}
          alt={alt}
          fill
          priority
          className={cn("object-cover transition-transform duration-300", zoomed && "scale-150")}
          style={zoomed ? zoomStyle : undefined}
          sizes="(max-width: 1024px) 100vw, 50vw"
        />
      </div>
      {images.length > 1 && (
        <div className="flex gap-2">
          {images.map((img, i) => (
            <button
              key={i}
              onClick={() => setActive(i)}
              className={cn(
                "relative size-16 shrink-0 overflow-hidden rounded-sm border transition",
                active === i ? "border-acid" : "border-border opacity-60 hover:opacity-100"
              )}
            >
              <Image src={img} alt={`${alt} view ${i + 1}`} fill className="object-cover" />
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
