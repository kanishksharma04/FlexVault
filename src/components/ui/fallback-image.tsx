"use client";

import { useState } from "react";
import Image, { type ImageProps } from "next/image";
import { mockProductImage } from "@/lib/mock-image";

type FallbackImageProps = Omit<ImageProps, "src" | "onError"> & {
  src: string;
  fallbackSeed: string;
};

export function FallbackImage({ src, fallbackSeed, ...props }: FallbackImageProps) {
  const [failed, setFailed] = useState(false);
  const effectiveSrc = failed ? mockProductImage(fallbackSeed, fallbackSeed) : src;

  return (
    // eslint-disable-next-line jsx-a11y/alt-text -- `alt` is required by ImageProps and forwarded via {...props}
    <Image
      {...props}
      src={effectiveSrc}
      unoptimized={effectiveSrc.startsWith("data:")}
      onError={() => setFailed(true)}
    />
  );
}
