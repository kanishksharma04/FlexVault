import path from "node:path";
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  turbopack: {
    root: path.join(__dirname),
  },
  images: {
    dangerouslyAllowSVG: true,
    contentDispositionType: "inline",
    contentSecurityPolicy: "default-src 'self'; script-src 'none'; sandbox;",
    remotePatterns: [
      { protocol: "https", hostname: "images.stockx.com" },
      { protocol: "https", hostname: "images.europeanwatch.com" },
      { protocol: "https", hostname: "upload.wikimedia.org" },
      { protocol: "https", hostname: "www.bobswatches.com" },
      { protocol: "https", hostname: "cdn2.jomashop.com" },
      { protocol: "https", hostname: "hobbycars.co.uk" },
      { protocol: "https", hostname: "www.toycarsusa.com" },
      { protocol: "https", hostname: "creations.mattel.com" },
      { protocol: "https", hostname: "shop.mattel.com" },
      { protocol: "https", hostname: "www.hwmodels.com" },
      { protocol: "https", hostname: "topcollectibles.com" },
      { protocol: "https", hostname: "cdn10.bigcommerce.com" },
      { protocol: "https", hostname: "www.jcardiecast.com" },
      { protocol: "https", hostname: "krazycaterpillar.com" },
      { protocol: "https", hostname: "www.tarmacworks.com" },
      { protocol: "https", hostname: "www.hlj.com" },
      { protocol: "https", hostname: "japan-figure.com" },
      { protocol: "https", hostname: "us.bape.com" },
      { protocol: "https", hostname: "image-cdn.hypb.st" },
      { protocol: "https", hostname: "cultizm.com" },
      { protocol: "https", hostname: "kith.com" },
      { protocol: "https", hostname: "feature.com" },
      { protocol: "https", hostname: "www.stadiumgoods.com" },
      { protocol: "https", hostname: "www.fashionphile.com" },
    ],
  },
};

export default nextConfig;
