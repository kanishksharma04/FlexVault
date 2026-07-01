import type { MetadataRoute } from "next";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: {
      userAgent: "*",
      allow: "/",
      disallow: ["/dashboard/", "/checkout", "/api/"],
    },
    sitemap: "https://flex-vault.vercel.app/sitemap.xml",
  };
}
