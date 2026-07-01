import type { MetadataRoute } from "next";

const BASE_URL = "https://flex-vault.vercel.app";

const STATIC_ROUTES = [
  { path: "/", changeFrequency: "daily", priority: 1 },
  { path: "/drops", changeFrequency: "daily", priority: 0.9 },
  { path: "/trend", changeFrequency: "daily", priority: 0.8 },
  { path: "/blog", changeFrequency: "weekly", priority: 0.6 },
  { path: "/sell", changeFrequency: "monthly", priority: 0.7 },
  { path: "/pro", changeFrequency: "monthly", priority: 0.6 },
  { path: "/how-it-works", changeFrequency: "monthly", priority: 0.5 },
  { path: "/authentication", changeFrequency: "monthly", priority: 0.5 },
  { path: "/about", changeFrequency: "monthly", priority: 0.4 },
  { path: "/faq", changeFrequency: "monthly", priority: 0.4 },
  { path: "/contact", changeFrequency: "monthly", priority: 0.3 },
] as const;

export default function sitemap(): MetadataRoute.Sitemap {
  const lastModified = new Date();
  return STATIC_ROUTES.map(({ path, changeFrequency, priority }) => ({
    url: `${BASE_URL}${path}`,
    lastModified,
    changeFrequency,
    priority,
  }));
}
