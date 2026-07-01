import { getHypeTicker } from "@/lib/queries/trend";
import { HypeTickerMarquee } from "./hype-ticker-marquee";

export async function HypeTicker() {
  const entries = await getHypeTicker(18);
  if (entries.length === 0) return null;
  return <HypeTickerMarquee entries={entries} />;
}
