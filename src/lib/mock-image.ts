/**
 * Deterministic gradient placeholder "photography" for seeded products.
 * Avoids scraping real brand assets while still giving every product a
 * distinct, on-brand looking image (no network dependency).
 */
const PALETTES: [string, string][] = [
  ["#1c1c20", "#c6f135"],
  ["#0a0a0b", "#e8b33d"],
  ["#131316", "#ff4d1c"],
  ["#1a1a1d", "#6ee7ff"],
  ["#0a0a0b", "#c6f135"],
  ["#1c1c20", "#ff4d1c"],
];

function hashString(input: string): number {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    hash = (hash << 5) - hash + input.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash);
}

export function mockProductImage(seed: string, label: string, variant = 0): string {
  const idx = (hashString(`${seed}:${variant}`) + variant) % PALETTES.length;
  const [from, to] = PALETTES[idx];
  const angle = 45 + ((hashString(seed) + variant * 37) % 270);
  const initials = label
    .split(" ")
    .slice(0, 2)
    .map((w) => w[0])
    .join("")
    .toUpperCase();

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="800" height="800" viewBox="0 0 800 800">
    <defs>
      <linearGradient id="g" gradientTransform="rotate(${angle} 0.5 0.5)">
        <stop offset="0%" stop-color="${from}"/>
        <stop offset="100%" stop-color="${to}"/>
      </linearGradient>
      <filter id="n"><feTurbulence type="fractalNoise" baseFrequency="0.85" numOctaves="2"/></filter>
    </defs>
    <rect width="800" height="800" fill="url(#g)"/>
    <rect width="800" height="800" filter="url(#n)" opacity="0.05"/>
    <text x="400" y="440" font-family="Arial, sans-serif" font-weight="900" font-size="200" fill="#0a0a0b" fill-opacity="0.18" text-anchor="middle">${initials}</text>
  </svg>`;

  const base64 =
    typeof Buffer !== "undefined"
      ? Buffer.from(svg).toString("base64")
      : btoa(svg);
  return `data:image/svg+xml;base64,${base64}`;
}

export function mockProductImages(seed: string, label: string, count = 3): string[] {
  return Array.from({ length: count }, (_, i) => mockProductImage(seed, label, i));
}
