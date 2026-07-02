import type { Metadata } from "next";
import { Anton, Archivo, Space_Mono } from "next/font/google";
import "./globals.css";
import { Providers } from "@/components/providers";
import { SiteHeader } from "@/components/layout/site-header";
import { SiteFooter } from "@/components/layout/site-footer";
import { HypeTicker } from "@/components/hype/hype-ticker";
import { Toaster } from "@/components/ui/sonner";

const fontDisplay = Anton({
  variable: "--font-display",
  weight: "400",
  subsets: ["latin"],
});

const fontBody = Archivo({
  variable: "--font-body",
  subsets: ["latin"],
});

const fontData = Space_Mono({
  variable: "--font-data",
  weight: ["400", "700"],
  subsets: ["latin"],
});

const TITLE = "Flex Vault";
const OG_TITLE = "Flex Vault — Drip. Verified. Delivered.";
const DESCRIPTION =
  "India's authenticated marketplace for hype culture — sneakers, streetwear, diecast, watches, and accessories. Multi-layer verified, delivered PAN-India in 2-3 days.";

export const metadata: Metadata = {
  metadataBase: new URL("https://flex-vault.vercel.app"),
  title: TITLE,
  description: DESCRIPTION,
  openGraph: {
    title: OG_TITLE,
    description: DESCRIPTION,
    siteName: "Flex Vault",
    type: "website",
    locale: "en_IN",
  },
  twitter: {
    card: "summary_large_image",
    title: OG_TITLE,
    description: DESCRIPTION,
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`dark ${fontDisplay.variable} ${fontBody.variable} ${fontData.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col">
        <Providers>
          <HypeTicker />
          <SiteHeader />
          <main className="flex-1">{children}</main>
          <SiteFooter />
          <Toaster theme="dark" position="bottom-right" />
        </Providers>
      </body>
    </html>
  );
}
