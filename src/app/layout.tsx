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

export const metadata: Metadata = {
  title: "Flex Vault — Drip. Verified. Delivered.",
  description:
    "India's authenticated marketplace for hype culture — sneakers, streetwear, diecast, watches, and accessories. Multi-layer verified, delivered PAN-India in 2-3 days.",
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
