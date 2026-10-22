import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { NavHeader } from "@/components/nav-header";
import { PrintExpander } from "@/components/print-expander";
import { SiteFooter } from "@/components/site-footer";
import { SITE_URL } from "@/lib/constants";
import { getResearchSnapshot } from "@/lib/research-data";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

const DESCRIPTION =
  "Mechanism-level research tracing publicly disclosed vulnerabilities to AI-authored code changes.";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: {
    default: "Vibe Security Radar",
    template: "%s · Vibe Security Radar",
  },
  description: DESCRIPTION,
  openGraph: {
    title: "Vibe Security Radar",
    description: DESCRIPTION,
    siteName: "Vibe Security Radar",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "Vibe Security Radar",
    description: DESCRIPTION,
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const snapshot = getResearchSnapshot().snapshot;
  const generationId = snapshot.case_set + "@" + snapshot.source_cutoff;
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable}`}
      data-publication-generation={generationId}
      data-scroll-behavior="smooth"
    >
      <body className="font-sans antialiased">
        <a
          href="#content"
          className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-3 focus:z-[60] focus:rounded-md focus:bg-foreground focus:px-3 focus:py-2 focus:text-sm focus:font-medium focus:text-background"
        >
          Skip to content
        </a>
        <div className="flex min-h-screen flex-col">
          <NavHeader />
          <div id="content" tabIndex={-1} className="flex-1 outline-none">
            {children}
          </div>
          <SiteFooter />
          <PrintExpander />
        </div>
      </body>
    </html>
  );
}
