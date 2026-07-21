import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { NavHeader } from "@/components/nav-header";
import { SiteFooter } from "@/components/site-footer";
import { getDataGenerationId } from "@/lib/data";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  metadataBase: new URL("https://vibe-radar-ten.vercel.app"),
  title: "Vibe Security Radar",
  description: "Tracking the security cost of vibe coding",
  openGraph: {
    title: "Vibe Security Radar",
    description: "Tracking the security cost of vibe coding",
    siteName: "Vibe Security Radar",
    type: "website",
  },
  twitter: {
    card: "summary",
    title: "Vibe Security Radar",
    description: "Tracking the security cost of vibe coding",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const generationId = getDataGenerationId();
  return (
    <html
      lang="en"
      className="dark"
      data-publication-generation={generationId}
    >
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        <div className="flex min-h-screen flex-col">
          <NavHeader />
          <div className="flex-1">{children}</div>
          <SiteFooter />
        </div>
      </body>
    </html>
  );
}
