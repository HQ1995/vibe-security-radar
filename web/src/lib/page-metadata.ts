import type { Metadata } from "next";

export const SITE_NAME = "Vibe Security Radar";

export const SHARE_IMAGE = {
  url: "/opengraph-image",
  width: 1200,
  height: 630,
  type: "image/png",
  alt: SITE_NAME,
};

export function pageMetadata({
  title,
  description,
  path,
  type = "website",
  absoluteTitle = false,
}: {
  readonly title: string;
  readonly description: string;
  readonly path: string;
  readonly type?: "website" | "article";
  readonly absoluteTitle?: boolean;
}): Metadata {
  return {
    title: absoluteTitle ? { absolute: title } : title,
    description,
    alternates: { canonical: path },
    openGraph: {
      title,
      description,
      url: path,
      type,
      siteName: SITE_NAME,
      images: [SHARE_IMAGE],
    },
    twitter: {
      card: "summary_large_image",
      title,
      description,
      images: [SHARE_IMAGE],
    },
  };
}

export function clampDescription(text: string, max = 200): string {
  return text.length > max
    ? `${text.slice(0, max - 3).replace(/\s+\S*$/, "")}…`
    : text;
}
