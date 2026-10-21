import type { MetadataRoute } from "next";

import { SITE_URL } from "@/lib/constants";
import {
  getResearchCases,
  getResearchSnapshot,
  preferredCaseId,
} from "@/lib/research-data";

export const dynamic = "force-static";

export default function sitemap(): MetadataRoute.Sitemap {
  const updated = getResearchSnapshot().snapshot.source_cutoff.slice(0, 10);
  return [
    { url: `${SITE_URL}/`, lastModified: updated, priority: 1 },
    { url: `${SITE_URL}/cves/`, lastModified: updated, priority: 0.9 },
    { url: `${SITE_URL}/about/`, priority: 0.5 },
    ...getResearchCases().map((item) => ({
      url: `${SITE_URL}/cves/${preferredCaseId(item)}/`,
      lastModified: item.published_at?.slice(0, 10) ?? updated,
      priority: 0.7,
    })),
  ];
}
