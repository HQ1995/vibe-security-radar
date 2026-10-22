import { SITE_URL } from "@/lib/constants";
import {
  getCaseHeadline,
  getResearchCases,
  getResearchSnapshot,
  preferredCaseId,
} from "@/lib/research-data";

export const dynamic = "force-static";

function escape(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function GET() {
  const updated = `${getResearchSnapshot().snapshot.source_cutoff.slice(0, 10)}T00:00:00Z`;
  const entries = [...getResearchCases()]
    .filter((item) => item.published_at)
    .sort((a, b) => (b.published_at ?? "").localeCompare(a.published_at ?? ""))
    .slice(0, 50)
    .map((item) => {
      const id = preferredCaseId(item);
      const url = `${SITE_URL}/cves/${id}/`;
      const date = `${item.published_at!.slice(0, 10)}T00:00:00Z`;
      return `  <entry>
    <title>${escape(`${id}: ${item.repository ?? "repository not recorded"}`)}</title>
    <link href="${url}"/>
    <id>${url}</id>
    <updated>${date}</updated>
    <summary>${escape(getCaseHeadline(item))}</summary>
  </entry>`;
    });
  const body = `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Vibe Security Radar: new findings</title>
  <subtitle>Vulnerabilities where an AI-assisted change played a role, newest first.</subtitle>
  <link href="${SITE_URL}/"/>
  <link rel="self" href="${SITE_URL}/feed.xml"/>
  <id>${SITE_URL}/</id>
  <updated>${updated}</updated>
  <author><name>Georgia Tech SSLab</name></author>
${entries.join("\n")}
</feed>
`;
  return new Response(body, {
    headers: { "Content-Type": "application/atom+xml; charset=utf-8" },
  });
}
