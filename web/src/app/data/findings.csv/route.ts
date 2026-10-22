import { SITE_URL } from "@/lib/constants";
import {
  formatContributionClass,
  getAiToolLabel,
  getCaseHeadline,
  getCauseCategoryLabel,
  getResearchCases,
  preferredCaseId,
} from "@/lib/research-data";

export const dynamic = "force-static";

const COLUMNS = [
  "id",
  "aliases",
  "repository",
  "language",
  "published",
  "ai_tool",
  "ai_role",
  "root_cause",
  "summary",
  "url",
];

function cell(value: string): string {
  return /[",\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}

export function GET() {
  const rows = getResearchCases().map((item) => {
    const id = preferredCaseId(item);
    return [
      id,
      [item.case_id, ...item.aliases]
        .filter((value) => value !== id && /^(CVE|GHSA)-/i.test(value))
        .join(" "),
      item.repository ?? "",
      item.repository_metadata.language,
      item.published_at?.slice(0, 10) ?? "",
      getAiToolLabel(item),
      formatContributionClass(item.contribution_class),
      getCauseCategoryLabel(item.cause_category),
      getCaseHeadline(item),
      `${SITE_URL}/cves/${id}/`,
    ];
  });
  const body = [COLUMNS, ...rows]
    .map((row) => row.map(cell).join(","))
    .join("\n");
  return new Response(`${body}\n`, {
    headers: { "Content-Type": "text/csv; charset=utf-8" },
  });
}
