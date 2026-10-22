import Link from "next/link";

import { LanguageBadge } from "@/components/language-badge";
import { SeverityLabel } from "@/components/severity-label";
import { ToolIcon } from "@/components/tool-icon";
import { formatDay } from "@/lib/month-utils";
import {
  aiToolLabel,
  causeCategoryLabel,
  formatCaseLabel,
  formatContributionClass,
  getAiFamilyIconKey,
  getCaseHeadline,
  preferredCaseId,
  type FindingRow,
  type ResearchLabels,
} from "@/lib/research-format";

export function ResearchCaseTable({
  cases,
  labels,
}: {
  readonly cases: readonly FindingRow[];
  readonly labels: ResearchLabels;
}) {
  return (
    <ol
      aria-label={`${cases.length} findings`}
      className="divide-y divide-border border-b border-border"
    >
      {cases.map((item) => {
        const id = preferredCaseId(item);
        return (
          <li key={item.case_id} data-finding={item.case_id} className="py-3.5">
            <Link
              href={`/cves/${id}`}
              className="line-clamp-2 font-semibold leading-6 [overflow-wrap:anywhere] hover:text-primary hover:underline"
            >
              {getCaseHeadline(item)}
            </Link>
            <p className="meta-list mt-1 text-xs text-muted-foreground">
              <span className="inline-flex items-center gap-2">
                <SeverityLabel severity={item.severity} />
                <span
                  className="break-all font-mono font-medium text-foreground"
                  title={formatCaseLabel(item, id)}
                >
                  {id}
                </span>
              </span>
              <span className="whitespace-nowrap">
                {item.published_at
                  ? formatDay(item.published_at)
                  : "Date unavailable"}
              </span>
              <span className="break-all">
                {item.repository ?? "Not recorded"}
              </span>
              <span className="hidden items-center sm:inline-flex [&>span]:text-xs">
                <LanguageBadge language={item.repository_metadata.language} />
              </span>
              <span className="inline-flex items-center gap-1">
                <ToolIcon
                  tool={getAiFamilyIconKey(item.ai_provenance.family)}
                  size={13}
                />
                {aiToolLabel(item, labels)}
              </span>
              <span>{formatContributionClass(item.contribution_class)}</span>
              <span className="hidden sm:inline">
                {causeCategoryLabel(item.cause_category, labels)}
              </span>
            </p>
          </li>
        );
      })}
    </ol>
  );
}
