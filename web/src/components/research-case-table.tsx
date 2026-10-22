import Link from "next/link";

import { LanguageBadge } from "@/components/language-badge";
import { ToolIcon } from "@/components/tool-icon";
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
            <p className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
              <span className="break-all font-mono font-medium text-foreground">
                {formatCaseLabel(item, id)}
              </span>
              <span aria-hidden="true">·</span>
              <span className="break-all">
                {item.repository ?? "Not recorded"}
              </span>
              <span aria-hidden="true">·</span>
              <span className="[&>span]:text-xs">
                <LanguageBadge language={item.repository_metadata.language} />
              </span>
              <span aria-hidden="true">·</span>
              <span className="inline-flex items-center gap-1">
                <ToolIcon
                  tool={getAiFamilyIconKey(item.ai_provenance.family)}
                  size={13}
                />
                {aiToolLabel(item, labels)}
              </span>
              <span aria-hidden="true">·</span>
              <span>{formatContributionClass(item.contribution_class)}</span>
              <span aria-hidden="true">·</span>
              <span>{causeCategoryLabel(item.cause_category, labels)}</span>
              <span aria-hidden="true">·</span>
              <span className="tabular-nums">
                {item.published_at
                  ? `published ${item.published_at.slice(0, 10)}`
                  : "Date unavailable"}
              </span>
            </p>
          </li>
        );
      })}
    </ol>
  );
}
