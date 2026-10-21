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
      className="divide-y divide-border border-y border-border"
    >
      {cases.map((item) => {
        const id = preferredCaseId(item);
        return (
          <li key={item.case_id} data-finding={item.case_id}>
            <Link
              href={`/cves/${id}`}
              className="group grid gap-x-8 gap-y-2 px-1 py-4 transition-colors hover:bg-card lg:grid-cols-[minmax(0,1fr)_15rem] lg:px-3"
            >
              <div className="min-w-0">
                <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 text-xs">
                  <span className="break-all font-mono font-medium text-primary">
                    {formatCaseLabel(item, id)}
                  </span>
                  <span className="tabular-nums text-muted-foreground">
                    {item.published_at?.slice(0, 10) ?? "Date unavailable"}
                  </span>
                </div>
                <p className="mt-1.5 line-clamp-2 font-medium leading-6 [overflow-wrap:anywhere] group-hover:text-primary">
                  {getCaseHeadline(item)}
                </p>
                <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
                  <span className="min-w-0 break-all text-foreground">
                    {item.repository ?? "Not recorded"}
                  </span>
                  <span className="[&>span]:text-xs">
                    <LanguageBadge
                      language={item.repository_metadata.language}
                    />
                  </span>
                  <span>{causeCategoryLabel(item.cause_category, labels)}</span>
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs lg:flex-col lg:items-start lg:justify-center">
                <span className="inline-flex items-center gap-1.5 font-medium">
                  <ToolIcon
                    tool={getAiFamilyIconKey(item.ai_provenance.family)}
                    size={16}
                  />
                  {aiToolLabel(item, labels)}
                </span>
                <span className="rounded-full bg-accent px-2 py-0.5 font-medium text-accent-foreground">
                  {formatContributionClass(item.contribution_class)}
                </span>
              </div>
            </Link>
          </li>
        );
      })}
    </ol>
  );
}
