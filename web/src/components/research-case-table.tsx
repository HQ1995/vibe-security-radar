import Link from "next/link";

import { LanguageBadge } from "@/components/language-badge";
import { ToolIcon } from "@/components/tool-icon";
import {
  formatCaseLabel,
  formatContributionClass,
  formatPublicationStatus,
  getAiFamilyIconKey,
  getAiToolLabel,
  getCauseCategoryLabel,
  preferredCaseId,
  type ResearchCase,
} from "@/lib/research-data";

export function ResearchCaseTable({
  cases,
}: {
  readonly cases: readonly ResearchCase[];
}) {
  return (
    <>
      <ul className="grid gap-3 border-y border-border py-4 sm:grid-cols-2 xl:hidden">
        {cases.map((item) => {
          const id = preferredCaseId(item);
          return (
            <li key={item.case_id} className="border border-border bg-card p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <Link
                    href={`/cves/${id}`}
                    className="font-mono text-sm font-semibold text-primary hover:underline"
                  >
                    {formatCaseLabel(item, id)}
                  </Link>
                </div>
                <span className="shrink-0 font-mono text-[10px] text-muted-foreground">
                  {item.published_at?.slice(0, 10) ?? "Date unavailable"}
                </span>
              </div>
              <p className="mt-4 break-words text-sm font-medium">
                {item.repository ?? "Not recorded"}
              </p>
              <p className="mt-1 text-xs font-medium text-primary">
                {formatPublicationStatus(item.publication_status)}
              </p>
              <dl className="mt-4 grid grid-cols-2 gap-x-4 gap-y-3 text-xs">
                <div>
                  <dt className="text-muted-foreground">Root cause</dt>
                  <dd className="mt-1">
                    {getCauseCategoryLabel(item.cause_category)}
                  </dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">AI contribution</dt>
                  <dd className="mt-1">
                    {formatContributionClass(item.contribution_class)}
                  </dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Language</dt>
                  <dd className="mt-1">
                    <LanguageBadge
                      language={item.repository_metadata.language}
                    />
                  </dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">AI tool</dt>
                  <dd className="mt-1 flex items-center gap-1.5">
                    <ToolIcon
                      tool={getAiFamilyIconKey(item.ai_provenance.family)}
                      size={16}
                    />
                    <span>{getAiToolLabel(item)}</span>
                  </dd>
                </div>
              </dl>
            </li>
          );
        })}
      </ul>
      <div className="hidden overflow-x-auto border-y border-border xl:block">
        <table className="w-full min-w-[1080px] text-left">
          <caption className="sr-only">
            All {cases.length} findings
          </caption>
          <thead>
            <tr className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
              <th className="py-3 pr-4 font-medium">Advisory</th>
              <th className="px-4 py-3 font-medium">Repository</th>
              <th className="px-4 py-3 font-medium">Language</th>
              <th className="px-4 py-3 font-medium">Root cause</th>
              <th className="px-4 py-3 font-medium">AI contribution</th>
              <th className="px-4 py-3 font-medium">AI tool</th>
              <th className="px-4 py-3 font-medium">Verification</th>
              <th className="py-3 pl-4 text-right font-medium">Published</th>
            </tr>
          </thead>
          <tbody>
            {cases.map((item) => {
              const id = preferredCaseId(item);
              return (
                <tr
                  key={item.case_id}
                  className="border-t border-border align-top"
                >
                  <td className="py-4 pr-4">
                    <Link
                      href={`/cves/${id}`}
                      className="font-mono text-sm font-medium text-primary hover:underline"
                    >
                      {formatCaseLabel(item, id)}
                    </Link>
                  </td>
                  <td className="px-4 py-4 text-sm">
                    {item.repository ?? "Not recorded"}
                  </td>
                  <td className="px-4 py-4 text-sm">
                    <LanguageBadge
                      language={item.repository_metadata.language}
                    />
                  </td>
                  <td className="px-4 py-4 text-sm">
                    {getCauseCategoryLabel(item.cause_category)}
                  </td>
                  <td className="px-4 py-4 text-sm">
                    {formatContributionClass(item.contribution_class)}
                  </td>
                  <td className="px-4 py-4 text-sm text-muted-foreground">
                    <span className="inline-flex items-center gap-2">
                      <ToolIcon
                        tool={getAiFamilyIconKey(item.ai_provenance.family)}
                        size={16}
                      />
                      {getAiToolLabel(item)}
                    </span>
                  </td>
                  <td className="px-4 py-4 text-sm font-medium text-primary">
                    {formatPublicationStatus(item.publication_status)}
                  </td>
                  <td className="py-4 pl-4 text-right font-mono text-xs">
                    {item.published_at?.slice(0, 10) ?? "Date unavailable"}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </>
  );
}
