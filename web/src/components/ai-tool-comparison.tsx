import Link from "next/link";

import { ToolIcon } from "@/components/tool-icon";
import {
  getAiFamilyIconKey,
  getAiToolBaseRate,
  getAiToolDistribution,
} from "@/lib/research-data";

const pct = (value: number) =>
  value >= 0.1 || value === 0
    ? `${Math.round(value * 100)}%`
    : `${(value * 100).toFixed(1)}%`;

export function AiToolComparison() {
  const tools = getAiToolDistribution();
  const rate = getAiToolBaseRate();
  const named = tools.items.reduce((sum, item) => sum + item.count, 0);
  const commitShare = new Map(
    rate.rows.map((row) => [row.key, row.ai_commit_share]),
  );
  const rows = tools.items.map((item) => ({
    ...item,
    findingShare: item.count / Math.max(1, named),
    commitShare: rate.unavailable ? null : (commitShare.get(item.key) ?? 0),
  }));

  return (
    <section>
      <h3 className="text-base font-semibold">AI tools</h3>
      <p className="mt-1 text-sm leading-6 text-muted-foreground">
        {`${tools.coverage.complete} of ${tools.total} findings name the tool on every AI-assisted change.`}
        {rate.unavailable
          ? " Commit shares are hidden until the commit census is regenerated for the same repositories and window."
          : ` Gray bars show each tool's share of the ${rate.markedAiCommits.toLocaleString("en-US")} AI-marked commits in the same repositories and window.`}
      </p>
      {rate.unavailable ? null : (
        <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
          <span className="inline-flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-[2px] bg-primary" />
            Share of findings
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-[2px] bg-muted-foreground/45" />
            Share of AI-marked commits
          </span>
        </div>
      )}
      <ol className="mt-3 space-y-1">
        {rows.map((row) => (
          <li key={row.key}>
            <Link
              href={`/cves?${new URLSearchParams({ tool: row.label })}`}
              className="group -mx-2 block rounded-md px-2 py-1.5 transition-colors hover:bg-card"
            >
              <div className="flex items-center justify-between gap-3 text-sm">
                <span className="flex min-w-0 items-center gap-2">
                  <span
                    aria-hidden="true"
                    className="flex w-5 shrink-0 justify-center"
                  >
                    <ToolIcon tool={getAiFamilyIconKey(row.key)} size={18} />
                  </span>
                  <span className="truncate font-medium group-hover:text-primary">
                    {row.label}
                  </span>
                </span>
                <span className="shrink-0 tabular-nums text-muted-foreground">
                  {row.count} {row.count === 1 ? "finding" : "findings"}
                </span>
              </div>
              <div className="mt-1.5 grid grid-cols-[minmax(0,1fr)_3rem] items-center gap-x-3 gap-y-1 text-xs tabular-nums">
                <div className="h-2 overflow-hidden rounded-full bg-muted">
                  <div
                    className="h-full rounded-full bg-primary"
                    style={{ width: `${row.findingShare * 100}%` }}
                    role="img"
                    aria-label={`${row.label}: ${pct(row.findingShare)} of findings that name a tool`}
                  />
                </div>
                <span className="text-right">{pct(row.findingShare)}</span>
                {row.commitShare === null ? null : (
                  <>
                    <div className="h-2 overflow-hidden rounded-full bg-muted">
                      <div
                        className="h-full rounded-full bg-muted-foreground/45"
                        style={{ width: `${row.commitShare * 100}%` }}
                        role="img"
                        aria-label={`${row.label}: ${pct(row.commitShare)} of AI-marked commits`}
                      />
                    </div>
                    <span className="text-right text-muted-foreground">
                      {pct(row.commitShare)}
                    </span>
                  </>
                )}
              </div>
            </Link>
          </li>
        ))}
      </ol>
      {rate.unavailable ? null : (
        <details className="mt-4 text-xs leading-5 text-muted-foreground">
          <summary className="cursor-pointer text-primary hover:underline">
            Why some tools look over-represented
          </summary>
          <p className="mt-2">
            Claude self-marks nearly every commit; GPT/Codex and Cursor usually
            leave no marker, so their commit shares are floors. A findings share
            above the commit share is an upper bound, not proof a tool writes
            worse code. Shares that match mean findings track usage.
          </p>
        </details>
      )}
    </section>
  );
}
