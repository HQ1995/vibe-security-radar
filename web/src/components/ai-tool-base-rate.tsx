import { getAiToolBaseRate, getAiFamilyIconKey } from "@/lib/research-data";
import { ToolIcon } from "@/components/tool-icon";

const pct = (value: number) => `${(value * 100).toFixed(1)}%`;

export function AiToolBaseRate() {
  const rate = getAiToolBaseRate();
  if (rate.unavailable) {
    return (
      <section className="border-t border-border pt-4">
        <p className="section-kicker">Commit denominator</p>
        <h3 className="mt-2 text-xl font-semibold tracking-[-0.025em]">
          Measurement paused
        </h3>
        <p className="mt-1.5 text-xs leading-5 text-muted-foreground">
          Tool ratios are hidden until the commit census is regenerated for
          the same repositories and disclosure window as this dataset.
        </p>
      </section>
    );
  }
  const max = Math.max(1, ...rate.rows.map((row) => row.ai_commit_share));

  return (
    <section className="border-t border-border pt-4">
      <p className="section-kicker">Base rate sibling</p>
      <h3 className="mt-2 text-xl font-semibold tracking-[-0.025em]">
        Share of AI-marked commits
      </h3>
      <p className="mt-1.5 text-xs leading-5 text-muted-foreground">
        {rate.markedAiCommits.toLocaleString()} AI-marked of{" "}
        {rate.totalCommits.toLocaleString()} commits, same repos and window.
        Absolute case counts mean nothing without this denominator.
      </p>
      <ol className="mt-4 space-y-3">
        {rate.rows.map((row) => (
          <li key={row.key}>
            <div className="mb-1 flex items-baseline justify-between gap-3 text-xs leading-4">
              <span className="flex min-w-0 items-center gap-2">
                <span aria-hidden="true" className="flex w-5 shrink-0 justify-center">
                  <ToolIcon tool={getAiFamilyIconKey(row.key)} size={20} />
                </span>
                <span className="truncate">{row.label}</span>
              </span>
              <span className="shrink-0 font-mono text-xs tabular-nums">
                {pct(row.ai_commit_share)} commits
              </span>
            </div>
            <div className="h-1.5 overflow-hidden bg-muted">
              <div
                className="h-full bg-muted-foreground/45"
                style={{ width: `${(row.ai_commit_share / max) * 100}%` }}
                role="img"
                aria-label={`${row.label}: ${pct(row.ai_commit_share)} of AI-marked commits`}
              />
            </div>
            <p className="mt-1 min-w-0 truncate text-[11px] leading-4 text-muted-foreground">
              cases {pct(row.case_share)} ({row.cases}) ·{" "}
              {row.ratio === null
                ? "no marked commits"
                : `${row.ratio.toFixed(2)}× cases vs commits`}
            </p>
          </li>
        ))}
      </ol>
      <details className="mt-4 border-t border-border pt-3 text-[11px] leading-4 text-muted-foreground">
        <summary className="cursor-pointer text-primary hover:underline">
          Why some tools look over-represented
        </summary>
        <p className="mt-2">
          Claude self-marks nearly every commit; GPT/Codex and Cursor usually
          leave no marker, so their shares are floors and ratios above 1× are
          upper bounds, not proof a tool writes worse code. A ratio near 1×
          means cases track usage.
        </p>
      </details>
    </section>
  );
}
