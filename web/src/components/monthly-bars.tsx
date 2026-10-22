import { formatMonthShort } from "@/lib/month-utils";
import type { ResearchMonth } from "@/lib/research-data";

export function MonthlyBars({
  timeline,
  sourceCutoff,
  className = "h-24",
}: {
  readonly timeline: readonly ResearchMonth[];
  readonly sourceCutoff: string;
  readonly className?: string;
}) {
  const max = Math.max(1, ...timeline.map((month) => month.count)) * 1.2;
  const peak = timeline.reduce(
    (best, month) => (month.count > best.count ? month : best),
    timeline[0] ?? { month: "", count: 0 },
  );
  const cutoffMonth = sourceCutoff.slice(0, 7);

  return (
    <>
      <div
        className={`mt-3 flex items-end gap-1 border-b border-border ${className}`}
        role="img"
        aria-label={timeline
          .map((month) => `${formatMonthShort(month.month)}: ${month.count}`)
          .join(", ")}
      >
        {timeline.map((month) => (
          <div
            key={month.month}
            className="relative flex h-full min-w-0 flex-1 items-end justify-center"
          >
            {month.month === peak.month && month.count ? (
              <span
                className="absolute left-1/2 -translate-x-1/2 -translate-y-1 text-[10px] font-semibold tabular-nums"
                style={{ bottom: `${(month.count / max) * 100}%` }}
              >
                {month.count}
              </span>
            ) : null}
            {month.count ? (
              <span
                className={`w-full max-w-5 rounded-t-[3px] bg-primary ${
                  month.month === cutoffMonth ? "opacity-45" : ""
                }`}
                style={{ height: `${Math.max(3, (month.count / max) * 100)}%` }}
              />
            ) : null}
          </div>
        ))}
      </div>
      <div className="mt-1.5 flex justify-between gap-2 text-[11px] text-muted-foreground">
        <span>{timeline[0] ? formatMonthShort(timeline[0].month) : ""}</span>
        <span>
          Peak advisory month: {peak.count ? formatMonthShort(peak.month) : "—"}
        </span>
        <span>
          {timeline.at(-1) ? formatMonthShort(timeline.at(-1)!.month) : ""}
        </span>
      </div>
    </>
  );
}
