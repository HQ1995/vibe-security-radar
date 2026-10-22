import Link from "next/link";

import { ToolIcon } from "@/components/tool-icon";
import { formatMonthShort } from "@/lib/month-utils";
import { getAiFamilyIconKey, type ResearchMonth } from "@/lib/research-data";

const TOOL_COLORS = [
  "var(--chart-1)",
  "var(--chart-2)",
  "var(--chart-3)",
  "var(--chart-4)",
  "var(--chart-5)",
];

interface ShareItem {
  readonly key: string;
  readonly label: string;
  readonly count: number;
}

function share(count: number, total: number): string {
  const value = (count / Math.max(1, total)) * 100;
  return value >= 10 || value === 0
    ? `${Math.round(value)}%`
    : `${value.toFixed(1)}%`;
}

export function OverviewPanel({
  timeline,
  tools,
  causes,
  sourceCutoff,
}: {
  readonly timeline: readonly ResearchMonth[];
  readonly tools: readonly ShareItem[];
  readonly causes: readonly ShareItem[];
  readonly sourceCutoff: string;
}) {
  const max = Math.max(1, ...timeline.map((month) => month.count)) * 1.2;
  const peak = timeline.reduce(
    (best, month) => (month.count > best.count ? month : best),
    timeline[0] ?? { month: "", count: 0 },
  );
  const cutoffMonth = sourceCutoff.slice(0, 7);
  const toolTotal = tools.reduce((sum, item) => sum + item.count, 0);
  const topCauses = causes
    .filter((item) => item.key !== "other_ambiguous")
    .slice(0, 4);
  const causeMax = Math.max(1, ...topCauses.map((item) => item.count));

  return (
    <section
      aria-label="At a glance"
      className="border-t border-border pt-5 lg:border-l lg:border-t-0 lg:pl-10 lg:pt-0"
    >
      <div className="flex items-baseline justify-between gap-3">
        <h2 className="text-sm font-semibold">Findings per month</h2>
        <Link
          href="#disclosure-trend"
          className="text-xs font-medium text-primary hover:underline"
        >
          Full trend ↓
        </Link>
      </div>
      <div
        className="mt-3 flex h-24 items-end gap-1 border-b border-border"
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
            {month.month === peak.month ? (
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
      <div className="mt-1.5 flex justify-between text-[11px] text-muted-foreground">
        <span>{timeline[0] ? formatMonthShort(timeline[0].month) : ""}</span>
        <span>
          Peak advisory month: {peak.month ? formatMonthShort(peak.month) : "—"}
        </span>
        <span>
          {timeline.at(-1) ? formatMonthShort(timeline.at(-1)!.month) : ""}
        </span>
      </div>

      <div className="mt-6 grid gap-6 border-t border-border pt-5 sm:grid-cols-2">
        <div className="min-w-0">
          <div className="flex items-baseline justify-between gap-3">
            <h2 className="text-sm font-semibold">AI tools</h2>
            <Link
              href="#patterns"
              className="text-xs font-medium text-primary hover:underline"
            >
              vs. commits ↓
            </Link>
          </div>
          <div className="mt-3 flex h-2.5 overflow-hidden rounded-full bg-muted">
            {tools.map((item, index) => (
              <span
                key={item.key}
                className="h-full border-r-2 border-background last:border-r-0"
                style={{
                  width: `${(item.count / Math.max(1, toolTotal)) * 100}%`,
                  background: TOOL_COLORS[index % TOOL_COLORS.length],
                }}
              />
            ))}
          </div>
          <ul className="mt-3 space-y-1.5 text-xs">
            {tools.slice(0, 4).map((item, index) => (
              <li
                key={item.key}
                className="flex items-center justify-between gap-2"
              >
                <span className="flex min-w-0 items-center gap-1.5">
                  <span
                    aria-hidden="true"
                    className="h-2 w-2 shrink-0 rounded-[2px]"
                    style={{
                      background: TOOL_COLORS[index % TOOL_COLORS.length],
                    }}
                  />
                  <ToolIcon tool={getAiFamilyIconKey(item.key)} size={14} />
                  <span className="truncate">{item.label}</span>
                </span>
                <span className="shrink-0 tabular-nums text-muted-foreground">
                  {share(item.count, toolTotal)}
                </span>
              </li>
            ))}
          </ul>
          <p className="mt-2 text-[11px] text-muted-foreground">
            Most common AI tool among findings that name one.
          </p>
        </div>
        <div className="min-w-0">
          <div className="flex items-baseline justify-between gap-3">
            <h2 className="text-sm font-semibold">Root causes</h2>
            <Link
              href="#patterns"
              className="text-xs font-medium text-primary hover:underline"
            >
              All ↓
            </Link>
          </div>
          <ul className="mt-3 space-y-2.5 text-xs">
            {topCauses.map((item) => (
              <li key={item.key}>
                <Link
                  href={`/cves?${new URLSearchParams({ cause: item.key })}`}
                  className="group block"
                >
                  <span className="flex items-baseline justify-between gap-2">
                    <span className="truncate group-hover:text-primary">
                      {item.label}
                    </span>
                    <span className="shrink-0 tabular-nums text-muted-foreground">
                      {item.count}
                    </span>
                  </span>
                  <span className="mt-1 block h-1.5 overflow-hidden rounded-full bg-muted">
                    <span
                      className="block h-full rounded-full bg-primary"
                      style={{ width: `${(item.count / causeMax) * 100}%` }}
                    />
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}
