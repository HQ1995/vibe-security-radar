"use client";

import Link from "next/link";
import { useState } from "react";

import { formatDay, formatMonthShort } from "@/lib/month-utils";
import type { ResearchMonth } from "@/lib/research-data";

export interface TrendSeries {
  readonly key: string;
  readonly label: string;
  readonly counts: readonly number[];
}

export interface TrendBreakdown {
  readonly key: string;
  readonly label: string;
  readonly series: readonly TrendSeries[];
}

export interface TrendChartProps {
  readonly data: readonly ResearchMonth[];
  readonly caseCount: number;
  readonly datedCount: number;
  readonly unknownDateCount: number;
  readonly sourceCutoff: string;
  readonly breakdowns?: readonly TrendBreakdown[];
}

const SERIES_COLORS = [
  "var(--chart-1)",
  "var(--chart-2)",
  "var(--chart-3)",
  "var(--chart-4)",
  "var(--chart-5)",
];

function seriesColor(series: TrendSeries, index: number): string {
  return series.key === "other"
    ? "color-mix(in srgb, var(--muted-foreground) 45%, transparent)"
    : SERIES_COLORS[index % SERIES_COLORS.length];
}

interface AxisLabel {
  readonly month: string;
  readonly year: string | null;
}

function niceTicks(max: number): number[] {
  const raw = Math.max(1, max) / 4;
  const power = 10 ** Math.floor(Math.log10(raw));
  const step = Math.max(
    1,
    [1, 2, 5, 10].map((m) => m * power).find((value) => value >= raw) ?? raw,
  );
  const top = Math.max(step, Math.ceil(max / step) * step);
  const ticks: number[] = [];
  for (let tick = 0; tick <= top; tick += step) ticks.push(tick);
  return ticks;
}

function axisLabels(data: readonly ResearchMonth[]): (AxisLabel | null)[] {
  const interval = data.length <= 24 ? 3 : data.length <= 60 ? 6 : 12;
  const starts = data.map(
    (entry) => (Number(entry.month.slice(5, 7)) - 1) % interval === 0,
  );
  const firstStart = starts.indexOf(true);
  const show = data.map(
    (_, index) =>
      starts[index] || (index === 0 && (firstStart === -1 || firstStart >= 2)),
  );
  let lastYear: string | null = null;
  return data.map((entry, index) => {
    if (!show[index]) return null;
    const year = entry.month.slice(0, 4);
    const label = {
      month: formatMonthShort(entry.month).slice(0, 3),
      year: year === lastYear ? null : year,
    };
    lastYear = year;
    return label;
  });
}

function percent(value: number): string {
  return `${Math.round(value * 100)}%`;
}

function findings(count: number): string {
  return `${count} ${count === 1 ? "finding" : "findings"}`;
}

const AXIS = "grid grid-cols-[2rem_minmax(0,1fr)] gap-x-2";

export function TrendChart({
  data,
  caseCount,
  datedCount,
  unknownDateCount,
  sourceCutoff,
  breakdowns = [],
}: TrendChartProps) {
  const [view, setView] = useState<"chart" | "table">("chart");
  const [mode, setMode] = useState("total");
  const breakdown = breakdowns.find((item) => item.key === mode) ?? null;
  const [active, setActive] = useState<number | null>(null);
  const [hovering, setHovering] = useState(false);
  const maxCount = Math.max(1, ...data.map((entry) => entry.count));
  const ticks = niceTicks(maxCount);
  const scaleMax = ticks.at(-1)!;
  const peakIndex = data.reduce(
    (best, entry, index) => (entry.count > data[best].count ? index : best),
    0,
  );
  const labels = axisLabels(data);
  const shareOf = (entry: ResearchMonth) =>
    entry.advisories ? (entry.researched ?? 0) / entry.advisories : null;
  const shares = data
    .map(shareOf)
    .filter((value): value is number => value !== null);
  const hasCoverage = shares.length > 0;
  const shareMax = Math.max(0.2, Math.ceil(Math.max(0, ...shares) * 20) / 20);
  const coverageRange = hasCoverage
    ? `${percent(Math.min(...shares))}–${percent(Math.max(...shares))}`
    : "";
  const cutoffMonth = sourceCutoff.slice(0, 7);
  const [cutoffYear, cutoffMonthNumber, cutoffDay] = sourceCutoff
    .slice(0, 10)
    .split("-")
    .map(Number);
  const cutoffIsPartial =
    data.some((entry) => entry.month === cutoffMonth) &&
    cutoffDay <
      new Date(Date.UTC(cutoffYear, cutoffMonthNumber, 0)).getUTCDate();
  const columns = data.map((entry, index) => {
    const share = shareOf(entry);
    const name = formatMonthShort(entry.month);
    return {
      ...entry,
      index,
      name,
      height: entry.count > 0 ? Math.max(1, (entry.count / scaleMax) * 100) : 0,
      share,
      shareHeight:
        share && share > 0 ? Math.max(4, (share / shareMax) * 100) : 0,
      partial: cutoffIsPartial && entry.month === cutoffMonth,
      label: labels[index],
      title: `${name}: ${findings(entry.count)}${share === null ? "" : `, ${percent(share)} of ${entry.advisories?.toLocaleString("en-US")} advisories researched`}`,
    };
  });
  const focused = active === null ? null : columns[active];
  const range = data.length
    ? `${formatMonthShort(data[0].month)} – ${formatMonthShort(data.at(-1)!.month)}`
    : "";
  const hover = (index: number) => ({
    onPointerEnter: () => setActive(index),
    onClick: () => setActive(index),
  });
  const dimmed = (index: number) =>
    hovering && active !== null && active !== index;

  return (
    <section id="disclosure-trend" className="scroll-mt-20">
      <div className="flex flex-wrap items-end justify-between gap-x-6 gap-y-3">
        <div className="min-w-0">
          <h2 className="text-xl font-semibold tracking-[-0.02em] sm:text-2xl">
            Disclosures over time
          </h2>
          <p className="mt-1 text-sm leading-6 text-muted-foreground">
            {datedCount === caseCount
              ? `${caseCount} findings`
              : `${datedCount} of ${caseCount} findings`}{" "}
            by advisory publication month{range ? `, ${range}` : ""}. Data
            through {formatDay(sourceCutoff)}.
            {unknownDateCount
              ? ` ${unknownDateCount} findings without an advisory date are not shown.`
              : ""}
          </p>
        </div>
        {columns.length ? (
          <div className="flex shrink-0 flex-wrap items-end gap-x-5 gap-y-2">
            {breakdowns.length ? (
              <label className="flex items-center gap-2 text-sm text-muted-foreground">
                Break down by
                <select
                  value={mode}
                  onChange={(event) => setMode(event.target.value)}
                  className="h-8 rounded-md border border-input bg-card px-2 text-sm text-foreground outline-none focus:border-primary focus:ring-2 focus:ring-primary/15"
                >
                  <option value="total">Total</option>
                  {breakdowns.map((item) => (
                    <option key={item.key} value={item.key}>
                      {item.label}
                    </option>
                  ))}
                </select>
              </label>
            ) : null}
            <div className="flex shrink-0 gap-4 border-b border-border text-sm">
              {(["chart", "table"] as const).map((option) => (
                <button
                  key={option}
                  type="button"
                  aria-pressed={view === option}
                  onClick={() => setView(option)}
                  className={`-mb-px border-b-2 pb-1.5 font-medium transition-colors ${
                    view === option
                      ? "border-foreground text-foreground"
                      : "border-transparent text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {option === "chart" ? "Chart" : "Table"}
                </button>
              ))}
            </div>
          </div>
        ) : null}
      </div>

      {!columns.length ? (
        <p className="py-10 text-sm text-muted-foreground">
          No exact first-party advisory dates are available.
        </p>
      ) : null}

      {columns.length && view === "chart" ? (
        <div
          className="mt-5"
          onPointerEnter={() => setHovering(true)}
          onPointerLeave={() => setHovering(false)}
        >
          <div className={AXIS}>
            <span />
            <div className="mb-2 flex min-h-5 flex-wrap items-baseline justify-between gap-x-4 text-xs">
              <span className="font-medium text-foreground">
                Findings per month
              </span>
              <span className="text-muted-foreground">
                {focused ? (
                  <>
                    <span className="font-semibold text-foreground">
                      {focused.name}
                      {focused.partial ? "*" : ""}
                    </span>
                    {` · ${findings(focused.count)}`}
                    {breakdown
                      ? `: ${breakdown.series
                          .filter((series) => series.counts[focused.index])
                          .map(
                            (series) =>
                              `${series.label} ${series.counts[focused.index]}`,
                          )
                          .join(", ")}`
                      : focused.share === null
                        ? ""
                        : ` · ${percent(focused.share)} of ${focused.advisories?.toLocaleString("en-US")} researched`}
                    {focused.count ? (
                      <Link
                        href={`/cves?month=${focused.month}`}
                        className="ml-2 font-medium text-primary hover:underline"
                      >
                        View findings →
                      </Link>
                    ) : null}
                  </>
                ) : (
                  "Hover or tap a month for details"
                )}
              </span>
            </div>
          </div>
          {breakdown ? (
            <div className={AXIS}>
              <span />
              <ul className="mb-3 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
                {breakdown.series.map((series, index) => (
                  <li key={series.key} className="flex items-center gap-1.5">
                    <span
                      aria-hidden="true"
                      className="h-2.5 w-2.5 rounded-[2px]"
                      style={{ background: seriesColor(series, index) }}
                    />
                    {series.label}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          <div className={AXIS} aria-hidden="true">
            <div className="relative h-44 sm:h-56">
              {ticks.map((tick) => (
                <span
                  key={tick}
                  className="absolute right-0 translate-y-1/2 text-[11px] leading-none tabular-nums text-muted-foreground"
                  style={{ bottom: `${(tick / scaleMax) * 100}%` }}
                >
                  {tick}
                </span>
              ))}
            </div>
            <div className="relative h-44 border-b border-muted-foreground/40 sm:h-56">
              {ticks.slice(1).map((tick) => (
                <div
                  key={tick}
                  className="absolute inset-x-0 border-t border-border"
                  style={{ bottom: `${(tick / scaleMax) * 100}%` }}
                />
              ))}
              <div className="absolute inset-0 flex">
                {columns.map((column) => (
                  <div
                    key={column.month}
                    {...hover(column.index)}
                    className={`relative flex h-full min-w-0 flex-1 items-end justify-center ${
                      active === column.index ? "bg-foreground/[0.04]" : ""
                    }`}
                  >
                    {column.index === peakIndex ? (
                      <span
                        className="absolute left-1/2 -translate-x-1/2 -translate-y-1 text-[11px] font-semibold tabular-nums"
                        style={{ bottom: `${column.height}%` }}
                      >
                        {column.count}
                      </span>
                    ) : null}
                    {column.height && breakdown ? (
                      <span
                        className={`flex w-[62%] max-w-6 flex-col-reverse gap-[2px] overflow-hidden rounded-t-[4px] transition-opacity ${
                          dimmed(column.index)
                            ? "opacity-60"
                            : column.partial
                              ? "opacity-45"
                              : ""
                        }`}
                        style={{ height: `${column.height}%` }}
                      >
                        {breakdown.series.map((series, index) =>
                          series.counts[column.index] ? (
                            <span
                              key={series.key}
                              className="block w-full"
                              style={{
                                flexGrow: series.counts[column.index],
                                flexBasis: 0,
                                background: seriesColor(series, index),
                              }}
                            />
                          ) : null,
                        )}
                      </span>
                    ) : column.height ? (
                      <span
                        className={`w-[62%] max-w-6 rounded-t-[4px] bg-primary transition-opacity ${
                          dimmed(column.index)
                            ? column.partial
                              ? "opacity-30"
                              : "opacity-60"
                            : column.partial
                              ? "opacity-45"
                              : ""
                        }`}
                        style={{ height: `${column.height}%` }}
                      />
                    ) : null}
                  </div>
                ))}
              </div>
            </div>
          </div>

          {hasCoverage ? (
            <div className={`${AXIS} mt-5`} aria-hidden="true">
              <span />
              <p className="mb-2 text-xs font-medium text-foreground">
                Share of the month&apos;s advisories researched
              </p>
              <div className="relative h-10">
                <span className="absolute right-0 top-0 -translate-y-1/2 text-[11px] leading-none tabular-nums text-muted-foreground">
                  {percent(shareMax)}
                </span>
                <span className="absolute bottom-0 right-0 translate-y-1/2 text-[11px] leading-none tabular-nums text-muted-foreground">
                  0
                </span>
              </div>
              <div className="relative flex h-10 border-y border-b-muted-foreground/40 border-t-border">
                {columns.map((column) => (
                  <div
                    key={column.month}
                    {...hover(column.index)}
                    className={`flex h-full min-w-0 flex-1 items-end justify-center ${
                      active === column.index ? "bg-foreground/[0.04]" : ""
                    }`}
                  >
                    {column.shareHeight ? (
                      <span
                        className="w-[62%] max-w-6 rounded-t-[3px] bg-muted-foreground/45"
                        style={{ height: `${column.shareHeight}%` }}
                      />
                    ) : null}
                  </div>
                ))}
              </div>
            </div>
          ) : null}

          <div className={AXIS} aria-hidden="true">
            <span />
            <div className="flex pt-1.5 text-[11px] leading-tight text-muted-foreground">
              {columns.map((column) => (
                <div
                  key={column.month}
                  className="flex min-w-0 flex-1 flex-col items-center overflow-visible whitespace-nowrap"
                >
                  {column.label ? (
                    <>
                      <span>
                        {column.label.month}
                        {column.partial ? "*" : ""}
                      </span>
                      {column.label.year ? (
                        <span>{column.label.year}</span>
                      ) : null}
                    </>
                  ) : null}
                </div>
              ))}
            </div>
          </div>
        </div>
      ) : null}

      {columns.length ? (
        <div
          className={
            view === "table"
              ? `mt-5 overflow-x-auto ${breakdown ? "" : "max-w-xl"}`
              : "sr-only"
          }
        >
          <table className="w-full text-sm">
            <caption className="sr-only">
              Findings by advisory publication month
            </caption>
            <thead>
              <tr className="border-b border-border text-xs text-muted-foreground">
                <th className="py-2 text-left font-medium">Month</th>
                <th className="py-2 text-right font-medium">Findings</th>
                {breakdown
                  ? breakdown.series.map((series) => (
                      <th
                        key={series.key}
                        className="py-2 pl-3 text-right font-medium"
                      >
                        {series.label}
                      </th>
                    ))
                  : null}
                {hasCoverage ? (
                  <th className="py-2 text-right font-medium">
                    Advisories researched
                  </th>
                ) : null}
              </tr>
            </thead>
            <tbody>
              {columns.map((column) => (
                <tr
                  key={column.month}
                  title={column.title}
                  className="border-b border-border/70"
                >
                  <td className="py-1.5">
                    {column.count ? (
                      <Link
                        href={`/cves?month=${column.month}`}
                        className="text-primary hover:underline"
                      >
                        {column.name}
                        {column.partial ? "*" : ""}
                      </Link>
                    ) : (
                      <>
                        {column.name}
                        {column.partial ? "*" : ""}
                      </>
                    )}
                  </td>
                  <td className="py-1.5 text-right tabular-nums">
                    {column.count}
                  </td>
                  {breakdown
                    ? breakdown.series.map((series) => (
                        <td
                          key={series.key}
                          className="py-1.5 pl-3 text-right tabular-nums text-muted-foreground"
                        >
                          {series.counts[column.index]}
                        </td>
                      ))
                    : null}
                  {hasCoverage ? (
                    <td className="py-1.5 text-right tabular-nums text-muted-foreground">
                      {column.share === null
                        ? "–"
                        : `${percent(column.share)} of ${column.advisories?.toLocaleString("en-US")}`}
                    </td>
                  ) : null}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {hasCoverage ? (
        <p className="mt-4 max-w-3xl text-sm leading-6 text-muted-foreground">
          <span className="font-medium text-foreground">Note: </span>
          {`Only ${coverageRange} of each month's advisories have been researched so far, so a short bar can mean little research rather than few AI-caused vulnerabilities.`}
        </p>
      ) : null}
      {cutoffIsPartial ? (
        <p className="mt-3 text-xs text-muted-foreground">
          * {formatMonthShort(cutoffMonth)} is partial, so its bar is lighter.
        </p>
      ) : null}
    </section>
  );
}
