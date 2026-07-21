"use client";

import * as React from "react";
import Image from "next/image";
import Link from "next/link";
import { Cell, Label, Pie, PieChart } from "recharts";
import { getIconDimensions } from "@/components/tool-icon";

import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

interface DistributionPieChartProps {
  readonly title: string;
  readonly data: Readonly<Record<string, number>>;
  readonly getColor: (key: string) => string;
  readonly getName?: (key: string) => string;
  /** Builds the filtered-list URL for a legend row (e.g. /cves?tool=<id>). */
  readonly getHref: (key: string) => string;
  readonly iconDir?: string;
  readonly getIconKey?: (key: string) => string | null;
  readonly themedIcons?: ReadonlySet<string>;
  /** Override the center total (e.g. unique CVE count instead of sum of slices). */
  readonly totalOverride?: number;
}

interface ChartEntry {
  key: string;
  name: string;
  value: number;
  fill: string;
}

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

export function DistributionPieChart({
  title,
  data,
  getColor,
  getName = (k) => k,
  getHref,
  iconDir,
  getIconKey = (k) => k,
  themedIcons = new Set(),
  totalOverride,
}: DistributionPieChartProps) {
  const [activeIndex, setActiveIndex] = React.useState<number | undefined>(
    undefined,
  );

  const chartData: ChartEntry[] = React.useMemo(
    () =>
      Object.entries(data)
        .map(([key, count]) => ({
          key,
          name: getName(key),
          value: count,
          fill: getColor(key),
        }))
        .sort((a, b) => b.value - a.value),
    [data, getColor, getName],
  );

  const total = React.useMemo(
    () => chartData.reduce((sum, d) => sum + d.value, 0),
    [chartData],
  );

  const activeItem = activeIndex !== undefined ? chartData[activeIndex] : null;

  // Build chartConfig for shadcn ChartTooltip
  const chartConfig: ChartConfig = React.useMemo(() => {
    const cfg: ChartConfig = {};
    for (const entry of chartData) {
      cfg[entry.key] = { label: entry.name, color: entry.fill };
    }
    return cfg;
  }, [chartData]);

  // Screen-reader summary, e.g. "Tool Distribution: Claude Code 46 (71%), …"
  const ariaLabel = React.useMemo(
    () =>
      `${title}: ` +
      chartData
        .map((entry) => {
          const pct =
            total > 0 ? Math.round((entry.value / total) * 100) : 0;
          return `${entry.name} ${entry.value} (${pct}%)`;
        })
        .join(", "),
    [title, chartData, total],
  );

  return (
    <section>
      <h2 className="mb-4 text-xl font-semibold">{title}</h2>
      <div className="rounded-xl border border-border bg-card p-6">
        <div className="flex flex-col items-center gap-8 lg:flex-row lg:justify-center">
          {/* ---- Donut ---- */}
          <ChartContainer
            config={chartConfig}
            className="aspect-square h-[280px] shrink-0"
            role="img"
            aria-label={ariaLabel}
          >
            <PieChart>
              <ChartTooltip
                cursor={false}
                content={<ChartTooltipContent hideLabel nameKey="key" />}
              />
              <Pie
                data={chartData}
                dataKey="value"
                nameKey="key"
                cx="50%"
                cy="50%"
                innerRadius={70}
                outerRadius={110}
                paddingAngle={3}
                cornerRadius={4}
                strokeWidth={2}
                stroke="var(--color-card)"
                isAnimationActive={false}
                onMouseEnter={(_, index) => setActiveIndex(index)}
                onMouseLeave={() => setActiveIndex(undefined)}
              >
                {chartData.map((entry, i) => (
                  <Cell
                    key={entry.key}
                    fill={entry.fill}
                    opacity={
                      activeIndex === undefined || activeIndex === i ? 1 : 0.35
                    }
                    style={{ transition: "opacity 150ms" }}
                  />
                ))}
                <Label
                  content={({ viewBox }) => {
                    if (viewBox && "cx" in viewBox && "cy" in viewBox) {
                      return (
                        <text
                          x={viewBox.cx}
                          y={viewBox.cy}
                          textAnchor="middle"
                          dominantBaseline="middle"
                        >
                          <tspan
                            x={viewBox.cx}
                            y={(viewBox.cy || 0) - 6}
                            className="fill-foreground text-3xl font-bold"
                          >
                            {activeItem
                              ? activeItem.value
                              : (totalOverride ?? total).toLocaleString()}
                          </tspan>
                          <tspan
                            x={viewBox.cx}
                            y={(viewBox.cy || 0) + 18}
                            className="fill-muted-foreground text-sm"
                          >
                            {activeItem ? activeItem.name : "Total CVEs"}
                          </tspan>
                        </text>
                      );
                    }
                  }}
                />
              </Pie>
            </PieChart>
          </ChartContainer>

          {/* ---- Legend (links to the filtered CVE list) ---- */}
          <div className="grid w-full max-w-lg grid-cols-2 gap-x-6 gap-y-2.5">
            {chartData.map((entry, i) => {
              const pct =
                total > 0 ? ((entry.value / total) * 100).toFixed(0) : "0";
              const isActive = activeIndex === i;
              const iconKey = getIconKey(entry.key);

              return (
                <Link
                  key={entry.key}
                  href={getHref(entry.key)}
                  className={`flex items-center gap-2.5 rounded-md px-2 py-1.5 transition-colors focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50 ${
                    isActive ? "bg-accent" : "hover:bg-accent/50"
                  }`}
                  onMouseEnter={() => setActiveIndex(i)}
                  onMouseLeave={() => setActiveIndex(undefined)}
                  onFocus={() => setActiveIndex(i)}
                  onBlur={() => setActiveIndex(undefined)}
                >
                  {/* Color dot */}
                  <span
                    aria-hidden="true"
                    className="h-3 w-3 shrink-0 rounded-full"
                    style={{ backgroundColor: entry.fill }}
                  />

                  {/* Icon */}
                  {iconDir && iconKey && (
                    <IconImg
                      iconKey={iconKey}
                      iconDir={iconDir}
                      themed={themedIcons.has(entry.key)}
                    />
                  )}

                  {/* Name + count */}
                  <span className="min-w-0 flex-1 truncate text-sm font-medium text-card-foreground">
                    {entry.name}
                  </span>
                  <span className="shrink-0 text-sm tabular-nums text-muted-foreground">
                    {entry.value}
                    <span className="ml-0.5 text-xs">({pct}%)</span>
                  </span>
                </Link>
              );
            })}
          </div>
        </div>

        {/* ---- Full distribution data for screen readers ---- */}
        <table className="sr-only">
          <caption>{title}</caption>
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">CVEs</th>
              <th scope="col">Percentage</th>
            </tr>
          </thead>
          <tbody>
            {chartData.map((entry) => {
              const pct =
                total > 0 ? ((entry.value / total) * 100).toFixed(0) : "0";
              return (
                <tr key={entry.key}>
                  <th scope="row">{entry.name}</th>
                  <td>{entry.value}</td>
                  <td>{pct}%</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ */
/*  Tool icon helper                                                   */
/* ------------------------------------------------------------------ */

function IconImg({
  iconKey,
  iconDir,
  themed,
}: {
  iconKey: string;
  iconDir: string;
  themed: boolean;
}) {
  const dimensions = getIconDimensions(iconKey, 18);

  if (themed) {
    return (
      <>
        <Image
          src={`${iconDir}/${iconKey}.svg`}
          alt=""
          {...dimensions}
          className="shrink-0 dark:hidden"
          loading="lazy"
        />
        <Image
          src={`${iconDir}/${iconKey}_dark.svg`}
          alt=""
          {...dimensions}
          className="hidden shrink-0 dark:inline-block"
          loading="lazy"
        />
      </>
    );
  }

  return (
    <Image
      src={`${iconDir}/${iconKey}.svg`}
      alt=""
      {...dimensions}
      className="shrink-0"
      loading="lazy"
    />
  );
}
