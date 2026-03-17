"use client";

import * as React from "react";
import { Cell, Label, Pie, PieChart } from "recharts";

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
  readonly iconDir?: string;
  readonly getIconKey?: (key: string) => string;
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

  return (
    <section>
      <h2 className="mb-4 text-xl font-semibold">{title}</h2>
      <div className="rounded-xl border border-border bg-card p-6 [&_*]:outline-none">
        <div className="flex flex-col items-center gap-8 lg:flex-row lg:justify-center">
          {/* ---- Donut ---- */}
          <ChartContainer
            config={chartConfig}
            className="aspect-square h-[280px] shrink-0"
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

          {/* ---- Legend ---- */}
          <div className="grid w-full max-w-lg grid-cols-2 gap-x-6 gap-y-2.5">
            {chartData.map((entry, i) => {
              const pct =
                total > 0 ? ((entry.value / total) * 100).toFixed(0) : "0";
              const isActive = activeIndex === i;

              return (
                <div
                  key={entry.key}
                  className={`flex cursor-default items-center gap-2.5 rounded-md px-2 py-1.5 transition-colors ${
                    isActive ? "bg-accent" : "hover:bg-accent/50"
                  }`}
                  onMouseEnter={() => setActiveIndex(i)}
                  onMouseLeave={() => setActiveIndex(undefined)}
                >
                  {/* Color dot */}
                  <span
                    className="h-3 w-3 shrink-0 rounded-full"
                    style={{ backgroundColor: entry.fill }}
                  />

                  {/* Icon */}
                  {iconDir && (
                    <IconImg
                      iconKey={getIconKey(entry.key)}
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
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ */
/*  Tool icon helper (HTML img, not SVG label)                         */
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
  if (themed) {
    return (
      <>
        <img
          src={`${iconDir}/${iconKey}.svg`}
          alt=""
          width={18}
          height={18}
          className="shrink-0 dark:hidden"
          loading="eager"
        />
        <img
          src={`${iconDir}/${iconKey}_dark.svg`}
          alt=""
          width={18}
          height={18}
          className="hidden shrink-0 dark:inline-block"
          loading="eager"
        />
      </>
    );
  }

  return (
    <img
      src={`${iconDir}/${iconKey}.svg`}
      alt=""
      width={18}
      height={18}
      className="shrink-0"
      loading="eager"
    />
  );
}
