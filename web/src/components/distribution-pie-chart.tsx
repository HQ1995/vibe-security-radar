"use client";

import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
} from "recharts";

interface ChartEntry {
  readonly key: string;
  readonly name: string;
  readonly value: number;
  readonly color: string;
}

interface DistributionPieChartProps {
  readonly title: string;
  readonly data: Readonly<Record<string, number>>;
  readonly getColor: (key: string) => string;
  readonly getName?: (key: string) => string;
  readonly iconDir?: string;
  readonly themedIcons?: ReadonlySet<string>;
}

function LegendItem({ entry, total }: { entry: ChartEntry; total: number }) {
  const pct = total > 0 ? ((entry.value / total) * 100).toFixed(0) : "0";
  return (
    <div className="flex items-center gap-2 min-w-0">
      <span
        className="h-3 w-3 shrink-0 rounded-full"
        style={{ backgroundColor: entry.color }}
      />
      <span className="truncate text-sm text-card-foreground">
        {entry.name}
      </span>
      <span className="shrink-0 text-sm text-muted-foreground">
        {entry.value} ({pct}%)
      </span>
    </div>
  );
}

function IconLegendItem({
  entry,
  total,
  iconDir,
  themedIcons,
}: {
  entry: ChartEntry;
  total: number;
  iconDir: string;
  themedIcons: ReadonlySet<string>;
}) {
  const pct = total > 0 ? ((entry.value / total) * 100).toFixed(0) : "0";
  const hasThemed = themedIcons.has(entry.key);

  return (
    <div className="flex items-center gap-2 min-w-0">
      <span
        className="h-3 w-3 shrink-0 rounded-full"
        style={{ backgroundColor: entry.color }}
      />
      {hasThemed ? (
        <>
          <img
            src={`${iconDir}/${entry.key}.svg`}
            alt=""
            width={18}
            height={18}
            className="shrink-0 dark:hidden"
            loading="eager"
          />
          <img
            src={`${iconDir}/${entry.key}_dark.svg`}
            alt=""
            width={18}
            height={18}
            className="hidden shrink-0 dark:inline-block"
            loading="eager"
          />
        </>
      ) : (
        <img
          src={`${iconDir}/${entry.key}.svg`}
          alt=""
          width={18}
          height={18}
          className="shrink-0"
          loading="eager"
        />
      )}
      <span className="truncate text-sm font-medium text-card-foreground">
        {entry.name}
      </span>
      <span className="shrink-0 text-xs tabular-nums text-muted-foreground">
        {entry.value} ({pct}%)
      </span>
    </div>
  );
}

export function DistributionPieChart({
  title,
  data,
  getColor,
  getName = (k) => k,
  iconDir,
  themedIcons = new Set(),
}: DistributionPieChartProps) {
  const chartData: ChartEntry[] = Object.entries(data)
    .map(([key, count]) => ({
      key,
      name: getName(key),
      value: count,
      color: getColor(key),
    }))
    .sort((a, b) => b.value - a.value);

  const total = chartData.reduce((sum, d) => sum + d.value, 0);

  return (
    <section>
      <h2 className="mb-4 text-xl font-semibold">{title}</h2>
      <div className="w-full rounded-xl border border-border bg-card p-4 [&_*]:outline-none">
        <div className="flex flex-col items-center gap-6 lg:flex-row lg:justify-center lg:gap-10">
          {/* Donut */}
          <div className="h-64 w-64 shrink-0">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={chartData}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={100}
                  paddingAngle={2}
                  dataKey="value"
                  nameKey="name"
                  isAnimationActive={false}
                >
                  {chartData.map((entry) => (
                    <Cell key={entry.key} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: "var(--color-card)",
                    border: "1px solid var(--color-border)",
                    borderRadius: "0.5rem",
                    color: "var(--color-card-foreground)",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          {/* Legend */}
          <div className="grid w-full max-w-md grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-2">
            {chartData.map((entry) =>
              iconDir ? (
                <IconLegendItem
                  key={entry.key}
                  entry={entry}
                  total={total}
                  iconDir={iconDir}
                  themedIcons={themedIcons}
                />
              ) : (
                <LegendItem key={entry.key} entry={entry} total={total} />
              ),
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
