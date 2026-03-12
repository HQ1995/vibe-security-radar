"use client";

import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
} from "recharts";

interface DistributionPieChartProps {
  readonly title: string;
  readonly data: Readonly<Record<string, number>>;
  readonly getColor: (key: string) => string;
  readonly getName?: (key: string) => string;
}

export function DistributionPieChart({
  title,
  data,
  getColor,
  getName = (k) => k,
}: DistributionPieChartProps) {
  const chartData = Object.entries(data)
    .map(([key, count]) => ({
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
        <div className="flex flex-col items-center gap-4 sm:flex-row sm:items-start">
          <div className="h-64 w-64 shrink-0">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={chartData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={90}
                  paddingAngle={2}
                  dataKey="value"
                  nameKey="name"
                >
                  {chartData.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} />
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
          <ul className="flex flex-wrap gap-x-4 gap-y-1 text-sm sm:flex-col sm:gap-y-1.5">
            {chartData.map((entry) => {
              const pct = total > 0 ? ((entry.value / total) * 100).toFixed(0) : "0";
              return (
                <li key={entry.name} className="flex items-center gap-2">
                  <span
                    className="inline-block h-3 w-3 shrink-0 rounded-sm"
                    style={{ backgroundColor: entry.color }}
                  />
                  <span style={{ color: "var(--color-card-foreground)" }}>
                    {entry.name}
                    <span className="ml-1 text-muted-foreground">
                      {entry.value} ({pct}%)
                    </span>
                  </span>
                </li>
              );
            })}
          </ul>
        </div>
      </div>
    </section>
  );
}
