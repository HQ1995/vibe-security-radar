"use client";

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

interface MonthEntry {
  readonly month: string;
  readonly count: number;
}

interface TrendChartProps {
  readonly data: readonly MonthEntry[];
}

export function TrendChart({ data }: TrendChartProps) {
  // Recharts requires mutable arrays, so create a shallow copy
  const chartData = data.map((entry) => ({
    month: entry.month,
    count: entry.count,
  }));

  return (
    <section>
      <h2 className="mb-4 text-xl font-semibold">Vulnerabilities by Month</h2>
      <div className="h-72 w-full rounded-xl border border-border bg-card p-4">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={chartData}
            margin={{ top: 8, right: 8, bottom: 8, left: 0 }}
          >
            <CartesianGrid
              strokeDasharray="3 3"
              vertical={false}
              stroke="var(--color-border)"
            />
            <XAxis
              dataKey="month"
              tick={{ fill: "var(--color-muted-foreground)", fontSize: 12 }}
              axisLine={{ stroke: "var(--color-border)" }}
              tickLine={false}
            />
            <YAxis
              allowDecimals={false}
              tick={{ fill: "var(--color-muted-foreground)", fontSize: 12 }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              trigger="hover"
              isAnimationActive={false}
              contentStyle={{
                backgroundColor: "var(--color-card)",
                border: "1px solid var(--color-border)",
                borderRadius: "0.5rem",
                color: "var(--color-card-foreground)",
              }}
              cursor={{ fill: "var(--color-muted)", opacity: 0.4 }}
            />
            <Bar
              dataKey="count"
              fill="var(--color-chart-1)"
              radius={[4, 4, 0, 0]}
              isAnimationActive={false}
            />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
}
