"use client";

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
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
            <XAxis
              dataKey="month"
              tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 12 }}
              axisLine={{ stroke: "hsl(var(--border))" }}
              tickLine={false}
            />
            <YAxis
              allowDecimals={false}
              tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 12 }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "hsl(var(--card))",
                border: "1px solid hsl(var(--border))",
                borderRadius: "0.5rem",
                color: "hsl(var(--card-foreground))",
              }}
              cursor={{ fill: "hsl(var(--muted))", opacity: 0.4 }}
            />
            <Bar
              dataKey="count"
              fill="hsl(var(--chart-1))"
              radius={[4, 4, 0, 0]}
            />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
}
