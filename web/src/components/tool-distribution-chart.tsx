"use client";

import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  Legend,
} from "recharts";
import {
  getToolDisplayName,
  TOOL_BRAND_COLORS,
  TOOL_BRAND_FALLBACK_COLOR,
} from "@/lib/constants";

interface ToolDistributionChartProps {
  readonly data: Readonly<Record<string, number>>;
}

export function ToolDistributionChart({ data }: ToolDistributionChartProps) {
  const chartData = Object.entries(data).map(([tool, count]) => ({
    name: getToolDisplayName(tool),
    value: count,
    color: TOOL_BRAND_COLORS[tool] ?? TOOL_BRAND_FALLBACK_COLOR,
  }));

  return (
    <section>
      <h2 className="mb-4 text-xl font-semibold">Tool Distribution</h2>
      <div className="h-80 w-full rounded-xl border border-border bg-card p-4 [&_*]:outline-none">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={chartData}
              cx="50%"
              cy="50%"
              innerRadius={60}
              outerRadius={100}
              paddingAngle={2}
              dataKey="value"
              nameKey="name"
              label={({ name, percent }) =>
                `${name} ${((percent ?? 0) * 100).toFixed(0)}%`
              }
              labelLine={false}
            >
              {chartData.map((entry) => (
                <Cell
                  key={entry.name}
                  fill={entry.color}
                />
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
            <Legend
              formatter={(value: string) => (
                <span style={{ color: "var(--color-card-foreground)" }}>
                  {value}
                </span>
              )}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
}
