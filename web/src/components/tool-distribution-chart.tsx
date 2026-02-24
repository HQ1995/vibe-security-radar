"use client";

import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  Legend,
} from "recharts";

const TOOL_DISPLAY_NAMES: Readonly<Record<string, string>> = {
  claude_code: "Claude Code",
  cursor: "Cursor",
  aider: "Aider",
  github_copilot: "GitHub Copilot",
  devin: "Devin",
  windsurf: "Windsurf",
  codeium: "Codeium",
  amazon_q: "Amazon Q",
  sweep: "Sweep",
  openai_codex: "OpenAI Codex",
  google_gemini: "Google Gemini",
  google_jules: "Google Jules",
  unknown_ai: "Unknown AI",
};

const CHART_COLORS = [
  "hsl(var(--chart-1))",
  "hsl(var(--chart-2))",
  "hsl(var(--chart-3))",
  "hsl(var(--chart-4))",
  "hsl(var(--chart-5))",
  "oklch(0.65 0.2 150)",
  "oklch(0.55 0.25 320)",
  "oklch(0.70 0.15 60)",
] as const;

function getDisplayName(tool: string): string {
  return TOOL_DISPLAY_NAMES[tool] ?? tool;
}

interface ToolDistributionChartProps {
  readonly data: Readonly<Record<string, number>>;
}

export function ToolDistributionChart({ data }: ToolDistributionChartProps) {
  const chartData = Object.entries(data).map(([tool, count]) => ({
    name: getDisplayName(tool),
    value: count,
  }));

  return (
    <section>
      <h2 className="mb-4 text-xl font-semibold">Tool Distribution</h2>
      <div className="h-80 w-full rounded-xl border border-border bg-card p-4">
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
              {chartData.map((entry, index) => (
                <Cell
                  key={entry.name}
                  fill={CHART_COLORS[index % CHART_COLORS.length]}
                />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: "hsl(var(--card))",
                border: "1px solid hsl(var(--border))",
                borderRadius: "0.5rem",
                color: "hsl(var(--card-foreground))",
              }}
            />
            <Legend
              formatter={(value: string) => (
                <span style={{ color: "hsl(var(--card-foreground))" }}>
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
