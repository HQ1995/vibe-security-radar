"use client";

import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  Legend,
} from "recharts";
import { getToolDisplayName } from "@/lib/constants";

/** Brand colors for each AI tool (keyed by internal tool id). */
const TOOL_BRAND_COLORS: Readonly<Record<string, string>> = {
  claude_code: "#E87322",    // Anthropic orange
  cursor: "#00B4D8",         // Cursor teal
  aider: "#14B8A6",          // Aider teal-green
  github_copilot: "#6E40C9", // GitHub Copilot purple
  devin: "#2563EB",          // Devin blue
  windsurf: "#22D3EE",       // Windsurf cyan
  codeium: "#09B6A2",        // Codeium green
  amazon_q: "#FF9900",       // AWS orange
  sweep: "#8B5CF6",          // Sweep purple
  openai_codex: "#10A37F",   // OpenAI green
  google_gemini: "#4285F4",  // Google blue
  google_jules: "#EA4335",   // Google red
  tabnine: "#6C63FF",        // Tabnine purple
  sourcegraph_cody: "#A112FF",// Sourcegraph purple
  opencode: "#3B82F6",       // blue
  kiro: "#FF6B2B",           // Kiro orange
  jetbrains_junie: "#FE315D",// JetBrains red-pink
  roo_code: "#FFA500",       // Roo orange
  cline: "#5A67D8",          // Cline indigo
  openhands: "#EF4444",      // red
  lovable: "#E11D48",        // Lovable rose
  fine_dev: "#06B6D4",       // cyan
  replit_agent: "#F26522",   // Replit orange
  qodo: "#7C3AED",           // Qodo violet
  continue_dev: "#F59E0B",   // Continue amber
  augment_code: "#2DD4BF",   // teal
  trae: "#6366F1",           // indigo
  gitlab_duo: "#FC6D26",     // GitLab orange
  gemini_cli: "#4285F4",     // Google blue
  kimi_code: "#5046E5",      // Kimi indigo
  bolt_new: "#F97316",       // Bolt orange
  zencoder: "#0EA5E9",       // sky blue
  codegpt: "#10A37F",        // green
  unknown_ai: "#71717A",     // zinc-500 grey
};

const FALLBACK_COLOR = "#71717A";

interface ToolDistributionChartProps {
  readonly data: Readonly<Record<string, number>>;
}

export function ToolDistributionChart({ data }: ToolDistributionChartProps) {
  const chartData = Object.entries(data).map(([tool, count]) => ({
    name: getToolDisplayName(tool),
    value: count,
    color: TOOL_BRAND_COLORS[tool] ?? FALLBACK_COLOR,
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
              {chartData.map((entry) => (
                <Cell
                  key={entry.name}
                  fill={entry.color}
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
