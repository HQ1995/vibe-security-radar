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

const RADIAN = Math.PI / 180;

/**
 * Custom label renderer that places text outside the pie with a short leader line.
 * Uses collision avoidance to prevent overlapping labels.
 */
function renderOuterLabel(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  props: Record<string, any>,
  positions: { y: number; side: "left" | "right" }[],
) {
  const cx = props.cx as number;
  const cy = props.cy as number;
  const midAngle = props.midAngle as number;
  const outerRadius = props.outerRadius as number;
  const name = props.name as string;
  const percent = props.percent as number;
  const index = props.index as number;
  if (percent < 0.02) return null;

  const sin = Math.sin(-RADIAN * midAngle);
  const cos = Math.cos(-RADIAN * midAngle);
  const side: "left" | "right" = cos >= 0 ? "right" : "left";

  // Point on the outer edge of the pie
  const ex = cx + outerRadius * cos;
  const ey = cy + outerRadius * sin;

  // Leader line endpoint — extend outward
  const lineLen = 18;
  const lx = cx + (outerRadius + lineLen) * cos;
  let ly = cy + (outerRadius + lineLen) * sin;

  // Collision avoidance: push labels apart vertically (min 16px gap)
  const minGap = 16;
  for (const prev of positions) {
    if (prev.side === side && Math.abs(ly - prev.y) < minGap) {
      ly = prev.y + (ly > prev.y ? minGap : -minGap);
    }
  }
  positions.push({ y: ly, side });

  // Horizontal tail
  const tailLen = 12;
  const tx = lx + (side === "right" ? tailLen : -tailLen);
  const pct = `${((percent) * 100).toFixed(0)}%`;

  return (
    <g key={`label-${index}`}>
      <path
        d={`M${ex},${ey} L${lx},${ly} L${tx},${ly}`}
        stroke="var(--color-muted-foreground)"
        strokeWidth={1}
        fill="none"
        opacity={0.6}
      />
      <text
        x={tx + (side === "right" ? 4 : -4)}
        y={ly}
        textAnchor={side === "right" ? "start" : "end"}
        dominantBaseline="central"
        fill="var(--color-card-foreground)"
        fontSize={12}
      >
        {name} {pct}
      </text>
    </g>
  );
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

  // Shared mutable array for collision tracking across label renders
  const positions: { y: number; side: "left" | "right" }[] = [];

  return (
    <section>
      <h2 className="mb-4 text-xl font-semibold">{title}</h2>
      <div className="h-96 w-full rounded-xl border border-border bg-card p-4 [&_*]:outline-none">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={chartData}
              cx="50%"
              cy="50%"
              innerRadius={55}
              outerRadius={95}
              paddingAngle={2}
              dataKey="value"
              nameKey="name"
              label={(props) => {
                // Reset positions on first label of each render cycle
                if (props.index === 0) positions.length = 0;
                return renderOuterLabel(props, positions);
              }}
              labelLine={false}
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
    </section>
  );
}
