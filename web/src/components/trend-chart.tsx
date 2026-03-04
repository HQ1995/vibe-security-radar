"use client";

import { useState, useEffect, useRef, useMemo, useCallback } from "react";
import { useRouter } from "next/navigation";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from "recharts";
import {
  getToolDisplayName,
  TOOL_BRAND_COLORS,
  TOOL_BRAND_FALLBACK_COLOR,
} from "@/lib/constants";

const VISIBLE_MONTHS = 8;
const COUNT_KEY = "__count__";

interface MonthEntry {
  readonly month: string;
  readonly count: number;
  readonly by_tool: Readonly<Record<string, number>>;
}

interface TrendChartProps {
  readonly data: readonly MonthEntry[];
}

function CustomTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: Array<{ dataKey: string; value: number; color: string }>;
  label?: string;
}) {
  if (!active || !payload?.length) return null;

  const entries = payload.filter(
    (p) => p.value > 0 && p.dataKey !== COUNT_KEY,
  );
  // Use the real CVE count, not sum of tool credits (a CVE can have multiple tools)
  const countEntry = payload.find((p) => p.dataKey === COUNT_KEY);
  const total = countEntry?.value ?? entries.reduce((sum, p) => sum + p.value, 0);

  return (
    <div className="rounded-lg border border-border bg-card px-3 py-2 shadow-md">
      <p className="mb-1 text-sm font-semibold text-card-foreground">{label}</p>
      {entries.map((entry) => (
        <div
          key={entry.dataKey}
          className="flex items-center gap-2 text-xs text-card-foreground"
        >
          <span
            className="inline-block h-2.5 w-2.5 rounded-sm"
            style={{ backgroundColor: entry.color }}
          />
          <span>{getToolDisplayName(entry.dataKey)}</span>
          <span className="ml-auto font-mono">{entry.value}</span>
        </div>
      ))}
      <div className="mt-1 border-t border-border pt-1 text-xs font-semibold text-card-foreground">
        Total: {total}
      </div>
    </div>
  );
}

export function TrendChart({ data }: TrendChartProps) {
  const router = useRouter();
  const containerRef = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState<{ width: number; height: number } | null>(null);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;

    const observer = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (entry) {
        const { width, height } = entry.contentRect;
        if (width > 0 && height > 0) {
          setSize({ width, height });
        }
      }
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  // Collect all unique tool names across all months
  const allTools = useMemo(() => {
    const toolSet = new Set<string>();
    for (const entry of data) {
      for (const tool of Object.keys(entry.by_tool)) {
        toolSet.add(tool);
      }
    }
    return Array.from(toolSet).sort();
  }, [data]);

  // Default: show most recent months
  const maxStart = Math.max(0, data.length - VISIBLE_MONTHS);
  const [startIndex, setStartIndex] = useState(maxStart);

  const canScrollLeft = startIndex > 0;
  const canScrollRight = startIndex < maxStart;

  const visibleData = useMemo(() => {
    const sliced = data.slice(startIndex, startIndex + VISIBLE_MONTHS);
    // Flatten by_tool into top-level keys for recharts; include real count
    return sliced.map((entry) => {
      const flat: Record<string, string | number> = {
        month: entry.month,
        [COUNT_KEY]: entry.count,
      };
      for (const tool of allTools) {
        flat[tool] = entry.by_tool[tool] ?? 0;
      }
      return flat;
    });
  }, [data, startIndex, allTools]);

  // Legend: only tools present in visible data
  const visibleTools = useMemo(() => {
    return allTools.filter((tool) =>
      visibleData.some((d) => (d[tool] as number) > 0),
    );
  }, [allTools, visibleData]);

  const handleBarClick = useCallback(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (data: any) => {
      const month = data?.payload?.month;
      if (month) {
        router.push(`/cves/month/${month}`);
      }
    },
    [router],
  );

  return (
    <section>
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-xl font-semibold">Vulnerabilities by Month</h2>
        {data.length > VISIBLE_MONTHS && (
          <div className="flex items-center gap-1">
            <button
              type="button"
              onClick={() => setStartIndex(Math.max(0, startIndex - 1))}
              disabled={!canScrollLeft}
              className="rounded-md border border-border px-2 py-1 text-sm text-muted-foreground transition-colors hover:bg-muted disabled:opacity-30 disabled:cursor-not-allowed"
              aria-label="Show earlier months"
            >
              &larr;
            </button>
            <button
              type="button"
              onClick={() =>
                setStartIndex(Math.min(maxStart, startIndex + 1))
              }
              disabled={!canScrollRight}
              className="rounded-md border border-border px-2 py-1 text-sm text-muted-foreground transition-colors hover:bg-muted disabled:opacity-30 disabled:cursor-not-allowed"
              aria-label="Show later months"
            >
              &rarr;
            </button>
          </div>
        )}
      </div>

      <div ref={containerRef} className="h-72 w-full rounded-xl border border-border bg-card p-4">
        {size ? (
          <BarChart
            data={visibleData}
            width={size.width}
            height={size.height}
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
              content={<CustomTooltip />}
              cursor={{ fill: "var(--color-muted)", opacity: 0.4 }}
              isAnimationActive={false}
            />
            {allTools.map((tool) => (
              <Bar
                key={tool}
                dataKey={tool}
                stackId="tools"
                fill={TOOL_BRAND_COLORS[tool] ?? TOOL_BRAND_FALLBACK_COLOR}
                radius={[4, 4, 0, 0]}
                isAnimationActive={false}
                style={{ cursor: "pointer" }}
                onClick={handleBarClick}
              />
            ))}
          </BarChart>
        ) : (
          <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
            Loading chart...
          </div>
        )}
      </div>

      {/* Inline legend for visible tools */}
      {visibleTools.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5">
          {visibleTools.map((tool) => (
            <div key={tool} className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <span
                className="inline-block h-2.5 w-2.5 rounded-sm"
                style={{
                  backgroundColor:
                    TOOL_BRAND_COLORS[tool] ?? TOOL_BRAND_FALLBACK_COLOR,
                }}
              />
              <span>{getToolDisplayName(tool)}</span>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
