import Image from "next/image";
import Link from "next/link";

import { getIconDimensions } from "@/components/tool-icon";

interface DistributionPieChartProps {
  readonly title: string;
  readonly data: Readonly<Record<string, number>>;
  readonly getColor: (key: string) => string;
  readonly getName?: (key: string) => string;
  readonly getHref: (key: string) => string;
  readonly iconDir?: string;
  readonly getIconKey?: (key: string) => string | null;
  readonly totalOverride?: number;
}

export function DistributionPieChart({
  title,
  data,
  getColor,
  getName = (key) => key,
  getHref,
  iconDir,
  getIconKey = (key) => key,
  totalOverride,
}: DistributionPieChartProps) {
  const entries = Object.entries(data)
    .map(([key, value]) => ({
      key,
      value,
      name: getName(key),
      color: getColor(key),
    }))
    .sort((a, b) => b.value - a.value);
  const denominator =
    totalOverride ?? entries.reduce((sum, entry) => sum + entry.value, 0);

  return (
    <section>
      <div className="mb-4 flex items-baseline justify-between gap-4">
        <h2 className="text-xl font-semibold">{title}</h2>
        <span className="font-mono text-xs text-muted-foreground">
          {denominator.toLocaleString()} catalog pages
        </span>
      </div>
      <div className="grid gap-3 rounded-xl border border-border bg-card p-4 sm:grid-cols-2 sm:p-5">
        {entries.map((entry) => {
          const percentage =
            denominator > 0 ? (entry.value / denominator) * 100 : 0;
          const iconKey = getIconKey(entry.key);
          return (
            <Link
              key={entry.key}
              href={getHref(entry.key)}
              className="rounded-lg border border-border p-3 transition-colors hover:border-primary/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              <div className="flex items-center gap-2.5">
                <span
                  aria-hidden="true"
                  className="h-2.5 w-2.5 shrink-0 rounded-sm"
                  style={{ backgroundColor: entry.color }}
                />
                {iconDir && iconKey ? (
                  <IconImg iconKey={iconKey} iconDir={iconDir} />
                ) : null}
                <span className="min-w-0 flex-1 truncate text-sm font-medium">
                  {entry.name}
                </span>
                <span className="font-mono text-xs tabular-nums text-muted-foreground">
                  {entry.value} · {percentage.toFixed(0)}%
                </span>
              </div>
              <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-muted">
                <div
                  className="h-full rounded-full"
                  style={{
                    backgroundColor: entry.color,
                    width: `${Math.min(100, percentage)}%`,
                  }}
                />
              </div>
            </Link>
          );
        })}
      </div>
      <table className="sr-only">
        <caption>{title}</caption>
        <thead>
          <tr>
            <th scope="col">Name</th>
            <th scope="col">Catalog pages</th>
            <th scope="col">Share of pages</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((entry) => (
            <tr key={entry.key}>
              <th scope="row">{entry.name}</th>
              <td>{entry.value}</td>
              <td>
                {denominator > 0
                  ? ((entry.value / denominator) * 100).toFixed(0)
                  : 0}
                %
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

function IconImg({
  iconKey,
  iconDir,
}: {
  readonly iconKey: string;
  readonly iconDir: string;
}) {
  const dimensions = getIconDimensions(iconKey, 18);
  return (
    <Image
      src={
        iconDir === "/icons/tools" && iconKey === "openai_codex"
          ? "/icons/tools/chatgpt.png"
          : `${iconDir}/${iconKey}.svg`
      }
      alt=""
      {...dimensions}
      className="shrink-0"
      loading="lazy"
    />
  );
}
