import { formatMonthShort } from "@/lib/month-utils";
import type { ResearchMonth } from "@/lib/research-data";

const VISIBLE_MONTHS = 12;
const WIDTH = 720;
const HEIGHT = 260;
const LEFT = 36;
const RIGHT = 30;
const TOP = 24;
const BOTTOM = 42;

export interface TrendChartProps {
  readonly data: readonly ResearchMonth[];
  readonly caseCount: number;
  readonly datedCount: number;
  readonly unknownDateCount: number;
  readonly sourceCutoff: string;
}

function shortMonth(month: string): string {
  const year = month.slice(2, 4);
  return `${formatMonthShort(month).slice(0, 3)} '${year}`;
}

export function TrendChart({
  data,
  caseCount,
  datedCount,
  unknownDateCount,
  sourceCutoff,
}: TrendChartProps) {
  const visible = data.slice(-VISIBLE_MONTHS);
  const plotWidth = WIDTH - LEFT - RIGHT;
  const plotHeight = HEIGHT - TOP - BOTTOM;
  const maxCount = Math.max(1, ...visible.map((entry) => entry.count));
  const points = visible.map((entry, index) => ({
    ...entry,
    x: LEFT + (index * plotWidth) / Math.max(1, visible.length - 1),
    y: TOP + plotHeight - (entry.count / maxCount) * plotHeight,
  }));
  const line = points
    .map((point, index) => `${index === 0 ? "M" : "L"}${point.x},${point.y}`)
    .join(" ");
  const area = points.length
    ? `${line} L${points.at(-1)!.x},${TOP + plotHeight} L${points[0].x},${TOP + plotHeight} Z`
    : "";
  const yTicks = [...new Set([0, Math.ceil(maxCount / 2), maxCount])].sort(
    (a, b) => a - b,
  );
  const cutoffMonth = sourceCutoff.slice(0, 7);
  const [cutoffYear, cutoffMonthNumber, cutoffDay] = sourceCutoff
    .slice(0, 10)
    .split("-")
    .map(Number);
  const cutoffIsPartial =
    visible.some((entry) => entry.month === cutoffMonth) &&
    cutoffDay <
    new Date(Date.UTC(cutoffYear, cutoffMonthNumber, 0)).getUTCDate();

  return (
    <section
      id="disclosure-trend"
      className="scroll-mt-20 border-y border-border py-5"
    >
      <div>
        <div>
          <p className="section-kicker">Disclosure trend</p>
          <h2 className="mt-2 text-2xl font-semibold tracking-[-0.025em]">
            Disclosures over time
          </h2>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
            When first-party advisories for these cases were published.
          </p>
        </div>
      </div>

      <dl className="mt-4 flex flex-wrap gap-x-5 gap-y-2 border-y border-border py-2.5 font-mono text-[10px]">
        <div className="flex gap-2">
          <dt className="text-muted-foreground">Dated</dt>
          <dd>{datedCount}/{caseCount}</dd>
        </div>
        <div className="flex gap-2">
          <dt className="text-muted-foreground">Unavailable</dt>
          <dd>{unknownDateCount}</dd>
        </div>
        {visible.length ? (
          <div className="flex gap-2">
            <dt className="text-muted-foreground">Range</dt>
            <dd>
              {formatMonthShort(visible[0].month)}–
              {formatMonthShort(visible.at(-1)!.month)}
            </dd>
          </div>
        ) : null}
        <div className="flex gap-2">
          <dt className="text-muted-foreground">Cadence</dt>
          <dd>Monthly</dd>
        </div>
        <div className="flex gap-2">
          <dt className="text-muted-foreground">Through</dt>
          <dd>{sourceCutoff.slice(0, 10)}</dd>
        </div>
      </dl>

      {points.length ? (
        <div className="mt-4">
          <div
            className="sm:hidden"
            role="img"
            aria-label={points
              .map(
                (point) =>
                  `${formatMonthShort(point.month)}: ${point.count} cases`,
              )
              .join(", ")}
          >
            <div className="flex h-28 items-end gap-1 border-b border-border px-1">
              {points.map((point) => (
                <div
                  key={point.month}
                  className="flex h-full min-w-0 flex-1 flex-col items-center justify-end"
                >
                  <span className="mb-1 font-mono text-[8px] tabular-nums">
                    {point.count}
                  </span>
                  <span
                    className="w-full bg-primary"
                    style={{
                      height: `${Math.max(2, (point.count / maxCount) * 78)}px`,
                    }}
                  />
                </div>
              ))}
            </div>
            <div className="mt-2 grid grid-cols-6 font-mono text-[8px] text-muted-foreground">
              {points
                .filter((_, index) => index % 2 === 0)
                .map((point) => (
                  <span key={point.month}>{shortMonth(point.month)}</span>
                ))}
            </div>
          </div>
          <svg
            viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
            className="hidden h-auto w-full sm:block"
            role="img"
            aria-label={points
              .map(
                (point) =>
                  `${formatMonthShort(point.month)}: ${point.count} cases`,
              )
              .join(", ")}
          >
            <defs>
              <linearGradient id="trend-area" x1="0" x2="0" y1="0" y2="1">
                <stop offset="0%" stopColor="var(--primary)" stopOpacity="0.2" />
                <stop offset="100%" stopColor="var(--primary)" stopOpacity="0" />
              </linearGradient>
            </defs>
            {yTicks.map((tick) => {
              const y = TOP + plotHeight - (tick / maxCount) * plotHeight;
              return (
                <g key={tick}>
                  <line
                    x1={LEFT}
                    x2={WIDTH - RIGHT}
                    y1={y}
                    y2={y}
                    stroke="var(--border)"
                    strokeWidth="1"
                  />
                  <text
                    x={LEFT - 10}
                    y={y + 4}
                    textAnchor="end"
                    className="fill-muted-foreground font-mono text-[11px]"
                  >
                    {tick}
                  </text>
                </g>
              );
            })}
            <path d={area} fill="url(#trend-area)" />
            <path
              d={line}
              fill="none"
              stroke="var(--primary)"
              strokeWidth="3"
              strokeLinejoin="round"
              strokeLinecap="round"
            />
            {points.map((point) => (
              <g key={point.month}>
                <circle
                  cx={point.x}
                  cy={point.y}
                  r="4.5"
                  fill="var(--card)"
                  stroke="var(--primary)"
                  strokeWidth="3"
                >
                  <title>{`${formatMonthShort(point.month)}: ${point.count} cases`}</title>
                </circle>
                <text
                  x={point.x}
                  y={Math.max(14, point.y - 12)}
                  textAnchor="middle"
                  className="fill-foreground font-mono text-[11px] font-semibold"
                >
                  {point.count}
                </text>
                <text
                  x={point.x}
                  y={HEIGHT - 18}
                  textAnchor="middle"
                  className="fill-muted-foreground font-mono text-[10px]"
                >
                  {shortMonth(point.month)}
                  {cutoffIsPartial && point.month === cutoffMonth ? "*" : ""}
                </text>
              </g>
            ))}
          </svg>
          <table className="sr-only">
            <caption>Canonical advisory disclosures by month</caption>
            <thead>
              <tr>
                <th>Month</th>
                <th>Cases</th>
              </tr>
            </thead>
            <tbody>
              {points.map((point) => (
                <tr key={point.month}>
                  <td>{formatMonthShort(point.month)}</td>
                  <td>{point.count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="py-10 text-sm text-muted-foreground">
          No exact first-party advisory dates are available.
        </p>
      )}

      <p className="mt-2 text-[11px] leading-5 text-muted-foreground">
        Exact GHSA dates; {unknownDateCount} case
        {unknownDateCount === 1 ? " lacks" : "s lack"} a publication date.
        {cutoffIsPartial ? ` * ${formatMonthShort(cutoffMonth)} is partial.` : ""}
      </p>
    </section>
  );
}
