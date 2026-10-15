import { formatMonthShort } from "@/lib/month-utils";
import type { ResearchMonth } from "@/lib/research-data";

const WIDTH = 720;
const HEIGHT = 240;
const LEFT = 40;
const RIGHT = 16;
const TOP = 30;
const BOTTOM = 44;
const BAR_MAX = 24;
const RADIUS = 4;

export interface TrendChartProps {
  readonly data: readonly ResearchMonth[];
  readonly caseCount: number;
  readonly datedCount: number;
  readonly unknownDateCount: number;
  readonly sourceCutoff: string;
}

interface AxisLabel {
  readonly month: string;
  readonly year: string | null;
}

function niceTicks(max: number): number[] {
  const raw = Math.max(1, max) / 4;
  const power = 10 ** Math.floor(Math.log10(raw));
  const step = Math.max(
    1,
    [1, 2, 5, 10].map((m) => m * power).find((value) => value >= raw) ?? raw,
  );
  const top = Math.max(step, Math.ceil(max / step) * step);
  const ticks: number[] = [];
  for (let tick = 0; tick <= top; tick += step) ticks.push(tick);
  return ticks;
}

function axisLabels(data: readonly ResearchMonth[]): (AxisLabel | null)[] {
  const interval = data.length <= 24 ? 3 : data.length <= 60 ? 6 : 12;
  const starts = data.map(
    (entry) => (Number(entry.month.slice(5, 7)) - 1) % interval === 0,
  );
  const firstStart = starts.indexOf(true);
  const show = data.map(
    (_, index) =>
      starts[index] ||
      (index === 0 && (firstStart === -1 || firstStart >= 2)),
  );
  let lastYear: string | null = null;
  return data.map((entry, index) => {
    if (!show[index]) return null;
    const year = entry.month.slice(0, 4);
    const label = {
      month: formatMonthShort(entry.month).slice(0, 3),
      year: year === lastYear ? null : year,
    };
    lastYear = year;
    return label;
  });
}

function barPath(x: number, y: number, width: number, height: number): string {
  const r = Math.min(RADIUS, height, width / 2);
  const bottom = y + height;
  return `M${x},${bottom} V${y + r} Q${x},${y} ${x + r},${y} H${x + width - r} Q${x + width},${y} ${x + width},${y + r} V${bottom} Z`;
}

export function TrendChart({
  data,
  caseCount,
  datedCount,
  unknownDateCount,
  sourceCutoff,
}: TrendChartProps) {
  const visible = data;
  const plotWidth = WIDTH - LEFT - RIGHT;
  const plotHeight = HEIGHT - TOP - BOTTOM;
  const baseline = TOP + plotHeight;
  const maxCount = Math.max(1, ...visible.map((entry) => entry.count));
  const ticks = niceTicks(maxCount);
  const scaleMax = ticks.at(-1)!;
  const band = plotWidth / Math.max(1, visible.length);
  const barWidth = Math.min(BAR_MAX, band * 0.62);
  const peakIndex = visible.reduce(
    (best, entry, index) => (entry.count > visible[best].count ? index : best),
    0,
  );
  const labels = axisLabels(visible);
  const cutoffMonth = sourceCutoff.slice(0, 7);
  const [cutoffYear, cutoffMonthNumber, cutoffDay] = sourceCutoff
    .slice(0, 10)
    .split("-")
    .map(Number);
  const cutoffIsPartial =
    visible.some((entry) => entry.month === cutoffMonth) &&
    cutoffDay <
    new Date(Date.UTC(cutoffYear, cutoffMonthNumber, 0)).getUTCDate();
  const columns = visible.map((entry, index) => {
    const center = LEFT + band * (index + 0.5);
    const height =
      entry.count > 0 ? Math.max(2, (entry.count / scaleMax) * plotHeight) : 0;
    return {
      ...entry,
      index,
      center,
      top: baseline - height,
      height,
      partial: cutoffIsPartial && entry.month === cutoffMonth,
      label: labels[index],
    };
  });
  const summary = columns
    .map((column) => `${formatMonthShort(column.month)}: ${column.count} cases`)
    .join(", ");

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
            When these cases were publicly disclosed.
          </p>
        </div>
      </div>

      <dl className="mt-4 flex flex-wrap gap-x-5 gap-y-2 border-y border-border py-2.5 font-mono text-[10px]">
        <div className="flex gap-2">
          <dt className="text-muted-foreground">Dated</dt>
          <dd>{datedCount}/{caseCount}</dd>
        </div>
        {unknownDateCount ? (
          <div className="flex gap-2">
            <dt className="text-muted-foreground">Unavailable</dt>
            <dd>{unknownDateCount}</dd>
          </div>
        ) : null}
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

      {columns.length ? (
        <div className="mt-4">
          <div className="sm:hidden" role="img" aria-label={summary}>
            <div className="flex h-28 items-end gap-0.5 border-b border-border px-1">
              {columns.map((column) => (
                <div
                  key={column.month}
                  className="flex h-full min-w-0 flex-1 flex-col items-center justify-end"
                  title={`${formatMonthShort(column.month)}: ${column.count} cases`}
                >
                  {column.index === peakIndex ? (
                    <span className="mb-1 font-mono text-[9px] font-semibold tabular-nums">
                      {column.count}
                    </span>
                  ) : null}
                  {column.count > 0 ? (
                    <span
                      className={`w-full max-w-6 rounded-t-[3px] bg-primary${column.partial ? " opacity-45" : ""}`}
                      style={{
                        height: `${Math.max(2, (column.count / scaleMax) * 88)}px`,
                      }}
                    />
                  ) : null}
                </div>
              ))}
            </div>
            <div className="flex gap-0.5 px-1 pt-1.5 font-mono text-[9px] leading-tight text-muted-foreground">
              {columns.map((column) => (
                <div
                  key={column.month}
                  className="flex min-w-0 flex-1 flex-col items-center overflow-visible whitespace-nowrap"
                >
                  {column.label ? (
                    <>
                      <span>
                        {column.label.month}
                        {column.partial ? "*" : ""}
                      </span>
                      {column.label.year ? <span>{column.label.year}</span> : null}
                    </>
                  ) : null}
                </div>
              ))}
            </div>
          </div>
          <svg
            viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
            className="hidden h-auto w-full sm:block"
            role="img"
            aria-label={summary}
          >
            {ticks.map((tick) => {
              const y = baseline - (tick / scaleMax) * plotHeight;
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
                    className="fill-muted-foreground font-mono text-[11px] tabular-nums"
                  >
                    {tick}
                  </text>
                </g>
              );
            })}
            {columns.map((column) => {
              const hoverX = Math.min(
                WIDTH - RIGHT - 46,
                Math.max(LEFT + 46, column.center),
              );
              const valueY = Math.max(14, column.top - 8);
              return (
                <g key={column.month} className="group">
                  <title>{`${formatMonthShort(column.month)}: ${column.count} cases`}</title>
                  <rect
                    x={column.center - band / 2}
                    y={TOP - 20}
                    width={band}
                    height={plotHeight + 20}
                    fill="transparent"
                  />
                  {column.height ? (
                    <path
                      d={barPath(
                        column.center - barWidth / 2,
                        column.top,
                        barWidth,
                        column.height,
                      )}
                      fill="var(--primary)"
                      opacity={column.partial ? 0.45 : 1}
                      className="transition-opacity group-hover:opacity-70"
                    />
                  ) : null}
                  {column.index === peakIndex ? (
                    <text
                      x={column.center}
                      y={valueY}
                      textAnchor="middle"
                      className="fill-foreground font-mono text-[11px] font-semibold tabular-nums transition-opacity group-hover:opacity-0"
                    >
                      {column.count}
                    </text>
                  ) : null}
                  <text
                    x={hoverX}
                    y={valueY}
                    textAnchor="middle"
                    className="pointer-events-none fill-foreground font-mono text-[11px] opacity-0 transition-opacity group-hover:opacity-100"
                  >
                    <tspan className="font-semibold tabular-nums">{column.count}</tspan>
                    <tspan className="fill-muted-foreground">
                      {` · ${formatMonthShort(column.month)}${column.partial ? "*" : ""}`}
                    </tspan>
                  </text>
                  {column.label ? (
                    <text
                      x={column.center}
                      y={HEIGHT - 24}
                      textAnchor="middle"
                      className="fill-muted-foreground font-mono text-[10px]"
                    >
                      {column.label.month}
                      {column.partial ? "*" : ""}
                    </text>
                  ) : null}
                  {column.label?.year ? (
                    <text
                      x={column.center}
                      y={HEIGHT - 10}
                      textAnchor="middle"
                      className="fill-muted-foreground font-mono text-[10px]"
                    >
                      {column.label.year}
                    </text>
                  ) : null}
                </g>
              );
            })}
            <line
              x1={LEFT}
              x2={WIDTH - RIGHT}
              y1={baseline}
              y2={baseline}
              stroke="var(--muted-foreground)"
              strokeOpacity="0.5"
              strokeWidth="1"
            />
          </svg>
          <details className="mt-3">
            <summary className="cursor-pointer font-mono text-[10px] text-muted-foreground">
              Monthly counts
            </summary>
            <table className="mt-2 w-full max-w-xs font-mono text-[11px]">
              <caption className="sr-only">
                Canonical advisory disclosures by month
              </caption>
              <thead>
                <tr className="text-muted-foreground">
                  <th className="py-0.5 text-left font-normal">Month</th>
                  <th className="py-0.5 text-right font-normal">Findings</th>
                </tr>
              </thead>
              <tbody>
                {columns.map((column) => (
                  <tr key={column.month} className="border-t border-border">
                    <td className="py-0.5">
                      {formatMonthShort(column.month)}
                      {column.partial ? "*" : ""}
                    </td>
                    <td className="py-0.5 text-right tabular-nums">{column.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </details>
        </div>
      ) : (
        <p className="py-10 text-sm text-muted-foreground">
          No exact first-party advisory dates are available.
        </p>
      )}

      {cutoffIsPartial ? (
        <p className="mt-2 text-[11px] leading-5 text-muted-foreground">
          * {formatMonthShort(cutoffMonth)} is partial (lighter bar).
        </p>
      ) : null}
    </section>
  );
}
