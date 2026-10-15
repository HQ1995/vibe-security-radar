import { formatMonthShort } from "@/lib/month-utils";
import type { ResearchMonth } from "@/lib/research-data";

const WIDTH = 720;
const HEIGHT = 240;
const LEFT = 40;
const RIGHT = 16;
const TOP = 30;
const BOTTOM = 44;
const STRIP_GAP = 20;
const STRIP = 26;
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

function percent(value: number): string {
  return `${Math.round(value * 100)}%`;
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
  const shareOf = (entry: ResearchMonth) =>
    entry.advisories ? (entry.researched ?? 0) / entry.advisories : null;
  const shares = visible
    .map(shareOf)
    .filter((value): value is number => value !== null);
  const hasCoverage = shares.length > 0;
  const shareMax = Math.max(0.2, Math.ceil(Math.max(0, ...shares) * 20) / 20);
  const coverageRange = hasCoverage
    ? `${percent(Math.min(...shares))}–${percent(Math.max(...shares))}`
    : "";
  const height = HEIGHT + (hasCoverage ? STRIP_GAP + STRIP : 0);
  const stripBottom = baseline + STRIP_GAP + STRIP;
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
    const barHeight =
      entry.count > 0 ? Math.max(2, (entry.count / scaleMax) * plotHeight) : 0;
    const share = shareOf(entry);
    const stripHeight =
      share && share > 0 ? Math.max(1.5, (share / shareMax) * STRIP) : 0;
    const name = formatMonthShort(entry.month);
    return {
      ...entry,
      index,
      center,
      top: baseline - barHeight,
      height: barHeight,
      share,
      stripHeight,
      partial: cutoffIsPartial && entry.month === cutoffMonth,
      label: labels[index],
      title: `${name}: ${entry.count} cases${share === null ? "" : `, ${percent(share)} of ${entry.advisories?.toLocaleString("en-US")} advisories researched`}`,
    };
  });
  const summary = columns.map((column) => column.title).join("; ");

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
        {hasCoverage ? (
          <div className="flex gap-2">
            <dt className="text-muted-foreground">Researched</dt>
            <dd>{`${coverageRange} per month`}</dd>
          </div>
        ) : null}
        <div className="flex gap-2">
          <dt className="text-muted-foreground">Through</dt>
          <dd>{sourceCutoff.slice(0, 10)}</dd>
        </div>
      </dl>

      {columns.length ? (
        <div className="mt-4">
          {hasCoverage ? (
            <div className="mb-2 flex flex-wrap gap-x-4 gap-y-1 font-mono text-[10px] text-muted-foreground">
              <span className="flex items-center gap-1.5">
                <span className="h-2.5 w-2.5 rounded-[2px] bg-primary" />
                Findings per month
              </span>
              <span className="flex items-center gap-1.5">
                <span className="h-2.5 w-2.5 rounded-[2px] bg-muted-foreground/45" />
                Share of the month&apos;s advisories researched
              </span>
            </div>
          ) : null}
          <div className="sm:hidden" role="img" aria-label={summary}>
            <div className="flex h-28 items-end gap-0.5 border-b border-border px-1">
              {columns.map((column) => (
                <div
                  key={column.month}
                  className="flex h-full min-w-0 flex-1 flex-col items-center justify-end"
                  title={column.title}
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
            {hasCoverage ? (
              <div className="mt-1.5 flex h-5 items-end gap-0.5 border-b border-border px-1">
                {columns.map((column) => (
                  <div
                    key={column.month}
                    className="flex h-full min-w-0 flex-1 flex-col items-center justify-end"
                  >
                    {column.stripHeight ? (
                      <span
                        className="w-full max-w-6 rounded-t-[2px] bg-muted-foreground/45"
                        style={{
                          height: `${Math.max(1.5, ((column.share ?? 0) / shareMax) * 20)}px`,
                        }}
                      />
                    ) : null}
                  </div>
                ))}
              </div>
            ) : null}
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
            viewBox={`0 0 ${WIDTH} ${height}`}
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
            {hasCoverage ? (
              <g>
                <line
                  x1={LEFT}
                  x2={WIDTH - RIGHT}
                  y1={stripBottom}
                  y2={stripBottom}
                  stroke="var(--border)"
                  strokeWidth="1"
                />
                <text
                  x={LEFT - 10}
                  y={stripBottom - STRIP + 8}
                  textAnchor="end"
                  className="fill-muted-foreground font-mono text-[10px] tabular-nums"
                >
                  {percent(shareMax)}
                </text>
              </g>
            ) : null}
            {columns.map((column) => {
              const hoverX = Math.min(
                WIDTH - RIGHT - 92,
                Math.max(LEFT + 92, column.center),
              );
              const valueY = Math.max(14, column.top - 8);
              return (
                <g key={column.month} className="group">
                  <title>{column.title}</title>
                  <rect
                    x={column.center - band / 2}
                    y={TOP - 20}
                    width={band}
                    height={height - TOP - 4}
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
                  {column.stripHeight ? (
                    <path
                      d={barPath(
                        column.center - barWidth / 2,
                        stripBottom - column.stripHeight,
                        barWidth,
                        column.stripHeight,
                      )}
                      fill="var(--muted-foreground)"
                      opacity="0.45"
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
                      {column.share === null ? "" : ` · ${percent(column.share)} researched`}
                    </tspan>
                  </text>
                  {column.label ? (
                    <text
                      x={column.center}
                      y={height - 24}
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
                      y={height - 10}
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
            <table className="mt-2 w-full max-w-md font-mono text-[11px]">
              <caption className="sr-only">
                Canonical advisory disclosures by month
              </caption>
              <thead>
                <tr className="text-muted-foreground">
                  <th className="py-0.5 text-left font-normal">Month</th>
                  <th className="py-0.5 text-right font-normal">Findings</th>
                  {hasCoverage ? (
                    <th className="py-0.5 text-right font-normal">Researched</th>
                  ) : null}
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
                    {hasCoverage ? (
                      <td className="py-0.5 text-right tabular-nums">
                        {column.share === null
                          ? "–"
                          : `${percent(column.share)} of ${column.advisories?.toLocaleString("en-US")}`}
                      </td>
                    ) : null}
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

      {hasCoverage ? (
        <p className="mt-2 max-w-2xl text-[11px] leading-5 text-muted-foreground">
          {`Bars count findings among the advisories researched so far. Only ${coverageRange} of each month's covered advisories have been researched (gray), so a short bar can mean little research rather than few AI-caused vulnerabilities.`}
        </p>
      ) : null}
      {cutoffIsPartial ? (
        <p className="mt-1 text-[11px] leading-5 text-muted-foreground">
          * {formatMonthShort(cutoffMonth)} is partial (lighter bar).
        </p>
      ) : null}
    </section>
  );
}
