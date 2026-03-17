import type { StatsData } from "@/lib/types";

interface StatsCardsProps {
  readonly stats: StatsData;
}

export function StatsCards({ stats }: StatsCardsProps) {
  const totalCves = stats.total_cves;
  const aiToolsDetected = Object.keys(stats.by_tool).length;
  const criticalHigh =
    (stats.by_severity["CRITICAL"] ?? 0) + (stats.by_severity["HIGH"] ?? 0);

  const totalAnalyzed = stats.total_analyzed;
  const withFix = stats.with_fix_commits ?? 0;
  const fixPct =
    totalAnalyzed > 0 ? Math.round((withFix / totalAnalyzed) * 100) : 0;

  return (
    <div className="space-y-4">
      {/* Three key numbers */}
      <div className="grid grid-cols-3 gap-px overflow-hidden rounded-xl border border-border bg-border">
        <div className="bg-card px-5 py-5">
          <p className="font-[family-name:var(--font-display)] text-4xl font-extrabold tabular-nums text-primary">
            {totalCves}
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            AI-linked vulnerabilities
          </p>
        </div>
        <div className="bg-card px-5 py-5">
          <p className="font-[family-name:var(--font-display)] text-4xl font-extrabold tabular-nums text-foreground">
            {aiToolsDetected}
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            AI tools detected
          </p>
        </div>
        <div className="bg-card px-5 py-5">
          <p className="font-[family-name:var(--font-display)] text-4xl font-extrabold tabular-nums text-amber-400">
            {criticalHigh}
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            Critical / High
          </p>
        </div>
      </div>

      {/* Coverage line */}
      <p className="text-xs text-muted-foreground">
        <span className="tabular-nums text-foreground/70">{totalAnalyzed.toLocaleString()}</span> advisories
        analyzed{" · "}
        <span className="tabular-nums text-foreground/70">{withFix.toLocaleString()}</span> with
        fix commits ({fixPct}%)
      </p>
    </div>
  );
}
