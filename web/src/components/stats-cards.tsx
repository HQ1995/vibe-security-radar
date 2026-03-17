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
    <section>
      <div className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-border bg-border sm:grid-cols-4">
        <div className="bg-card px-5 py-5">
          <p className="text-3xl font-bold tabular-nums">{totalCves}</p>
          <p className="mt-1 text-xs text-muted-foreground">AI-linked CVEs</p>
        </div>
        <div className="bg-card px-5 py-5">
          <p className="text-3xl font-bold tabular-nums">{aiToolsDetected}</p>
          <p className="mt-1 text-xs text-muted-foreground">AI tools</p>
        </div>
        <div className="bg-card px-5 py-5">
          <p className="text-3xl font-bold tabular-nums">{criticalHigh}</p>
          <p className="mt-1 text-xs text-muted-foreground">Critical / High</p>
        </div>
        <div className="bg-card px-5 py-5">
          <p className="text-3xl font-bold tabular-nums">{totalAnalyzed.toLocaleString()}</p>
          <p className="mt-1 text-xs text-muted-foreground">
            Advisories scanned ({fixPct}% with fix)
          </p>
        </div>
      </div>
    </section>
  );
}
