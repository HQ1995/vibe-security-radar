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
      <div className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-border bg-border">
        <div className="bg-card px-5 py-5">
          <p className="text-3xl font-bold tabular-nums">{totalCves}</p>
          <p className="mt-1 text-xs text-muted-foreground">Verified AI-causal lower bound</p>
        </div>
        <div className="bg-card px-5 py-5">
          <p className="text-3xl font-bold tabular-nums">{criticalHigh}</p>
          <p className="mt-1 text-xs text-muted-foreground">Critical / High</p>
        </div>
      </div>
      <p className="mt-3 text-xs tabular-nums text-muted-foreground">
        {aiToolsDetected} AI tools &middot;{" "}
        {totalAnalyzed.toLocaleString()} advisories scanned ({fixPct}% with
        fix)
      </p>
      {stats.inventory ? (
        <p className="mt-1 text-xs tabular-nums text-muted-foreground">
          {stats.inventory.detector_candidate_count.toLocaleString()} detector candidates
          {" · "}
          {stats.inventory.pending_adjudication_count.toLocaleString()} awaiting independent review
          {" · "}
          inventory through {stats.inventory.coverage_to || "unknown cutoff"}
        </p>
      ) : null}
    </section>
  );
}
