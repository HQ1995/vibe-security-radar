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

  const findings = [
    { label: "AI-Linked Vulnerabilities", value: totalCves, accent: "text-primary" },
    { label: "AI Tools Detected", value: aiToolsDetected, accent: "text-foreground" },
    { label: "Critical / High", value: criticalHigh, accent: "text-amber-400" },
  ];

  return (
    <div className="space-y-3">
      {/* Hero metrics */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        {findings.map((m) => (
          <div
            key={m.label}
            className="rounded-xl border border-border/60 bg-card/60 px-5 py-4 backdrop-blur-sm"
          >
            <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
              {m.label}
            </p>
            <p className={`mt-1 text-3xl font-bold tabular-nums ${m.accent}`}>
              {m.value}
            </p>
          </div>
        ))}
      </div>

      {/* Coverage context */}
      <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1 rounded-lg border border-border/40 bg-muted/30 px-4 py-2.5 text-sm text-muted-foreground">
        <span>
          <span className="font-semibold tabular-nums text-foreground">
            {totalAnalyzed.toLocaleString()}
          </span>{" "}
          advisories analyzed
        </span>
        <span className="hidden sm:inline text-border" aria-hidden="true">
          |
        </span>
        <span>
          <span className="font-semibold tabular-nums text-foreground">
            {withFix.toLocaleString()}
          </span>{" "}
          with fix commits ({fixPct}%)
        </span>
      </div>
    </div>
  );
}
