import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
    { label: "AI-Linked Vulnerabilities", value: totalCves },
    { label: "AI Tools Detected", value: aiToolsDetected },
    { label: "Critical / High", value: criticalHigh },
  ];

  return (
    <div className="space-y-3">
      {/* Hero metrics — findings */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        {findings.map((m) => (
          <Card key={m.label}>
            <CardHeader className="pb-0">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                {m.label}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-3xl font-bold tabular-nums">{m.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Coverage bar — secondary context */}
      <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1 rounded-lg border bg-muted/40 px-4 py-2.5 text-sm text-muted-foreground">
        <span>
          <span className="font-semibold tabular-nums text-foreground">
            {totalAnalyzed.toLocaleString()}
          </span>{" "}
          advisories analyzed
        </span>
        <span className="hidden sm:inline" aria-hidden="true">
          ·
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
