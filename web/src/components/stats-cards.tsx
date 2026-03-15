import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { StatsData } from "@/lib/types";

interface StatsCardsProps {
  readonly stats: StatsData;
}

interface Metric {
  readonly label: string;
  readonly value: number | string;
  readonly detail?: string;
}

function computeMetrics(stats: StatsData): Metric[] {
  const totalCves = stats.total_cves;

  const aiToolsDetected = Object.keys(stats.by_tool).length;

  const criticalHigh =
    (stats.by_severity["CRITICAL"] ?? 0) + (stats.by_severity["HIGH"] ?? 0);

  const totalAnalyzed = stats.total_analyzed;
  const withFix = stats.with_fix_commits ?? 0;
  const withoutFix = totalAnalyzed - withFix;

  const fixPct = totalAnalyzed > 0 ? Math.round((withFix / totalAnalyzed) * 100) : 0;

  return [
    { label: "AI-Linked Vulnerabilities", value: totalCves },
    { label: "AI Tools Detected", value: aiToolsDetected },
    { label: "Critical / High", value: criticalHigh },
    {
      label: "Advisories Analyzed",
      value: totalAnalyzed.toLocaleString(),
      detail: `${withFix.toLocaleString()} with fix commits (${fixPct}%), ${withoutFix.toLocaleString()} without`,
    },
  ];
}

export function StatsCards({ stats }: StatsCardsProps) {
  const metrics = computeMetrics(stats);

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      {metrics.map((metric) => (
        <Card key={metric.label}>
          <CardHeader className="pb-0">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              {metric.label}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-3xl font-bold tabular-nums">{metric.value}</p>
            {metric.detail && (
              <p className="mt-1 text-xs text-muted-foreground">{metric.detail}</p>
            )}
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
