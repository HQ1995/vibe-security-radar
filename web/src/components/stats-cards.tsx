import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { StatsData } from "@/lib/types";

interface StatsCardsProps {
  readonly stats: StatsData;
}

function computeMetrics(stats: StatsData) {
  const totalCves = stats.total_cves;

  const aiToolsDetected = Object.keys(stats.by_tool).length;

  const criticalHigh =
    (stats.by_severity["CRITICAL"] ?? 0) + (stats.by_severity["HIGH"] ?? 0);

  const ecosystems = Object.keys(stats.by_ecosystem).length;

  return [
    { label: "Total CVEs", value: totalCves },
    { label: "AI Tools Detected", value: aiToolsDetected },
    { label: "Critical / High", value: criticalHigh },
    { label: "Ecosystems", value: ecosystems },
  ] as const;
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
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
