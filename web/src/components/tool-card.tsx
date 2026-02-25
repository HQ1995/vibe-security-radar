import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { getToolDisplayName, severityBadgeClass } from "@/lib/constants";

interface ToolCardProps {
  readonly tool: string;
  readonly count: number;
  readonly severities: Readonly<Record<string, number>>;
}

export function ToolCard({ tool, count, severities }: ToolCardProps) {
  const displayName = getToolDisplayName(tool);

  return (
    <Link href={`/cves?tool=${encodeURIComponent(tool)}`}>
      <Card className="transition-colors hover:border-primary/50">
        <CardHeader className="pb-2">
          <CardTitle className="text-lg">{displayName}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-3xl font-bold tabular-nums">
            {count}
            <span className="ml-2 text-sm font-normal text-muted-foreground">
              {count === 1 ? "vulnerability" : "vulnerabilities"}
            </span>
          </p>
          <div className="flex flex-wrap gap-1.5">
            {Object.entries(severities).map(([severity, severityCount]) => (
              <Badge key={severity} className={severityBadgeClass(severity)}>
                {severity} {severityCount}
              </Badge>
            ))}
          </div>
        </CardContent>
      </Card>
    </Link>
  );
}
