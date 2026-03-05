import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { severityBadgeClass } from "@/lib/constants";
import type { ReactNode } from "react";

interface EntityCardProps {
  readonly href: string;
  readonly label: string;
  readonly icon: ReactNode;
  readonly count: number;
  readonly severities: Readonly<Record<string, number>>;
}

export function EntityCard({
  href,
  label,
  icon,
  count,
  severities,
}: EntityCardProps) {
  return (
    <Link href={href}>
      <Card className="transition-colors hover:border-primary/50">
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-lg min-w-0">
            {icon}
            <span className="truncate" title={label}>{label}</span>
          </CardTitle>
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
