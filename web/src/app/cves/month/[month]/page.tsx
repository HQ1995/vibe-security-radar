import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { getCves, getStats } from "@/lib/data";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ToolIcon } from "@/components/tool-icon";
import { severityBadgeClass, getToolDisplayName } from "@/lib/constants";
import { formatPublished } from "@/lib/commit-utils";
import {
  formatMonthLabel,
  computeSeverityBreakdown,
  computeToolBreakdown,
  sortCvesByPriority,
} from "@/lib/month-utils";

// --- Static generation ---

export function generateStaticParams() {
  const stats = getStats();
  return stats.by_month.map((entry) => ({ month: entry.month }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ month: string }>;
}): Promise<Metadata> {
  const { month } = await params;
  const label = formatMonthLabel(month);
  return {
    title: `${label} Vulnerabilities - Vibe Security Radar`,
    description: `AI-linked vulnerabilities discovered in ${label}`,
  };
}

// --- Helpers ---

function getCvesForMonth(month: string) {
  const data = getCves();
  return data.cves.filter((cve) => cve.published.startsWith(month));
}

// --- Page component ---

export default async function MonthDetailPage({
  params,
}: {
  params: Promise<{ month: string }>;
}) {
  const { month } = await params;

  // Validate month format
  if (!/^\d{4}-\d{2}$/.test(month)) {
    notFound();
  }

  const cves = getCvesForMonth(month);
  if (cves.length === 0) {
    notFound();
  }

  const label = formatMonthLabel(month);
  const severities = computeSeverityBreakdown(cves);
  const tools = computeToolBreakdown(cves);

  return (
    <main className="mx-auto max-w-6xl space-y-8 px-4 py-10 sm:px-6">
      {/* Header */}
      <div className="space-y-4">
        <Link
          href="/"
          className="inline-flex items-center gap-1 text-sm text-muted-foreground transition-colors hover:text-foreground"
        >
          &larr; Back to Dashboard
        </Link>
        <h1 className="text-3xl font-bold tracking-tight sm:text-4xl">
          {label}
        </h1>
        <p className="text-lg text-muted-foreground">
          {cves.length} {cves.length === 1 ? "vulnerability" : "vulnerabilities"} with
          AI coding tool involvement
        </p>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {/* Total */}
        <Card>
          <CardHeader className="pb-0">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Total Vulnerabilities
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-3xl font-bold tabular-nums">{cves.length}</p>
          </CardContent>
        </Card>

        {/* By severity */}
        <Card>
          <CardHeader className="pb-0">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              By Severity
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {severities.map(({ severity, count }) => (
                <Badge key={severity} className={severityBadgeClass(severity)}>
                  {severity} ({count})
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* By tool */}
        <Card>
          <CardHeader className="pb-0">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              AI Tools Involved
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {tools.map(({ tool, count }) => (
                <span
                  key={tool}
                  className="inline-flex items-center gap-1.5 rounded-md border border-border bg-muted/50 px-2 py-1 text-sm"
                >
                  <ToolIcon tool={tool} size={14} />
                  {getToolDisplayName(tool)}
                  <span className="font-mono text-xs text-muted-foreground">
                    ({count})
                  </span>
                </span>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* CVE list */}
      <section className="space-y-4">
        <h2 className="text-xl font-semibold">All Vulnerabilities</h2>
        <div className="space-y-3">
          {sortCvesByPriority(cves).map((cve) => (
              <Link
                key={cve.id}
                href={`/cves/${cve.id}`}
                className="block rounded-xl border border-border bg-card p-4 transition-colors hover:bg-muted/50"
              >
                <div className="flex flex-wrap items-start gap-3">
                  <div className="flex-1 min-w-0 space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-sm font-semibold text-primary">
                        {cve.id}
                      </span>
                      <Badge className={severityBadgeClass(cve.severity)}>
                        {cve.severity}
                      </Badge>
                      {cve.cvss !== null && cve.cvss > 0 && (
                        <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
                          CVSS {cve.cvss.toFixed(1)}
                        </span>
                      )}
                    </div>
                    <p className="text-sm text-muted-foreground line-clamp-2">
                      {cve.description}
                    </p>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <div className="flex items-center gap-1">
                      {cve.ai_tools.map((tool) => (
                        <ToolIcon key={tool} tool={tool} size={18} />
                      ))}
                    </div>
                    <span className="text-xs text-muted-foreground whitespace-nowrap">
                      {formatPublished(cve.published) || "—"}
                    </span>
                  </div>
                </div>
              </Link>
            ))}
        </div>
      </section>
    </main>
  );
}
