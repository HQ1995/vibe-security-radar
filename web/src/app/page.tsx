import { getCves, getStats } from "@/lib/data";
import { StatsCards } from "@/components/stats-cards";
import { RecentCvesTable } from "@/components/recent-cves-table";
import { DataFreshness } from "@/components/data-freshness";
import { compareCves } from "@/lib/sort";
import { TrendChart } from "@/components/trend-chart";
import { MonthArchive } from "@/components/month-archive";
import { Star, GitPullRequest } from "lucide-react";

export default function HomePage() {
  const stats = getStats();
  const cves = getCves();

  const recentCves = [...cves.cves]
    .sort((a, b) => compareCves(a, b, { key: "published", direction: "desc" }))
    .slice(0, 10);

  return (
    <main className="mx-auto max-w-6xl px-4 sm:px-6">
      <section className="pb-8 pt-10 sm:pt-12">
        <h1 className="text-3xl font-bold tracking-tight sm:text-4xl">
          Vibe Security Radar
        </h1>
        <p className="mt-2 max-w-xl text-base leading-relaxed text-muted-foreground">
          Real CVEs where AI-generated code introduced the vulnerability.
        </p>
        <p className="mt-1 text-sm text-muted-foreground">
          by{" "}
          <a
            href="https://gts3.org"
            target="_blank"
            rel="noopener noreferrer"
            className="font-medium text-primary underline underline-offset-4 transition-colors hover:text-primary/80"
          >
            Georgia Tech SSLab
          </a>
        </p>
        <p className="mt-2 text-xs text-muted-foreground/70">
          Actively developed. Results may contain errors or omissions.{" "}
          <a href="/about" className="underline underline-offset-2 hover:text-muted-foreground">
            How it works
          </a>
        </p>
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <a
            href="https://github.com/HQ1995/vibe-security-radar"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 rounded-lg bg-foreground px-4 py-2 text-sm font-semibold text-background transition-opacity hover:opacity-90"
          >
            <Star className="h-4 w-4" />
            Star on GitHub
          </a>
          <a
            href="https://github.com/HQ1995/vibe-security-radar/issues"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 rounded-lg border-2 border-foreground/20 px-4 py-2 text-sm font-semibold transition-colors hover:border-foreground/40 hover:text-primary"
          >
            <GitPullRequest className="h-4 w-4" />
            Contribute
          </a>
        </div>
        <div className="mt-3">
          <DataFreshness generatedAt={stats.generated_at} coverageFrom={stats.coverage_from} coverageTo={stats.coverage_to} />
        </div>
      </section>

      <div className="space-y-12 pb-16">
        <StatsCards stats={stats} />
        <div className="space-y-3">
          <TrendChart data={stats.by_month} />
          <MonthArchive data={stats.by_month} />
        </div>
        <RecentCvesTable cves={recentCves} />
      </div>
    </main>
  );
}
