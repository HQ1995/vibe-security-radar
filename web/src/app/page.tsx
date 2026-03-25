import { getCves, getStats } from "@/lib/data";
import { StatsCards } from "@/components/stats-cards";
import { RecentCvesTable } from "@/components/recent-cves-table";
import { DataFreshness } from "@/components/data-freshness";
import { compareCves } from "@/lib/sort";
import { TrendChart } from "@/components/trend-chart";
import { Star, GitPullRequest } from "lucide-react";

export default function HomePage() {
  const stats = getStats();
  const cves = getCves();

  const recentCves = [...cves.cves]
    .sort((a, b) => compareCves(a, b, { key: "published", direction: "desc" }))
    .slice(0, 10);

  return (
    <main className="mx-auto max-w-6xl px-4 sm:px-6">
      <section className="pb-10 pt-16">
        <h1 className="text-4xl font-bold tracking-tight sm:text-5xl">
          Vibe Security Radar
        </h1>
        <p className="mt-3 max-w-xl text-base leading-relaxed text-muted-foreground">
          Real CVEs where AI-generated code introduced the vulnerability.
        </p>
        <p className="mt-2 max-w-2xl text-xs leading-relaxed text-muted-foreground/70">
          Detection is based on git co-author trailers, bot emails, and commit
          message markers — not all AI-assisted code leaves these traces. This
          project is under active development; results may contain errors.
          See{" "}
          <a href="/about" className="underline underline-offset-2 hover:text-muted-foreground">
            methodology &amp; limitations
          </a>.
        </p>
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <a
            href="https://github.com/HQ1995/vibe-security-radar"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 rounded-md border border-border bg-muted/50 px-3 py-1.5 text-sm font-medium transition-colors hover:bg-muted hover:text-primary"
          >
            <Star className="h-3.5 w-3.5" />
            Star on GitHub
          </a>
          <a
            href="https://github.com/HQ1995/vibe-security-radar/issues"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 rounded-md border border-border bg-muted/50 px-3 py-1.5 text-sm font-medium transition-colors hover:bg-muted hover:text-primary"
          >
            <GitPullRequest className="h-3.5 w-3.5" />
            Contribute
          </a>
          <DataFreshness generatedAt={stats.generated_at} coverageFrom={stats.coverage_from} coverageTo={stats.coverage_to} />
        </div>
      </section>

      <div className="space-y-12 pb-16">
        <StatsCards stats={stats} />
        <TrendChart data={stats.by_month} />
        <RecentCvesTable cves={recentCves} />
      </div>
    </main>
  );
}
