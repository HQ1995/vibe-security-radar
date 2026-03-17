import { getCves, getStats } from "@/lib/data";
import { StatsCards } from "@/components/stats-cards";
import { RecentCvesTable } from "@/components/recent-cves-table";
import { DataFreshness } from "@/components/data-freshness";
import { compareCves } from "@/lib/sort";
import { TrendChart } from "@/components/trend-chart";

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
        <div className="mt-3">
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
