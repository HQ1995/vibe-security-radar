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
    <main>
      {/* Hero + Stats — gradient backdrop */}
      <div className="relative overflow-hidden border-b border-border">
        {/* Gradient mesh */}
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-0 -z-10"
          style={{
            background:
              "radial-gradient(ellipse 80% 60% at 50% 0%, oklch(0.22 0.06 265 / 40%) 0%, transparent 70%), " +
              "radial-gradient(ellipse 50% 50% at 80% 20%, oklch(0.20 0.08 195 / 25%) 0%, transparent 60%)",
          }}
        />

        <div className="mx-auto max-w-6xl space-y-8 px-4 pb-10 pt-12 sm:px-6">
          <section className="space-y-3">
            <h1 className="text-4xl font-bold tracking-tight sm:text-5xl">
              Vibe Security Radar
            </h1>
            <p className="max-w-2xl text-lg text-muted-foreground">
              Tracking the security cost of vibe coding — real CVEs where
              AI-generated code introduced the vulnerability.
            </p>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
              <DataFreshness generatedAt={stats.generated_at} coverageFrom={stats.coverage_from} coverageTo={stats.coverage_to} />
              <span className="text-xs text-amber-500/80">
                Under active development — data may contain inaccuracies
              </span>
            </div>
          </section>

          <StatsCards stats={stats} />
        </div>
      </div>

      {/* Content */}
      <div className="mx-auto max-w-6xl space-y-10 px-4 py-10 sm:px-6">
        <TrendChart data={stats.by_month} />
        <RecentCvesTable cves={recentCves} />
      </div>
    </main>
  );
}
