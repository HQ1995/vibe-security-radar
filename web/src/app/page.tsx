import dynamic from "next/dynamic";
import { getCves, getStats } from "@/lib/data";
import { StatsCards } from "@/components/stats-cards";
import { RecentCvesTable } from "@/components/recent-cves-table";
import { DataFreshness } from "@/components/data-freshness";
import { compareCves } from "@/lib/sort";
import type { TrendChartProps } from "@/components/trend-chart";

const TrendChart = dynamic<TrendChartProps>(
  () => import("@/components/trend-chart").then((mod) => mod.TrendChart),
  {
    ssr: false,
    loading: () => (
      <section>
        <h2 className="mb-4 text-xl font-semibold">Vulnerabilities by Month</h2>
        <div className="h-72 w-full rounded-xl border border-border bg-card p-4 flex items-center justify-center text-sm text-muted-foreground">
          Loading chart...
        </div>
      </section>
    ),
  },
);

export default function HomePage() {
  const stats = getStats();
  const cves = getCves();

  const recentCves = [...cves.cves]
    .sort((a, b) => compareCves(a, b, { key: "published", direction: "desc" }))
    .slice(0, 10);

  return (
    <main className="mx-auto max-w-6xl space-y-10 px-4 py-10 sm:px-6">
      <section className="space-y-2">
        <h1 className="text-4xl font-bold tracking-tight">
          Vibe Security Radar
        </h1>
        <p className="text-lg text-muted-foreground">
          Tracking the security cost of vibe coding
        </p>
        <DataFreshness generatedAt={stats.generated_at} coverageFrom={stats.coverage_from} />
      </section>

      <StatsCards stats={stats} />

      <TrendChart data={stats.by_month} />

      <RecentCvesTable cves={recentCves} />
    </main>
  );
}
