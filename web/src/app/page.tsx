import { getCves, getStats } from "@/lib/data";
import { StatsCards } from "@/components/stats-cards";
import { TrendChart } from "@/components/trend-chart";
import { RecentCvesTable } from "@/components/recent-cves-table";
import { DataFreshness } from "@/components/data-freshness";
import { compareCves } from "@/lib/sort";

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
        <DataFreshness generatedAt={stats.generated_at} />
      </section>

      <StatsCards stats={stats} />

      <TrendChart data={stats.by_month} />

      <RecentCvesTable cves={recentCves} />
    </main>
  );
}
