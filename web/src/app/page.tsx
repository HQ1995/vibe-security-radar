import { getCves, getStats } from "@/lib/data";
import { StatsCards } from "@/components/stats-cards";
import { TrendChart } from "@/components/trend-chart";
import { RecentCvesTable } from "@/components/recent-cves-table";

export default function HomePage() {
  const stats = getStats();
  const cves = getCves();

  return (
    <main className="mx-auto max-w-6xl space-y-10 px-4 py-10 sm:px-6">
      <section className="space-y-2">
        <h1 className="text-4xl font-bold tracking-tight">
          Vibe Security Radar
        </h1>
        <p className="text-lg text-muted-foreground">
          Tracking the security cost of vibe coding
        </p>
      </section>

      <StatsCards stats={stats} />

      <TrendChart data={stats.by_month} />

      <RecentCvesTable cves={cves.cves.slice(0, 10)} />
    </main>
  );
}
