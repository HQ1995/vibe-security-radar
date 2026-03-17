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
      {/* Hero */}
      <div className="relative overflow-hidden">
        {/* Glow behind the title */}
        <div
          aria-hidden="true"
          className="pointer-events-none absolute left-1/2 top-0 -z-10 h-[480px] w-[800px] -translate-x-1/2"
          style={{
            background:
              "radial-gradient(ellipse 100% 80% at 50% 0%, oklch(0.80 0.22 155 / 8%) 0%, transparent 70%)",
          }}
        />

        <div className="mx-auto max-w-6xl px-4 pb-12 pt-16 sm:px-6">
          <section className="mb-10">
            <h1 className="font-[family-name:var(--font-display)] text-5xl font-extrabold tracking-tight sm:text-6xl">
              Vibe Security
              <br />
              <span className="text-primary">Radar</span>
            </h1>
            <p className="mt-4 max-w-xl text-lg leading-relaxed text-muted-foreground">
              Real CVEs where AI-generated code introduced the vulnerability.
              We scan public advisories, trace fix commits back through git blame,
              and verify with an LLM investigator.
            </p>
            <div className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
              <DataFreshness generatedAt={stats.generated_at} coverageFrom={stats.coverage_from} coverageTo={stats.coverage_to} />
            </div>
          </section>

          <StatsCards stats={stats} />
        </div>
      </div>

      {/* Content */}
      <div className="mx-auto max-w-6xl space-y-12 px-4 pb-16 sm:px-6">
        <TrendChart data={stats.by_month} />
        <RecentCvesTable cves={recentCves} />
      </div>
    </main>
  );
}
