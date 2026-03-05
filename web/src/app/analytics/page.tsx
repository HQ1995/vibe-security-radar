import { getCves, getStats } from "@/lib/data";
import { buildToolData } from "@/lib/tool-utils";
import { buildLanguageData } from "@/lib/language-utils";
import { buildRepoData, topNWithTies } from "@/lib/repo-utils";
import { ToolCard } from "@/components/tool-card";
import { ToolDistributionChart } from "@/components/tool-distribution-chart";
import { LanguageCard } from "@/components/language-card";
import { LanguageDistributionChart } from "@/components/language-distribution-chart";
import { RepoCard } from "@/components/repo-card";

export const metadata = {
  title: "Analytics - Vibe Security Radar",
  description:
    "Vulnerability distribution by AI tool and programming language",
};

export default function AnalyticsPage() {
  const stats = getStats();
  const cves = getCves();

  const toolData = buildToolData(stats.by_tool, cves.cves);
  const languageData = buildLanguageData(stats.by_language, cves.cves);
  const repoData = topNWithTies(buildRepoData(stats.by_repo, cves.cves), 10);

  return (
    <main className="mx-auto max-w-6xl space-y-10 px-4 py-10 sm:px-6">
      <section className="space-y-2">
        <h1 className="text-4xl font-bold tracking-tight">Analytics</h1>
        <p className="text-lg text-muted-foreground">
          Vulnerability distribution by AI tool and programming language
        </p>
      </section>

      {/* Tool distribution */}
      <ToolDistributionChart data={stats.by_tool} />

      <section>
        <h2 className="mb-4 text-xl font-semibold">Tools Overview</h2>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {toolData.map((td) => (
            <ToolCard
              key={td.tool}
              tool={td.tool}
              count={td.count}
              severities={td.severities}
            />
          ))}
        </div>
      </section>

      {/* Language distribution */}
      {languageData.length > 0 && (
        <>
          <LanguageDistributionChart data={stats.by_language} />

          <section>
            <h2 className="mb-4 text-xl font-semibold">Languages Overview</h2>
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
              {languageData.map((ld) => (
                <LanguageCard
                  key={ld.language}
                  language={ld.language}
                  count={ld.count}
                  severities={ld.severities}
                />
              ))}
            </div>
          </section>
        </>
      )}

      {/* Top repositories */}
      {repoData.length > 0 && (
        <section>
          <h2 className="mb-4 text-xl font-semibold">Top Repositories</h2>
          <div className="overflow-x-auto">
            <div className="flex gap-4">
              {repoData.map((rd) => (
                <div key={rd.repo} className="w-72 shrink-0">
                  <RepoCard
                    repo={rd.repo}
                    count={rd.count}
                    severities={rd.severities}
                  />
                </div>
              ))}
            </div>
          </div>
        </section>
      )}
    </main>
  );
}
