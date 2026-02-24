import { getCves, getStats } from "@/lib/data";
import { ToolCard } from "@/components/tool-card";
import { ToolDistributionChart } from "@/components/tool-distribution-chart";

interface ToolData {
  readonly tool: string;
  readonly count: number;
  readonly severities: Readonly<Record<string, number>>;
}

function buildToolData(
  byTool: Readonly<Record<string, number>>,
  cves: readonly { readonly ai_tools: readonly string[]; readonly severity: string }[],
): readonly ToolData[] {
  return Object.entries(byTool)
    .map(([tool, count]) => {
      const toolCves = cves.filter((c) => c.ai_tools.includes(tool));
      const severities: Record<string, number> = {};
      for (const cve of toolCves) {
        severities[cve.severity] = (severities[cve.severity] ?? 0) + 1;
      }
      return { tool, count, severities } as const;
    })
    .sort((a, b) => b.count - a.count);
}

export default function ToolsPage() {
  const stats = getStats();
  const cves = getCves();

  const toolData = buildToolData(stats.by_tool, cves.cves);

  return (
    <main className="mx-auto max-w-6xl space-y-10 px-4 py-10 sm:px-6">
      <section className="space-y-2">
        <h1 className="text-4xl font-bold tracking-tight">
          AI Tools Analysis
        </h1>
        <p className="text-lg text-muted-foreground">
          CVE distribution across AI coding tools
        </p>
      </section>

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
    </main>
  );
}
