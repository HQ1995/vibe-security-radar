import type { Metadata } from "next";

import { ResearchCaseExplorer } from "@/components/research-case-explorer";
import { getResearchCases, getResearchLabels } from "@/lib/research-data";
import { toFindingRow } from "@/lib/research-format";

export const metadata: Metadata = {
  title: "Findings",
  description:
    "Search every AI-contributed vulnerability finding by advisory, repository, AI tool, root cause, language and month.",
  alternates: { canonical: "/cves" },
};

export default function CvesPage() {
  const cases = [...getResearchCases()]
    .sort(
      (a, b) =>
        (b.published_at ?? "").localeCompare(a.published_at ?? "") ||
        a.case_id.localeCompare(b.case_id),
    )
    .map(toFindingRow);
  return (
    <main className="page-container py-8 sm:py-12">
      <header className="mb-6">
        <h1 className="text-3xl font-semibold tracking-[-0.035em] sm:text-4xl">
          All {cases.length} findings
        </h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
          Open a finding to see its evidence, caveats, contributing change, and
          fix status.
        </p>
      </header>
      <ResearchCaseExplorer cases={cases} labels={getResearchLabels()} />
    </main>
  );
}
