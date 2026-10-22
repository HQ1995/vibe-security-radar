import type { Metadata } from "next";

import { ResearchCaseExplorer } from "@/components/research-case-explorer";
import { pageMetadata } from "@/lib/page-metadata";
import { getResearchCases, getResearchLabels } from "@/lib/research-data";
import { toFindingRow } from "@/lib/research-format";

export const metadata: Metadata = pageMetadata({
  title: "Findings",
  description:
    "Search every published vulnerability traced to AI-generated code by CVE, GHSA, repository, AI tool, root cause, language and month.",
  path: "/cves",
});

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
        <h1 className="text-3xl font-semibold tracking-[-0.03em]">
          Findings
        </h1>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground">
          Published vulnerabilities where an AI-assisted change introduced the
          flaw, exposed the vulnerable path, or left a security fix incomplete.
          Open a finding to see its evidence, caveats, contributing change, and
          fix status.
        </p>
      </header>
      <ResearchCaseExplorer cases={cases} labels={getResearchLabels()} />
    </main>
  );
}
