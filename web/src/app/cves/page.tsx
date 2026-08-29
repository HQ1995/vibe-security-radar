import type { Metadata } from "next";

import { ResearchCaseExplorer } from "@/components/research-case-explorer";
import { getResearchCases, getResearchSnapshot } from "@/lib/research-data";

export const metadata: Metadata = {
  title: "Findings — Vibe Security Radar",
  description: "AI-contributed vulnerability findings with evidence status.",
};

export default function CvesPage() {
  const cases = [...getResearchCases()]
    .sort(
      (a, b) =>
        (b.published_at ?? "").localeCompare(a.published_at ?? "") ||
        a.case_id.localeCompare(b.case_id),
    )
    .map((item) => ({
      ...item,
      description: null,
      references: [],
      code_evidence: null,
      ir_chain: null,
    }));
  const snapshot = getResearchSnapshot().snapshot;

  return (
    <main className="mx-auto w-full max-w-[96rem] px-4 py-10 sm:px-6 sm:py-14 2xl:px-8 min-[1920px]:max-w-[112rem] min-[2400px]:max-w-[128rem]">
      <header className="mb-8">
        <p className="section-kicker">Findings</p>
        <h1 className="mt-3 text-4xl font-semibold tracking-[-0.04em]">
          All {cases.length} findings
        </h1>
        <p className="mt-3 max-w-2xl text-sm leading-6 text-muted-foreground">
          Open a finding to see its evidence, caveats, contributing change, and
          fix status.
        </p>
      </header>
      <ResearchCaseExplorer cases={cases} />
    </main>
  );
}
