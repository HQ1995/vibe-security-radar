import type { Metadata } from "next";

import { ResearchCaseExplorer } from "@/components/research-case-explorer";
import { getResearchCases } from "@/lib/research-data";

export const metadata: Metadata = {
  title: "Cases — Vibe Security Radar",
  description: "All advisory-level AI vulnerability research cases.",
};

export default function CvesPage() {
  const cases = [...getResearchCases()].sort(
    (a, b) =>
      (b.published_at ?? "").localeCompare(a.published_at ?? "") ||
      a.case_id.localeCompare(b.case_id),
  );

  return (
    <main className="mx-auto w-full max-w-[96rem] px-4 py-10 sm:px-6 sm:py-14 2xl:px-8 min-[1920px]:max-w-[112rem] min-[2400px]:max-w-[128rem]">
      <header className="mb-8">
        <p className="section-kicker">Case index</p>
        <h1 className="mt-3 text-4xl font-semibold tracking-[-0.04em]">
          All {cases.length} cases
        </h1>
        <p className="mt-3 max-w-2xl text-sm leading-6 text-muted-foreground">
          One row per first-party advisory. Open a case to see the AI change,
          root cause, and minimum fix.
        </p>
      </header>
      <ResearchCaseExplorer cases={cases} />
    </main>
  );
}
