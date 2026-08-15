import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import ErrorPage from "@/app/error";
import AboutPage from "@/app/about/page";
import HomePage from "@/app/page";
import { CanonicalCaseEvidence } from "@/components/canonical-case-evidence";
import { getLangIconKey } from "@/components/language-distribution-chart";
import { getIconDimensions } from "@/components/tool-icon";
import { ReviewPathBadge } from "@/components/review-path-badge";
import {
  filterResearchCases,
  ResearchCaseExplorer,
} from "@/components/research-case-explorer";
import { ResearchCaseTable } from "@/components/research-case-table";
import { DataFreshness } from "@/components/data-freshness";
import { TrendChart } from "@/components/trend-chart";
import { ToolDistributionChart } from "@/components/tool-distribution-chart";
import {
  formatContributionClass,
  getAiToolLabel,
  getResearchCaseById,
  getResearchCases,
} from "@/lib/research-data";

describe("ReviewPathBadge", () => {
  it("keeps model provenance without presenting the model as an authority", () => {
    const html = renderToStaticMarkup(
      <ReviewPathBadge verifiedBy="claude-opus-4-6-thinking,gpt-5.4-high" />,
    );

    expect(html).toContain("block truncate");
    expect(html).toContain("GPT-5.4 High trace");
    expect(html).toContain("Investigation provenance:");
    expect(html).toContain("not publication authority");
    expect(html).not.toContain("Verified by");
  });
});

describe("DataFreshness", () => {
  it("shows the generation timestamp and advisory cutoff together", () => {
    const html = renderToStaticMarkup(
      <DataFreshness
        generatedAt="2026-08-09T09:41:55+00:00"
        coverageFrom="2025-05-01"
        coverageTo="2026-03-31"
      />,
    );

    expect(html).toContain("Aug 9, 2026");
    expect(html).toContain("09:41 UTC");
    expect(html).toContain("advisory coverage");
    expect(html).toContain("Mar 31, 2026");
  });
});

describe("server-rendered charts", () => {
  it("renders trend and distribution data without a client chart runtime", () => {
    const trend = renderToStaticMarkup(
      <TrendChart
        data={[
          { month: "2026-02", count: 5 },
          { month: "2026-03", count: 23 },
        ]}
        caseCount={28}
        datedCount={28}
        unknownDateCount={0}
        sourceCutoff="2026-08-10T04:01:13.999999+00:00"
      />,
    );
    const distribution = renderToStaticMarkup(
      <ToolDistributionChart
        data={{ claude_code: 3, github_copilot: 1, openai_codex: 1 }}
        totalCves={5}
      />,
    );

    expect(trend).toContain("Feb 2026: 5 cases");
    expect(trend).toContain("Mar 2026: 23 cases");
    expect(trend).toContain("Disclosures over time");
    expect(distribution).toContain("3 · 60%");
    expect(distribution).toContain("chatgpt.png");
    expect(trend + distribution).not.toContain("recharts");
    expect(trend).not.toContain("min-w-[760px]");
  });
});

describe("homepage hierarchy", () => {
  it("keeps the full table on the case index", () => {
    const html = renderToStaticMarkup(<HomePage />);

    expect(html).toContain("Vibe Security Radar");
    expect(html).toContain("See the vulnerable code and fix");
    expect(html).toContain("Browse all 168 cases");
    expect(html).toContain("Star on GitHub");
    expect(html).toContain("Peak advisory month");
    expect(html).toContain("Most common AI tool");
    expect(html).toContain("Most represented project");
    expect(html).toContain("Media coverage");
    expect(html).toContain("Where the vulnerable code lives");
    expect(html).toContain("Repositories with the most cases");
    expect(html).toContain("/icons/tools/claude_code.svg");
    expect(html).toContain("/icons/tools/github_copilot.svg");
    expect(html).toContain("chatgpt.png");
    expect(html).not.toContain("/icons/tools/openai_codex_dark.svg");
    expect(html).toContain("What counts as an AI-contributed vulnerability?");
    expect(html).not.toContain("All 168 research cases");
  });
});

describe("method page", () => {
  it("keeps the public method short and scannable", () => {
    const html = renderToStaticMarkup(<AboutPage />);

    expect(html).toContain("Evidence before attribution");
    expect(html).toContain("Match the advisory");
    expect(html).toContain("Locate the AI change");
    expect(html).toContain("Prove cause and fix");
    expect(html).toContain("Confirm the release");
    expect(html).not.toContain("AI provenance signals");
    expect(html).not.toContain("Stage 6");
    expect(html).not.toContain("details");
  });
});

describe("canonical case evidence", () => {
  it("searches and filters the full case index", () => {
    const cases = getResearchCases();
    const html = renderToStaticMarkup(<ResearchCaseExplorer cases={cases} />);
    const filtered = filterResearchCases(cases, {
      query: "go-git",
      cause: "path_link",
      contribution: "AI_INCOMPLETE_REMEDIATION",
      tool: "Claude",
      language: "Go",
      repository: "go-git/go-git",
      month: "2026-08",
    });

    expect(html).toContain("CVE, GHSA, or repository");
    expect(html).toContain("All root causes");
    expect(html).toContain("All contribution types");
    expect(html).toContain("All tools");
    expect(html).toContain("All languages");
    expect(html).toContain("All repositories");
    expect(html).toContain("All months");
    expect(html).toContain("Page 1 of 9");
    expect(filtered.map((item) => item.case_id)).toEqual([
      "GHSA-HC8V-WWC9-VGXM",
    ]);
  });

  it("renders the complete case table", () => {
    const html = renderToStaticMarkup(
      <ResearchCaseTable cases={getResearchCases()} />,
    );

    expect(
      html.match(/class="border-t border-border align-top"/g),
    ).toHaveLength(168);
    expect(html).toContain("sm:grid-cols-2 xl:hidden");
    expect(html).toContain(
      "hidden overflow-x-auto border-y border-border xl:block",
    );
    expect(html).toContain("All 168 research cases");
    expect(html).toContain("CVE-2026-71556");
    expect(html).toContain("/icons/languages/go.svg");
    expect(html).toContain("/icons/tools/claude_code.svg");
  });

  it("keeps every case reachable through identities, facets, and evidence", () => {
    const cases = getResearchCases();
    const search = (query: string) =>
      filterResearchCases(cases, {
        query,
        cause: "",
        contribution: "",
        tool: "",
        language: "",
        repository: "",
        month: "",
      });

    for (const item of cases) {
      expect(search(item.case_id).map(({ case_id }) => case_id)).toContain(
        item.case_id,
      );
      for (const value of item.aliases) {
        expect(search(value).map(({ case_id }) => case_id)).toContain(
          item.case_id,
        );
      }
      for (const value of [
        ...item.candidate_set,
        ...item.carrier_set,
        ...item.minimum_fix_set,
      ]) {
        expect(search(value)).toContain(item);
      }
      expect(
        filterResearchCases(cases, {
          query: item.repository ?? item.case_id,
          cause: item.cause_category ?? "",
          contribution: item.contribution_class,
          tool: getAiToolLabel(item),
          language: item.repository_metadata.language,
          repository: item.repository!,
          month: item.published_at?.slice(0, 7) ?? "undated",
        }),
      ).toContain(item);
    }

    expect(search("kind")).toHaveLength(0);
    expect(search("2026-08-07").length).toBeGreaterThan(0);
    expect(search("Date unavailable")).toHaveLength(0);
    expect(
      filterResearchCases(cases, {
        query: "",
        cause: "",
        contribution: "",
        tool: "",
        language: "",
        repository: "",
        month: "undated",
      }),
    ).toHaveLength(0);
    expect(formatContributionClass("AI_NEW_SURFACE_CONTRIBUTOR")).toBe(
      "New attack surface",
    );
    expect(formatContributionClass("AI_ROOT_NEW_COMPONENT")).toBe(
      "New vulnerable component",
    );
  });

  it("assigns a non-empty case_id and gates object to every case", () => {
    for (const item of getResearchCases()) {
      expect(item.case_id).toBeTruthy();
      expect(item.gates).toBeTruthy();
      expect(Object.keys(item.gates).length).toBeGreaterThan(0);
    }
  });

  it("shows only the admitted candidate and exact fix for CVE-2026-34218", () => {
    const item = getResearchCaseById("CVE-2026-34218");
    expect(item).not.toBeNull();

    const html = renderToStaticMarkup(<CanonicalCaseEvidence item={item!} />);

    expect(html).toContain("What AI did");
    expect(html).toContain("Startup ordering drops the merged rules");
    expect(html).toContain("5a887953c4");
    expect(html).toContain("56d617b778");
    expect(html).toContain("-server.applyPolicyToFilter()");
    expect(html).toContain("+server.applyPolicyToFilter()");
    expect(html).not.toContain("AI-assisted vulnerable code");
    expect(html).toContain("Root cause");
    expect(html).toContain("AI-assisted fix: Claude Code");
    expect(html).not.toContain("ddfdacb263");
    expect(html).not.toContain("Verified by");
  });

  it("shows audited fix authorship without unknown labels", () => {
    const humanMarked = getResearchCaseById("CVE-2026-18446");
    const aiMarked = getResearchCaseById("GHSA-JM78-9FVV-MHGR");

    expect(
      renderToStaticMarkup(<CanonicalCaseEvidence item={humanMarked!} />),
    ).toContain("Fix by Matteo Collina · no AI marker found");
    expect(
      renderToStaticMarkup(<CanonicalCaseEvidence item={aiMarked!} />),
    ).toContain("AI-assisted fix: OpenAI GPT/Codex · Byron");
  });

  it("explains incomplete remediation without exposing an internal mechanism key", () => {
    const item = getResearchCaseById("CVE-2026-71556");
    expect(item).not.toBeNull();

    const html = renderToStaticMarkup(<CanonicalCaseEvidence item={item!} />);

    expect(html).toContain("AI change");
    expect(html).toContain("wrapped six worktree write operations");
    expect(html).toContain("s/config");
    expect(html).toContain("validWritePath");
    expect(html).toContain("AI-assisted fix: Claude Code");
    expect(html).toContain(
      "/blob/d83871ed0314f604e417f40733f762acfdcbc35c/worktree_fs.go",
    );
    expect(html).not.toContain(
      "go-git.worktreeFilesystem.validPath.symlink-follow",
    );
  });
});

describe("chart icon contracts", () => {
  it("uses the official ChatGPT app icon", () => {
    const icon = readFileSync("public/icons/tools/chatgpt.png");
    expect(createHash("sha256").update(icon).digest("hex")).toBe(
      "e799e2fa0d4149a2ec28fc595c8bfb4990bcbb478649791b42acff7cde6e805e",
    );
  });

  it("skips unavailable language assets", () => {
    expect(getLangIconKey("TypeScript")).toBe("typescript");
    expect(getLangIconKey("GitHub Actions")).toBeNull();
  });

  it("preserves non-square tool icon aspect ratios", () => {
    expect(getIconDimensions("github_copilot", 18)).toEqual({
      width: 18,
      height: 15,
    });
    expect(getIconDimensions("cursor", 18)).toEqual({
      width: 18,
      height: 21,
    });
  });
});

describe("global error page", () => {
  it("uses a stable user-safe message", () => {
    const html = renderToStaticMarkup(
      <ErrorPage
        error={new Error("database credential: secret")}
        reset={() => undefined}
      />,
    );

    expect(html).toContain(
      "An unexpected error occurred while rendering this page.",
    );
    expect(html).not.toContain("database credential");
  });
});
