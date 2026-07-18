import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import CveDetailPage from "@/app/cves/[id]/page";
import { AttributionChain } from "@/components/attribution-chain";
import {
  BugCommitTimeline,
  bugCommitSubjectKey,
} from "@/components/commit-timeline";
import type {
  AiSignalEntry,
  BugCommit,
  CveEntry,
  FixCommit,
} from "@/lib/types";

const dataFixture = vi.hoisted(() => ({
  current: null as CveEntry | null,
}));

vi.mock("@/lib/data", () => ({
  getCves: () => ({
    generated_at: "2026-07-17T00:00:00Z",
    total: dataFixture.current ? 1 : 0,
    cves: dataFixture.current ? [dataFixture.current] : [],
  }),
  getCveById: () => dataFixture.current,
}));

const bicSha = "a".repeat(40);
const firstFixSha = "b".repeat(40);
const secondFixSha = "c".repeat(40);

const sharedSignal: AiSignalEntry = {
  tool: "codex",
  signal_type: "co_author",
  matched_text: "Co-authored-by: Codex",
  confidence: 0.9,
};

function makeSubject(
  fixCommitSha: string,
  blamedFile: string,
  overrides: Partial<BugCommit> = {},
): BugCommit {
  return {
    sha: bicSha,
    author: "Developer",
    date: "2026-07-17T00:00:00Z",
    message: "Introduce vulnerable parser",
    ai_signals: [sharedSignal],
    blamed_file: blamedFile,
    blame_confidence: 0.95,
    screening_verification: null,
    fix_commit_sha: fixCommitSha,
    ...overrides,
  };
}

const fixCommits: readonly FixCommit[] = [
  {
    sha: firstFixSha,
    repo_url: "https://github.com/example/project",
    source: "osv",
  },
  {
    sha: secondFixSha,
    repo_url: "https://github.com/example/project",
    source: "ghsa",
  },
];

describe("bug-commit subject identity", () => {
  it("includes the fix, BIC, and blamed file", () => {
    expect(
      bugCommitSubjectKey(makeSubject(firstFixSha, "src/first.ts")),
    ).toBe(`${firstFixSha}:${bicSha}:src/first.ts`);
    expect(
      bugCommitSubjectKey(makeSubject(secondFixSha, "src/second.ts")),
    ).toBe(`${secondFixSha}:${bicSha}:src/second.ts`);
  });

  it("renders independent attribution chains for one BIC linked to two fixes", () => {
    const html = renderToStaticMarkup(
      <AttributionChain
        bugCommits={[
          makeSubject(firstFixSha, "src/parser.ts"),
          makeSubject(secondFixSha, "src/parser.ts"),
        ]}
        fixCommits={fixCommits}
        repoUrl="https://github.com/example/project"
      />,
    );

    expect(html).toContain(firstFixSha.slice(0, 7));
    expect(html).toContain(secondFixSha.slice(0, 7));
    expect(html.match(/Bug-Introducing Commit/g)).toHaveLength(2);
  });

  it("renders an independent timeline card for every subject", () => {
    const html = renderToStaticMarkup(
      <BugCommitTimeline
        commits={[
          makeSubject(firstFixSha, "src/parser.ts"),
          makeSubject(secondFixSha, "src/parser.ts"),
        ]}
        repoUrl="https://github.com/example/project"
      />,
    );

    expect(html.match(/src\/parser\.ts/g)).toHaveLength(2);
    expect(html).toContain(`Fix: ${firstFixSha.slice(0, 7)}`);
    expect(html).toContain(`Fix: ${secondFixSha.slice(0, 7)}`);
  });
});

describe("commit-level signal aggregation", () => {
  it("counts shared signals once and renders each subject verdict", async () => {
    const firstSubject = makeSubject(firstFixSha, "src/parser.ts", {
      verification: {
        verdict: "CONFIRMED",
        confidence: 0.95,
        models: ["gpt-5.4"],
        agent_verdicts: [
          {
            model: "gpt-5.4",
            verdict: "CONFIRMED",
            reasoning: "The first fix establishes causality.",
            confidence: 0.95,
            tool_calls_made: 3,
            steps_completed: 3,
            evidence: [],
          },
        ],
      },
    });
    const secondSubject = makeSubject(secondFixSha, "src/parser.ts", {
      verification: {
        verdict: "UNLIKELY",
        confidence: 0.7,
        models: ["claude-opus-4-6"],
        agent_verdicts: [
          {
            model: "claude-opus-4-6",
            verdict: "UNLIKELY",
            reasoning: "The second fix does not establish causality.",
            confidence: 0.7,
            tool_calls_made: 2,
            steps_completed: 2,
            evidence: [],
          },
        ],
      },
    });

    dataFixture.current = {
      id: "CVE-2026-9999",
      description: "A test vulnerability",
      severity: "HIGH",
      cvss: 8.1,
      cwes: ["CWE-20"],
      ecosystem: "npm",
      published: "2026-07-17",
      ai_tools: ["codex"],
      ai_involved: true,
      signal_source: "commit",
      languages: ["TypeScript"],
      confidence: 0.9,
      verified_by: "gpt-5.4",
      how_introduced: "An AI-authored commit skipped input validation.",
      verdict: "CONFIRMED",
      // Put the UNLIKELY subject first to prove the CVE summary does not adopt
      // an arbitrary subject verdict.
      bug_commits: [secondSubject, firstSubject],
      fix_commits: fixCommits,
      references: [],
    };

    const fixture = dataFixture.current;
    const page = await CveDetailPage({
      params: Promise.resolve({ id: fixture.id }),
    });
    const html = renderToStaticMarkup(page);

    // One page-level "Deep Verification" section; each verified subject is a
    // nested disclosure inside it.
    expect(html.match(/Deep Verification/g)).toHaveLength(1);
    expect(html).toContain("The first fix establishes causality.");
    expect(html).toContain("The second fix does not establish causality.");
    expect(html).toContain(`Fix ${firstFixSha.slice(0, 7)}`);
    expect(html).toContain(`Fix ${secondFixSha.slice(0, 7)}`);
    expect(html.match(/Co-authored-by: Codex/g)).toHaveLength(1);
    expect(html.match(/>CONFIRMED</g)).toHaveLength(2);
  });
});
