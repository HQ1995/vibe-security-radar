import researchData from "@/generated/research-data.json";

export interface ResearchGateSet {
  readonly identity: string;
  readonly ai_hunk: string;
  readonly topology: string;
  readonly but_for: string;
  readonly fix_reversal: string;
  readonly release: string;
  readonly uniqueness: string;
}

export interface ResearchCodeHunk {
  readonly file: string;
  readonly code: string;
  readonly annotation: string;
}

export interface ResearchCodeEvidence {
  readonly ai_marker: string;
  readonly fix_marker?: string;
  readonly candidate_url: string;
  readonly fix_url: string;
  readonly advisory_url: string;
  readonly summary: string;
  readonly steps: readonly {
    readonly title: string;
    readonly detail: string;
  }[];
  readonly candidate_hunks: readonly ResearchCodeHunk[];
  readonly fix_hunks: readonly ResearchCodeHunk[];
  readonly comparison_hunks: readonly ResearchCodeHunk[];
  readonly candidate_patch_sha256: string | null;
  readonly fix_patch_sha256: string | null;
}

export interface ResearchRelease {
  readonly kind?: string;
  readonly sha?: string;
  readonly tag?: string;
  readonly version?: string;
  readonly [key: string]: unknown;
}

export interface ResearchCase {
  readonly case_id: string;
  readonly aliases: readonly string[];
  readonly repository: string | null;
  readonly repository_metadata: {
    readonly full_name: string;
    readonly language: string;
    readonly archived: boolean;
  };
  readonly contribution_class: string;
  readonly candidate_set: readonly string[];
  readonly carrier_set: readonly string[];
  readonly minimum_fix_set: readonly string[];
  readonly gates: ResearchGateSet;
  readonly vulnerable_release: ResearchRelease | null;
  readonly fixed_release: ResearchRelease | null;
  readonly published_at: string | null;
  readonly severity: string | null;
  readonly cwes: readonly string[];
  readonly description: string | null;
  readonly references: readonly string[];
  readonly mechanism_key: string | null;
  readonly mechanism: string | null;
  readonly scope_statement: string | null;
  readonly cause_category: string | null;
  readonly ai_provenance: {
    readonly family: string | null;
    readonly coverage: "complete" | "generic" | "partial" | "unresolved";
    readonly candidate_count: number;
    readonly named_candidate_count: number;
    readonly note?: string;
  };
  readonly fix_authorship: {
    readonly classification: "ai_assisted" | "no_ai_marker" | "mixed";
    readonly families: readonly string[];
    readonly fixes: readonly {
      readonly sha: string;
      readonly classification: "ai_assisted" | "no_ai_marker";
      readonly author: { readonly name: string; readonly email: string };
    }[];
  };
  readonly code_evidence: ResearchCodeEvidence | null;
  readonly ir_chain?: {
    readonly original_advisory_ids: readonly string[];
    readonly original_mechanism: string | null;
    readonly original_sink: string | null;
    readonly original_author_kind: string | null;
    readonly original_author_name: string | null;
    readonly original_sha: string | null;
    readonly attempted_remediation: {
      readonly candidate_shas: readonly string[];
      readonly changed: string;
      readonly missed: string;
    } | null;
    readonly residual_bypass: string | null;
    readonly final_closure: {
      readonly minimum_fix_shas: readonly string[];
      readonly closed: string;
    } | null;
  } | null;
}

export interface ResearchMonth {
  readonly month: string;
  readonly count: number;
}

export interface ResearchDistributionItem {
  readonly key: string;
  readonly label: string;
  readonly count: number;
  readonly definition?: string;
}

export interface ResearchAiCommitCensus {
  readonly window: { readonly since: string; readonly until: string };
  readonly repos_scanned: number;
  readonly repos_missing: readonly string[];
  readonly total_commits: number;
  readonly marked_ai_commits: number;
  readonly families: Readonly<
    Record<
      string,
      {
        readonly trailer: number;
        readonly author: number;
        readonly text: number;
        readonly marked: number;
      }
    >
  >;
}

const snapshot = researchData as {
  readonly snapshot: {
    readonly status: string;
    readonly case_set: string;
    readonly case_count: number;
    readonly exact_publication_dates: number;
    readonly unknown_publication_dates: number;
    readonly date_policy: string;
    readonly source_cutoff: string;
  };
  readonly cause_categories: Readonly<
    Record<string, { readonly label: string; readonly definition: string }>
  >;
  readonly ai_provenance_families: Readonly<
    Record<string, { readonly label: string }>
  >;
  readonly ai_commit_census?: ResearchAiCommitCensus;
  readonly cases: readonly ResearchCase[];
};

const AI_FAMILY_ICON_KEYS: Readonly<Record<string, string>> = {
  claude: "claude_code",
  copilot: "github_copilot",
  cursor: "cursor",
  openai_gpt_codex: "openai_codex",
};

export function getAiFamilyIconKey(family: string | null): string {
  return family ? (AI_FAMILY_ICON_KEYS[family] ?? "unknown_ai") : "unknown_ai";
}

export function getResearchSnapshot() {
  return snapshot;
}

export function getResearchCases(): readonly ResearchCase[] {
  return snapshot.cases;
}

export function getResearchCaseById(id: string): ResearchCase | null {
  const normalized = id.toUpperCase();
  return (
    snapshot.cases.find(
      (item) =>
        item.case_id.toUpperCase() === normalized ||
        item.aliases.some((alias) => alias.toUpperCase() === normalized),
    ) ?? null
  );
}

export function buildResearchTimeline(
  cases: readonly Pick<ResearchCase, "published_at">[],
): ResearchMonth[] {
  const counts = new Map<string, number>();
  for (const item of cases) {
    const month = item.published_at?.slice(0, 7);
    if (month && /^\d{4}-(0[1-9]|1[0-2])$/.test(month)) {
      counts.set(month, (counts.get(month) ?? 0) + 1);
    }
  }

  const datedMonths = [...counts.keys()].sort();
  if (datedMonths.length === 0) return [];

  const [startYear, startMonth] = datedMonths[0].split("-").map(Number);
  const [endYear, endMonth] = datedMonths.at(-1)!.split("-").map(Number);
  const result: ResearchMonth[] = [];

  for (
    let cursor = new Date(Date.UTC(startYear, startMonth - 1));
    cursor <= new Date(Date.UTC(endYear, endMonth - 1));
    cursor.setUTCMonth(cursor.getUTCMonth() + 1)
  ) {
    const month = `${cursor.getUTCFullYear()}-${String(cursor.getUTCMonth() + 1).padStart(2, "0")}`;
    result.push({ month, count: counts.get(month) ?? 0 });
  }

  return result;
}

export function getResearchTimeline(): ResearchMonth[] {
  return buildResearchTimeline(snapshot.cases);
}

export function getCauseDistribution(): ResearchDistributionItem[] {
  const counts = new Map<string, number>();
  for (const item of snapshot.cases) {
    const key = item.cause_category ?? "other_ambiguous";
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([key, count]) => ({
      key,
      count,
      label: snapshot.cause_categories[key]?.label ?? key,
      definition: snapshot.cause_categories[key]?.definition,
    }))
    .sort(
      (a, b) =>
        Number(a.key === "other_ambiguous") -
          Number(b.key === "other_ambiguous") ||
        b.count - a.count ||
        a.label.localeCompare(b.label),
    );
}

function countLabels(values: readonly string[]): ResearchDistributionItem[] {
  const counts = new Map<string, number>();
  for (const value of values) counts.set(value, (counts.get(value) ?? 0) + 1);
  return [...counts.entries()]
    .map(([key, count]) => ({ key, label: key, count }))
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
}

export function getLanguageDistribution(): ResearchDistributionItem[] {
  return countLabels(
    snapshot.cases.map((item) => item.repository_metadata.language),
  );
}

export function getRepositoryDistribution(): ResearchDistributionItem[] {
  return countLabels(
    snapshot.cases
      .map((item) => item.repository_metadata.full_name)
      .filter((name) => name !== "" && name !== null),
  );
}

export function getCauseCategoryLabel(key: string | null): string {
  return key
    ? (snapshot.cause_categories[key]?.label ?? key)
    : "Not classified";
}

export function getAiToolLabel(item: ResearchCase): string {
  const family = item.ai_provenance.family
    ? snapshot.ai_provenance_families[item.ai_provenance.family]?.label
    : null;
  if (item.ai_provenance.coverage === "complete" && family) return family;
  if (item.ai_provenance.coverage === "partial" && family) {
    return `${family} + unidentified tool`;
  }
  if (item.ai_provenance.coverage === "generic") {
    return "AI-assisted; tool not identified";
  }
  return "Tool not identified";
}

export function getAiToolDistribution() {
  const counts = new Map<string, number>();
  const coverage = { complete: 0, generic: 0, partial: 0, unresolved: 0 };
  for (const item of snapshot.cases) {
    coverage[item.ai_provenance.coverage] += 1;
    if (
      item.ai_provenance.coverage === "complete" &&
      item.ai_provenance.family
    ) {
      counts.set(
        item.ai_provenance.family,
        (counts.get(item.ai_provenance.family) ?? 0) + 1,
      );
    }
  }
  return {
    items: [...counts.entries()]
      .map(([key, count]) => ({
        key,
        count,
        label: snapshot.ai_provenance_families[key]?.label ?? key,
      }))
      .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label)),
    coverage,
    total: snapshot.cases.length,
  };
}

export interface AiToolBaseRateRow {
  readonly key: string;
  readonly label: string;
  readonly ai_commits: number;
  readonly ai_commit_share: number;
  readonly cases: number;
  readonly case_share: number;
  readonly ratio: number | null;
}

export function getAiToolBaseRate(): {
  readonly rows: readonly AiToolBaseRateRow[];
  readonly markedAiCommits: number;
  readonly totalCommits: number;
  readonly reposScanned: number;
  readonly window: { readonly since: string; readonly until: string } | null;
  readonly unavailable: boolean;
} {
  const census = snapshot.ai_commit_census;
  if (!census) {
    return {
      rows: [],
      markedAiCommits: 0,
      totalCommits: 0,
      reposScanned: 0,
      window: null,
      unavailable: true,
    };
  }
  const caseCounts = new Map<string, number>();
  for (const item of snapshot.cases) {
    if (item.ai_provenance.coverage === "complete" && item.ai_provenance.family) {
      caseCounts.set(
        item.ai_provenance.family,
        (caseCounts.get(item.ai_provenance.family) ?? 0) + 1,
      );
    }
  }
  const totalCases = [...caseCounts.values()].reduce((a, b) => a + b, 0);
  const rows = Object.entries(census.families)
    .filter(([, v]) => v.marked > 0)
    .map(([key, v]) => {
      const cases = caseCounts.get(key) ?? 0;
      const aiCommitShare = v.marked / Math.max(1, census.marked_ai_commits);
      const caseShare = cases / Math.max(1, totalCases);
      return {
        key,
        label: snapshot.ai_provenance_families[key]?.label ?? key,
        ai_commits: v.marked,
        ai_commit_share: aiCommitShare,
        cases,
        case_share: caseShare,
        ratio: aiCommitShare > 0 ? caseShare / aiCommitShare : null,
      };
    })
    .sort((a, b) => b.ai_commits - a.ai_commits);
  return {
    rows,
    markedAiCommits: census.marked_ai_commits,
    totalCommits: census.total_commits,
    reposScanned: census.repos_scanned,
    window: census.window,
    unavailable: false,
  };
}

export function formatContributionClass(value: string): string {
  return (
    {
      AI_DIRECT_ROOT: "Direct introduction",
      AI_CAUSAL_CONTRIBUTOR: "Causal contribution",
      AI_INCOMPLETE_REMEDIATION: "Incomplete remediation",
      AI_NEW_SURFACE_CONTRIBUTOR: "New attack surface",
      AI_ROOT_NEW_COMPONENT: "New vulnerable component",
    }[value] ?? value.replaceAll("_", " ").toLowerCase()
  );
}
