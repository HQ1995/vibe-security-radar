import { stripMarkdown } from "@/lib/markdown-utils";
import type { ResearchCase } from "@/lib/research-data";

type CaseIdentity = Pick<ResearchCase, "case_id" | "aliases">;

export type FindingRow = CaseIdentity &
  Pick<
    ResearchCase,
    | "repository"
    | "contribution_class"
    | "cause_category"
    | "published_at"
    | "candidate_set"
    | "carrier_set"
    | "minimum_fix_set"
  > & {
    readonly severity?: string | null;
    readonly repository_metadata: Pick<
      ResearchCase["repository_metadata"],
      "language"
    >;
    readonly ai_provenance: Pick<
      ResearchCase["ai_provenance"],
      "family" | "coverage"
    >;
    readonly headline?: string;
    readonly code_evidence?: { readonly summary: string } | null;
    readonly description?: string | null;
  };

export interface ResearchLabels {
  readonly causeCategories: Readonly<
    Record<string, { readonly label: string }>
  >;
  readonly aiFamilies: Readonly<Record<string, { readonly label: string }>>;
}

const AI_FAMILY_ICON_KEYS: Readonly<Record<string, string>> = {
  claude: "claude_code",
  copilot: "github_copilot",
  cursor: "cursor",
  openai_gpt_codex: "openai_codex",
};

export function getAiFamilyIconKey(family: string | null): string {
  return family ? (AI_FAMILY_ICON_KEYS[family] ?? "unknown_ai") : "unknown_ai";
}

function officialIds(item: CaseIdentity): {
  readonly cve: string | null;
  readonly ghsa: string | null;
} {
  const ids = [item.case_id, ...item.aliases];
  return {
    cve: ids.find((value) => value.toUpperCase().startsWith("CVE-")) ?? null,
    ghsa: ids.find((value) => value.toUpperCase().startsWith("GHSA-")) ?? null,
  };
}

export function preferredCaseId(item: CaseIdentity): string {
  const { cve, ghsa } = officialIds(item);
  return cve ?? ghsa ?? item.case_id;
}

export function formatCaseLabel(
  item: CaseIdentity,
  displayId?: string,
): string {
  const shown = displayId ?? preferredCaseId(item);
  const { cve, ghsa } = officialIds(item);
  const other = shown.toUpperCase().startsWith("CVE-")
    ? ghsa
    : shown.toUpperCase().startsWith("GHSA-")
      ? cve
      : null;
  if (other && other.toUpperCase() !== shown.toUpperCase()) {
    return `${shown} (${other})`;
  }
  return shown;
}

export function formatCount(value: number): string {
  return value.toLocaleString("en-US");
}

export function formatContributionClass(value: string): string {
  return (
    {
      AI_DIRECT_ROOT: "Direct introduction",
      AI_CAUSAL_CONTRIBUTOR: "Causal contribution",
      AI_INCOMPLETE_REMEDIATION: "Incomplete remediation",
      AI_NEW_SURFACE_CONTRIBUTOR: "New attack surface",
      AI_ROOT_NEW_COMPONENT: "New vulnerable component",
      AI_CODE_FLAWED: "Flawed AI-written code",
      AI_ROOT_CAUSE: "AI root cause",
    }[value] ?? value.replaceAll("_", " ").toLowerCase()
  );
}

export function causeCategoryLabel(
  key: string | null,
  labels: ResearchLabels,
): string {
  return key ? (labels.causeCategories[key]?.label ?? key) : "Not classified";
}

export function aiToolLabel(
  item: Pick<FindingRow, "ai_provenance">,
  labels: ResearchLabels,
): string {
  const family = item.ai_provenance.family
    ? labels.aiFamilies[item.ai_provenance.family]?.label
    : null;
  if (item.ai_provenance.coverage === "complete" && family) return family;
  if (item.ai_provenance.coverage === "partial" && family) {
    return `${family} + unidentified tool`;
  }
  if (item.ai_provenance.coverage === "generic") {
    return "Unidentified AI tool";
  }
  return "Tool not identified";
}

export function getCaseHeadline(item: FindingRow): string {
  if (item.headline) return item.headline;
  const summary = stripMarkdown(item.code_evidence?.summary).replace(
    /\s+/g,
    " ",
  );
  if (summary) return summary;
  const generic = /^(summary|details|description|overview):?$/i;
  const cjk = /[\u4e00-\u9fff]/;
  const first = stripMarkdown(item.description)
    .split("\n")
    .map((line) => line.trim())
    .find((line) => line && !generic.test(line) && !cjk.test(line));
  return (
    first ??
    formatContributionClass(item.contribution_class) +
      (item.repository ? " in " + item.repository : "")
  );
}

export function toFindingRow(item: ResearchCase): FindingRow {
  return {
    case_id: item.case_id,
    aliases: item.aliases,
    repository: item.repository,
    repository_metadata: { language: item.repository_metadata.language },
    contribution_class: item.contribution_class,
    cause_category: item.cause_category,
    published_at: item.published_at,
    candidate_set: item.candidate_set,
    carrier_set: item.carrier_set,
    minimum_fix_set: item.minimum_fix_set,
    severity: severityLevel(item.severity),
    ai_provenance: {
      family: item.ai_provenance.family,
      coverage: item.ai_provenance.coverage,
    },
    headline: getCaseHeadline(item),
  };
}

const SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

export type SeverityLevel = (typeof SEVERITY_LEVELS)[number];

export function severityLevel(
  value: string | null | undefined,
): SeverityLevel | null {
  const level = String(value ?? "").trim().toUpperCase();
  return (SEVERITY_LEVELS as readonly string[]).includes(level)
    ? (level as SeverityLevel)
    : null;
}
