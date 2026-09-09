import type { ResearchCase } from "@/lib/research-data";

/** Small label maps the client index needs; the full payload stays server-side. */
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

function officialIds(item: ResearchCase): {
  readonly cve: string | null;
  readonly ghsa: string | null;
} {
  const ids = [item.case_id, ...item.aliases];
  return {
    cve: ids.find((value) => value.toUpperCase().startsWith("CVE-")) ?? null,
    ghsa: ids.find((value) => value.toUpperCase().startsWith("GHSA-")) ?? null,
  };
}

export function preferredCaseId(item: ResearchCase): string {
  const { cve, ghsa } = officialIds(item);
  return cve ?? ghsa ?? item.case_id;
}

/** Page title / in-page label: keep one ID, put the other in parentheses. */
export function formatCaseLabel(item: ResearchCase, displayId?: string): string {
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

export function aiToolLabel(item: ResearchCase, labels: ResearchLabels): string {
  const family = item.ai_provenance.family
    ? labels.aiFamilies[item.ai_provenance.family]?.label
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
