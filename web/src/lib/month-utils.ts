import { SEVERITY_ORDER } from "@/lib/constants";
import type { CveEntry } from "@/lib/types";

const MONTH_NAMES = [
  "January", "February", "March", "April", "May", "June",
  "July", "August", "September", "October", "November", "December",
];

export function formatMonthLabel(month: string): string {
  // "2025-05" -> "May 2025"
  const [year, m] = month.split("-");
  return `${MONTH_NAMES[Number(m) - 1] ?? m} ${year}`;
}

export function computeSeverityBreakdown(
  cves: readonly CveEntry[],
): { severity: string; count: number }[] {
  const counts: Record<string, number> = {};
  for (const cve of cves) {
    counts[cve.severity] = (counts[cve.severity] ?? 0) + 1;
  }
  return Object.entries(counts)
    .sort(
      ([a], [b]) =>
        (SEVERITY_ORDER[a] ?? 99) - (SEVERITY_ORDER[b] ?? 99),
    )
    .map(([severity, count]) => ({ severity, count }));
}

export function computeToolBreakdown(
  cves: readonly CveEntry[],
): { tool: string; count: number }[] {
  const counts: Record<string, number> = {};
  for (const cve of cves) {
    for (const tool of cve.ai_tools) {
      counts[tool] = (counts[tool] ?? 0) + 1;
    }
  }
  return Object.entries(counts)
    .sort(([, a], [, b]) => b - a)
    .map(([tool, count]) => ({ tool, count }));
}

export function sortCvesByPriority(cves: readonly CveEntry[]): CveEntry[] {
  return [...cves].sort((a, b) => {
    const sa = SEVERITY_ORDER[a.severity] ?? 99;
    const sb = SEVERITY_ORDER[b.severity] ?? 99;
    if (sa !== sb) return sa - sb;
    return b.published.localeCompare(a.published);
  });
}
