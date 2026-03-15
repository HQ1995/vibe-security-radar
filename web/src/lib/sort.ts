import { SEVERITY_ORDER } from "./constants";
import type { CveEntry } from "./types";

export type SortKey =
  | "id"
  | "severity"
  | "tools"
  | "verdict"
  | "verified"
  | "confidence"
  | "description"
  | "published";
export type SortDirection = "asc" | "desc";

export interface SortState {
  readonly key: SortKey;
  readonly direction: SortDirection;
}

export function compareCves(a: CveEntry, b: CveEntry, sort: SortState): number {
  const dir = sort.direction === "asc" ? 1 : -1;

  switch (sort.key) {
    case "id":
      return dir * a.id.localeCompare(b.id);
    case "severity": {
      const aOrder = SEVERITY_ORDER[a.severity] ?? 99;
      const bOrder = SEVERITY_ORDER[b.severity] ?? 99;
      return dir * (aOrder - bOrder);
    }
    case "tools":
      return dir * a.ai_tools.join(", ").localeCompare(b.ai_tools.join(", "));
    case "verdict": {
      const order: Record<string, number> = { CONFIRMED: 0, UNLIKELY: 1, "": 2 };
      const aOrder = order[a.verdict] ?? 2;
      const bOrder = order[b.verdict] ?? 2;
      return dir * (aOrder - bOrder);
    }
    case "verified": {
      // Verified entries sort before unverified
      const aVerified = a.verified_by ? 0 : 1;
      const bVerified = b.verified_by ? 0 : 1;
      if (aVerified !== bVerified) return dir * (aVerified - bVerified);
      return dir * a.verified_by.localeCompare(b.verified_by);
    }
    case "confidence":
      return dir * (a.confidence - b.confidence);
    case "description":
      return dir * a.description.localeCompare(b.description);
    case "published": {
      const aEmpty = a.published === "";
      const bEmpty = b.published === "";
      // Always push empty published to the end regardless of direction
      if (aEmpty && !bEmpty) return 1;
      if (!aEmpty && bEmpty) return -1;
      if (aEmpty && bEmpty) {
        // Tiebreaker: extract year from ID (CVE-YYYY-...) or fall back to ID string
        const aYear = a.id.match(/^CVE-(\d{4})/)?.[1] ?? "";
        const bYear = b.id.match(/^CVE-(\d{4})/)?.[1] ?? "";
        if (aYear !== bYear) return dir * aYear.localeCompare(bYear);
        return dir * a.id.localeCompare(b.id);
      }
      return dir * a.published.localeCompare(b.published);
    }
    default:
      return 0;
  }
}
