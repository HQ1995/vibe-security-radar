import { deduplicateModels, getModelDisplayName } from "@/lib/constants";

const INDEPENDENT_SOURCES = new Set(["independent-audit", "manual"]);

export function getReviewProvenanceDetail(verifiedBy: string): string {
  const sources = verifiedBy
    .split(",")
    .map((source) => source.trim())
    .filter(Boolean);

  if (sources.some((source) => INDEPENDENT_SOURCES.has(source.toLowerCase()))) {
    return "Independent audit";
  }

  const models = deduplicateModels(sources);
  return models.length
    ? models.map((model) => getModelDisplayName(model)).join(", ")
    : "Not recorded";
}

export function ReviewPathBadge({
  verifiedBy,
}: {
  readonly verifiedBy: string;
}) {
  const detail = getReviewProvenanceDetail(verifiedBy);
  const independent = detail === "Independent audit";

  return (
    <span
      className="block truncate text-sm text-muted-foreground"
      title={
        independent
          ? "Investigation provenance: independent audit"
          : `Investigation provenance: ${detail}. Model output is not publication authority.`
      }
    >
      {independent ? "Independent audit" : `${detail} trace`}
    </span>
  );
}
