import {
  verifiedByTooltip,
  getModelDisplayName,
  deduplicateModels,
} from "@/lib/constants";

export function VerifiedBadge({
  verifiedBy,
}: {
  readonly verifiedBy: string;
}) {
  const allModels = verifiedBy ? verifiedBy.split(",").map((m) => m.trim()).filter(Boolean) : [];
  const models = deduplicateModels(allModels);

  if (models.length === 0) {
    return <span className="text-muted-foreground/40 text-xs">&mdash;</span>;
  }

  return (
    <span
      className="block truncate text-sm text-muted-foreground"
      title={models.map((model) => verifiedByTooltip(model)).join("; ")}
    >
      {models.map((model) => getModelDisplayName(model)).join(", ")}
    </span>
  );
}
