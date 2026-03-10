import {
  verifiedBadgeColor,
  verifiedByTooltip,
  getModelDisplayName,
  deduplicateModels,
} from "@/lib/constants";

export function VerifiedBadge({
  verifiedBy,
}: {
  readonly verifiedBy: string;
}) {
  if (!verifiedBy) {
    return <span className="text-muted-foreground/40 text-xs">&mdash;</span>;
  }

  const allModels = verifiedBy.split(",").map((m) => m.trim()).filter(Boolean);
  const models = deduplicateModels(allModels);

  if (models.length === 0) {
    return <span className="text-muted-foreground/40 text-xs">&mdash;</span>;
  }

  // Single line: show first model as badge, rest as +N tooltip
  const [first, ...rest] = models;
  const color = verifiedBadgeColor(first);
  const allNames = models.map(getModelDisplayName).join(", ");

  return (
    <div className="flex items-center justify-center gap-1" title={allNames}>
      <span
        className={`inline-flex items-center rounded-md border px-1.5 py-0.5 text-[10px] font-semibold whitespace-nowrap ${color}`}
        title={verifiedByTooltip(first)}
      >
        {getModelDisplayName(first)}
      </span>
      {rest.length > 0 && (
        <span className="text-[10px] text-muted-foreground whitespace-nowrap">
          +{rest.length}
        </span>
      )}
    </div>
  );
}
