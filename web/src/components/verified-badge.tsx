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

  return (
    <div className="flex flex-wrap items-center justify-center gap-1">
      {models.map((model) => {
        const color = verifiedBadgeColor(model);
        return (
          <span
            key={model}
            className={`inline-flex items-center rounded-md border px-1.5 py-0.5 text-[10px] font-semibold whitespace-nowrap ${color}`}
            title={verifiedByTooltip(model)}
          >
            {getModelDisplayName(model)}
          </span>
        );
      })}
    </div>
  );
}
