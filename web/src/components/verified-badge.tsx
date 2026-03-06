import {
  verifiedBadgeColor,
  verifiedByLabel,
  verifiedByTooltip,
} from "@/lib/constants";

export function VerifiedBadge({
  verifiedBy,
}: {
  readonly verifiedBy: string;
}) {
  const label = verifiedByLabel(verifiedBy);
  if (!label) {
    return <span className="text-muted-foreground/40 text-xs">—</span>;
  }
  const primaryModel = verifiedBy.split(",")[0].trim();
  const color = verifiedBadgeColor(primaryModel);
  return (
    <span
      className={`inline-flex items-center rounded-md border px-1.5 py-0.5 text-[10px] font-semibold max-w-full truncate ${color}`}
      title={verifiedByTooltip(verifiedBy)}
    >
      {label}
    </span>
  );
}
