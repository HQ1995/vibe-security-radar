import { formatPublished } from "@/lib/commit-utils";

interface DataFreshnessProps {
  readonly generatedAt: string;
  readonly coverageFrom?: string;
  readonly coverageTo?: string;
}

export function formatGeneratedAt(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return formatPublished(value);
  return new Intl.DateTimeFormat("en", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
    timeZone: "UTC",
    timeZoneName: "short",
  }).format(date);
}

export function DataFreshness({
  generatedAt,
  coverageFrom,
  coverageTo,
}: DataFreshnessProps) {
  const generated = formatGeneratedAt(generatedAt);
  if (!generated) return null;

  if (coverageFrom) {
    const from = formatPublished(coverageFrom);
    const to = coverageTo ? formatPublished(coverageTo) : generated;
    return (
      <p className="text-xs text-muted-foreground">
        Snapshot generated {generated} &middot; advisory coverage {from} &ndash;{" "}
        {to}
      </p>
    );
  }

  return (
    <p className="text-xs text-muted-foreground">
      Snapshot generated {generated}
    </p>
  );
}
