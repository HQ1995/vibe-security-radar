import { formatPublished } from "@/lib/commit-utils";

interface DataFreshnessProps {
  readonly generatedAt: string;
  readonly coverageFrom?: string;
  readonly coverageTo?: string;
}

export function DataFreshness({ generatedAt, coverageFrom, coverageTo }: DataFreshnessProps) {
  const formatted = formatPublished(generatedAt);
  if (!formatted) return null;

  if (coverageFrom) {
    const from = formatPublished(coverageFrom);
    const to = coverageTo ? formatPublished(coverageTo) : formatted;
    return (
      <p className="text-xs text-muted-foreground">
        Coverage: {from} &ndash; {to}
      </p>
    );
  }

  return (
    <p className="text-xs text-muted-foreground">
      Data as of {formatted}
    </p>
  );
}
