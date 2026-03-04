import { formatPublished } from "@/lib/commit-utils";

interface DataFreshnessProps {
  readonly generatedAt: string;
  readonly coverageFrom?: string;
}

export function DataFreshness({ generatedAt, coverageFrom }: DataFreshnessProps) {
  const formatted = formatPublished(generatedAt);
  if (!formatted) return null;

  return (
    <p className="text-xs text-muted-foreground">
      {coverageFrom
        ? `Coverage: ${coverageFrom} \u2013 ${formatted}`
        : `Data as of ${formatted}`}
    </p>
  );
}
