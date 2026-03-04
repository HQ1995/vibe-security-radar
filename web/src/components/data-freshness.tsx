import { formatPublished } from "@/lib/commit-utils";

interface DataFreshnessProps {
  readonly generatedAt: string;
}

export function DataFreshness({ generatedAt }: DataFreshnessProps) {
  const formatted = formatPublished(generatedAt);
  if (!formatted) return null;

  return (
    <p className="text-xs text-muted-foreground">
      Coverage: May 2025 &ndash; {formatted}
    </p>
  );
}
