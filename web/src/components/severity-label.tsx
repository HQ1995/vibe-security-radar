import { severityLevel } from "@/lib/research-format";

const STYLES = {
  CRITICAL: "border-red-600 text-red-700 dark:border-red-500 dark:text-red-400",
  HIGH: "border-orange-600 text-orange-700 dark:border-orange-500 dark:text-orange-400",
  MEDIUM:
    "border-yellow-600 text-yellow-800 dark:border-yellow-500 dark:text-yellow-300",
  LOW: "border-muted-foreground/60 text-muted-foreground",
} as const;

const NAMES = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
} as const;

export function SeverityLabel({
  severity,
}: {
  readonly severity: string | null | undefined;
}) {
  const level = severityLevel(severity);
  if (!level) return null;
  return (
    <span
      className={`inline-flex shrink-0 items-center rounded-full border px-2 text-xs font-medium leading-5 ${STYLES[level]}`}
    >
      {NAMES[level]}
    </span>
  );
}
