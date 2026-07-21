import Link from "next/link";
import { formatMonthShort, isValidMonthKey } from "@/lib/month-utils";

interface MonthEntry {
  readonly month: string;
  readonly count: number;
  readonly by_tool: Readonly<Record<string, number>>;
}

interface MonthArchiveProps {
  readonly data: readonly MonthEntry[];
}

/** Compact index of month chips linking to /cves/month/[month], newest first. */
export function MonthArchive({ data }: MonthArchiveProps) {
  const months = data
    .filter((entry) => isValidMonthKey(entry.month))
    .sort((a, b) => b.month.localeCompare(a.month));

  if (months.length === 0) return null;

  return (
    <nav aria-label="Browse vulnerabilities by month">
      <ul className="flex flex-wrap gap-1.5">
        {months.map((entry) => (
          <li key={entry.month}>
            <Link
              href={`/cves/month/${entry.month}`}
              className="inline-flex items-baseline gap-1 rounded-md border border-border px-2.5 py-1 text-xs text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
            >
              {formatMonthShort(entry.month)}
              <span className="tabular-nums text-muted-foreground/60">
                &middot; {entry.count}
              </span>
            </Link>
          </li>
        ))}
      </ul>
    </nav>
  );
}
