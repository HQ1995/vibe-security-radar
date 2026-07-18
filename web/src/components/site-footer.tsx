import { getStats } from "@/lib/data";
import { formatPublished } from "@/lib/commit-utils";

export function SiteFooter() {
  const stats = getStats();
  const generatedAt = formatPublished(stats.generated_at);
  const coverageFrom = formatPublished(stats.coverage_from);
  const coverageTo = formatPublished(stats.coverage_to);

  return (
    <footer className="border-t border-border">
      <div className="mx-auto flex max-w-6xl flex-col gap-3 px-4 py-8 text-xs text-muted-foreground sm:flex-row sm:items-center sm:justify-between sm:px-6">
        <div className="space-y-1">
          <p className="font-medium text-foreground/80">Vibe Security Radar</p>
          <p>Data from OSV &middot; GitHub Advisory Database &middot; NVD</p>
          {generatedAt && (
            <p className="tabular-nums">
              Data as of {generatedAt}
              {coverageFrom && coverageTo && (
                <>
                  {" "}
                  &middot; Coverage {coverageFrom} &ndash; {coverageTo}
                </>
              )}
            </p>
          )}
        </div>
        <div className="flex items-center gap-4">
          <a
            href="https://github.com/HQ1995/vibe-security-radar"
            target="_blank"
            rel="noopener noreferrer"
            className="transition-colors hover:text-foreground"
          >
            GitHub
          </a>
          <a
            href="mailto:hanqing@gatech.edu"
            className="transition-colors hover:text-foreground"
          >
            Contact
          </a>
        </div>
      </div>
    </footer>
  );
}
