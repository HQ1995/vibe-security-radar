import { getResearchSnapshot } from "@/lib/research-data";

export function SiteFooter() {
  const research = getResearchSnapshot();

  return (
    <footer className="border-t border-border/70 bg-card/35">
      <div className="mx-auto grid w-full max-w-[96rem] gap-8 px-4 py-10 text-xs text-muted-foreground sm:px-6 md:grid-cols-[1fr_auto] md:items-end 2xl:px-8 min-[1920px]:max-w-[112rem] min-[2400px]:max-w-[128rem]">
        <div className="max-w-2xl space-y-2">
          <p className="text-sm font-semibold tracking-tight text-foreground">
            Vibe Security Radar
          </p>
          <p className="leading-5">
            A mechanism-level study of vulnerabilities contributed by AI-written
            code. Each finding connects an advisory to the relevant change,
            residual vulnerability, and security fix.
          </p>
          <p>
            Sources: first-party security advisories &middot; public Git history
            &middot; release artifacts
          </p>
          <p className="font-mono text-[10px] uppercase tracking-[0.1em] tabular-nums">
            Advisory-date source cutoff{" "}
            {research.snapshot.source_cutoff.slice(0, 10)}
          </p>
        </div>
        <div className="flex items-center gap-5 md:justify-end">
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
