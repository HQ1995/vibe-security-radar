import Link from "next/link";

import { getResearchSnapshot } from "@/lib/research-data";
import { getTopics, topicPath } from "@/lib/topics";

const DIRECTORY = [
  { kind: "tool" as const, title: "By AI tool" },
  { kind: "cause" as const, title: "By root cause" },
];

export function SiteFooter() {
  const research = getResearchSnapshot();

  return (
    <footer className="border-t border-border/70 bg-card/35">
      <div className="page-container grid gap-8 py-10 text-xs text-muted-foreground lg:grid-cols-[minmax(0,1fr)_auto_auto] lg:gap-14">
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
        <nav
          aria-label="Browse findings"
          className="grid grid-cols-2 gap-8 sm:gap-12"
        >
          {DIRECTORY.map((group) => (
            <div key={group.kind}>
              <p className="font-semibold text-foreground">{group.title}</p>
              <ul className="mt-2 space-y-1.5">
                {getTopics(group.kind).map((topic) => (
                  <li key={topic.key}>
                    <Link
                      href={topicPath(topic)}
                      className="transition-colors hover:text-foreground"
                    >
                      {topic.label}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>
        <div className="flex flex-wrap items-start gap-x-5 gap-y-1.5 lg:flex-col">
          <p className="hidden font-semibold text-foreground lg:block">
            Project
          </p>
          <a
            href="https://github.com/HQ1995/vibe-security-radar"
            target="_blank"
            rel="noopener noreferrer"
            className="transition-colors hover:text-foreground"
          >
            GitHub
          </a>
          <a
            href="/data/findings.csv"
            download
            className="transition-colors hover:text-foreground"
          >
            Data (CSV)
          </a>
          <a
            href="/feed.xml"
            className="transition-colors hover:text-foreground"
          >
            Atom feed
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
