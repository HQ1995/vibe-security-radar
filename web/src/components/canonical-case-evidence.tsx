import { ArrowRight, ExternalLink } from "lucide-react";

import {
  formatContributionClass,
  getAiToolLabel,
  getCauseCategoryLabel,
  type ResearchCase,
  type ResearchCodeHunk,
  type ResearchRelease,
} from "@/lib/research-data";

function shortSha(value: string): string {
  return value.slice(0, 10);
}

function commitUrl(repository: string | null, sha: string): string | null {
  return repository ? `https://github.com/${repository}/commit/${sha}` : null;
}

function releaseLabel(release: ResearchRelease | null): string {
  if (!release) return "Not recorded";
  return (
    release.tag ??
    release.version ??
    release.sha?.slice(0, 10) ??
    release.kind ??
    "Recorded in the evidence bundle"
  );
}

function contributionHeadline(value: string): string {
  return (
    {
      AI_DIRECT_ROOT:
        "AI introduced the vulnerable behavior.",
      AI_CAUSAL_CONTRIBUTOR:
        "AI made the vulnerable path reachable.",
      AI_INCOMPLETE_REMEDIATION:
        "AI tried to fix the flaw but missed a case.",
    }[value] ?? "AI contributed to this vulnerability."
  );
}

function rootCauseTitle(item: ResearchCase): string {
  const category = getCauseCategoryLabel(item.cause_category);
  return (
    {
      AI_DIRECT_ROOT: `${category} introduced`,
      AI_CAUSAL_CONTRIBUTOR: `${category} path exposed`,
      AI_INCOMPLETE_REMEDIATION: `${category} bypass remained`,
    }[item.contribution_class] ?? category
  );
}

function markerName(marker: string | undefined): string | null {
  return marker?.match(/(?:Co-Authored-By|Assisted-by):\s*([^<]+)/i)?.[1].trim() ?? null;
}

function fixAuthorship(item: ResearchCase): string {
  const record = item.fix_authorship;
  const authors = [...new Set(record.fixes.map((fix) => fix.author.name))].join(", ");
  const families = record.families
    .map(
      (family) =>
        ({
          aether: "Aether AI",
          claude_code: "Claude Code",
          cursor: "Cursor",
          github_copilot: "GitHub Copilot",
          openai_codex: "OpenAI GPT/Codex",
        })[family] ?? family,
    )
    .join(" + ");
  if (record.classification === "ai_assisted") {
    return `AI-assisted fix: ${families} · ${authors}`;
  }
  if (record.classification === "mixed") {
    return `Mixed fix set: ${families} + unmarked commit · ${authors}`;
  }
  return `Fix by ${authors} · no AI marker found`;
}

function CommitLink({
  repository,
  sha,
}: {
  readonly repository: string | null;
  readonly sha: string;
}) {
  const href = commitUrl(repository, sha);
  if (!href) return <span className="font-mono">{shortSha(sha)}</span>;
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex items-center gap-1 font-mono text-primary hover:underline"
    >
      {shortSha(sha)}
      <ExternalLink className="h-3 w-3" />
    </a>
  );
}

function FileLink({
  repository,
  sha,
  file,
}: {
  readonly repository: string | null;
  readonly sha: string;
  readonly file: string;
}) {
  if (!repository) return <span className="font-mono">{file}</span>;
  return (
    <a
      href={`https://github.com/${repository}/blob/${sha}/${file}`}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex items-center gap-1 font-mono text-primary hover:underline"
    >
      {file}
      <ExternalLink className="h-3 w-3" />
    </a>
  );
}

function CauseFixCard({
  tone,
  title,
  detail,
  repository,
  shas,
  files,
  authorship,
}: {
  readonly tone: "bad" | "good";
  readonly title: string;
  readonly detail: string;
  readonly repository: string | null;
  readonly shas: readonly string[];
  readonly files: readonly string[];
  readonly authorship: string;
}) {
  const isBad = tone === "bad";
  return (
    <article
      className={`border border-border border-l-4 p-5 ${
        isBad ? "border-l-destructive bg-red-50/55" : "border-l-emerald-600 bg-emerald-50/55"
      }`}
    >
      <p
        className={`font-mono text-[10px] font-semibold uppercase tracking-wider ${
          isBad ? "text-destructive" : "text-emerald-700"
        }`}
      >
        {isBad ? "Root cause" : "Fix"}
      </p>
      <h3 className="mt-3 text-lg font-semibold">{title}</h3>
      <p className="mt-2 text-sm leading-6 text-muted-foreground">{detail}</p>
      <div className="mt-5 space-y-2 border-t border-border pt-4 text-xs">
        <p className="text-muted-foreground">{authorship}</p>
        <div className="flex flex-wrap gap-x-3 gap-y-1">
          {shas.map((sha) => (
            <CommitLink key={sha} repository={repository} sha={sha} />
          ))}
        </div>
        {files.length ? (
          <div className="flex flex-wrap gap-x-3 gap-y-1">
            {[...new Set(files)].map((file) => (
              <FileLink
                key={file}
                repository={repository}
                sha={shas[0]}
                file={file}
              />
            ))}
          </div>
        ) : null}
      </div>
    </article>
  );
}

function DiffHunk({
  hunk,
  repository,
  sha,
  label,
  open,
}: {
  readonly hunk: ResearchCodeHunk;
  readonly repository: string | null;
  readonly sha: string;
  readonly label: "AI change" | "Fix";
  readonly open: boolean;
}) {
  const lines = hunk.code.replace(/\n$/, "").split("\n");
  const added = lines.filter(
    (line) => line.startsWith("+") && !line.startsWith("+++"),
  ).length;
  const removed = lines.filter(
    (line) => line.startsWith("-") && !line.startsWith("---"),
  ).length;

  return (
    <details
      open={open}
      className="group overflow-hidden border border-border bg-card"
    >
      <summary className="flex cursor-pointer select-none items-center justify-between gap-3 px-4 py-2.5 [&::-webkit-details-marker]:hidden">
        <span className="flex min-w-0 items-center text-[11px]">
          <FileLink repository={repository} sha={sha} file={hunk.file} />
        </span>
        <span className="flex shrink-0 items-center gap-2 font-mono text-[10px] tabular-nums">
          <span className="text-emerald-700">+{added}</span>
          <span className="text-red-700">−{removed}</span>
          <span className="font-semibold uppercase tracking-wider text-muted-foreground">
            {label}
          </span>
        </span>
      </summary>
      <pre className="max-h-[28rem] overflow-auto border-t border-border py-3 text-[12px] leading-6">
        <code>
          {lines.map((line, index) => (
            <span
              key={`${index}-${line}`}
              className={`block min-w-max px-4 ${
                line.startsWith("+")
                  ? "bg-emerald-50 text-emerald-900"
                  : line.startsWith("-")
                    ? "bg-red-50 text-red-900"
                    : line.startsWith("@@")
                      ? "text-primary"
                      : ""
              }`}
            >
              {line || " "}
            </span>
          ))}
        </code>
      </pre>
      {hunk.annotation ? (
        <p className="border-t border-border px-4 py-3 text-xs leading-5 text-muted-foreground">
          {hunk.annotation}
        </p>
      ) : null}
    </details>
  );
}

export function CanonicalCaseEvidence({
  item,
}: {
  readonly item: ResearchCase;
}) {
  const evidence = item.code_evidence;
  const candidateFiles = evidence?.candidate_hunks.map((hunk) => hunk.file) ?? [];
  const fixFiles = evidence?.fix_hunks.map((hunk) => hunk.file) ?? [];
  const candidateModel = markerName(evidence?.ai_marker) ?? getAiToolLabel(item);
  const githubAdvisoryUrl = `https://github.com/advisories/${item.case_id}`;
  const hasCode = Boolean(evidence?.comparison_hunks.length);

  return (
    <section className="space-y-8 border-t border-border pt-7">
      <div>
        <div className="flex flex-wrap items-center gap-3">
          <p className="section-kicker">What AI did</p>
          <span className="border border-primary/25 bg-primary/[0.05] px-2 py-1 font-mono text-[10px] font-semibold text-primary">
            {formatContributionClass(item.contribution_class)}
          </span>
        </div>
        <h2 className="mt-3 max-w-3xl text-2xl font-semibold tracking-[-0.025em] sm:text-3xl">
          {evidence?.summary ?? contributionHeadline(item.contribution_class)}
        </h2>
      </div>

      {evidence?.steps[0] ? (
        <div className="grid gap-2 border-y border-border py-4 sm:grid-cols-[8rem_1fr]">
          <p className="font-mono text-[10px] font-semibold uppercase tracking-wider text-primary">
            AI change
          </p>
          <p className="text-sm leading-6 text-muted-foreground">
            {evidence.steps[0].detail}
          </p>
        </div>
      ) : null}

      <div className="grid items-stretch gap-3 sm:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)]">
        <CauseFixCard
          tone="bad"
          title={evidence?.steps[1]?.title ?? rootCauseTitle(item)}
          detail={
            evidence?.steps[1]?.detail ??
            "The candidate commit below is where the vulnerable behavior appears."
          }
          repository={item.repository}
          shas={item.candidate_set}
          files={candidateFiles}
          authorship={`AI candidate: ${candidateModel}`}
        />
        <div className="flex items-center justify-center" aria-hidden="true">
          <ArrowRight className="h-5 w-5 rotate-90 text-muted-foreground sm:rotate-0" />
        </div>
        <CauseFixCard
          tone="good"
          title={evidence?.steps[2]?.title ?? "Security fix"}
          detail={
            evidence?.steps[2]?.detail ??
            "The minimum fix commit below closes the same vulnerable path."
          }
          repository={item.repository}
          shas={item.minimum_fix_set}
          files={fixFiles}
          authorship={fixAuthorship(item)}
        />
      </div>

      {evidence && hasCode ? (
        <div className="space-y-4" aria-labelledby="code-comparison">
          <div>
            <p className="section-kicker">Code comparison</p>
            <h3 id="code-comparison" className="mt-2 text-xl font-semibold">
              Vulnerable code and fix
            </h3>
          </div>
          {evidence.comparison_hunks.map((hunk, index) => (
            <DiffHunk
              key={`${index}-${hunk.file}`}
              hunk={hunk}
              repository={item.repository}
              sha={
                index < evidence.candidate_hunks.length
                  ? item.candidate_set[0]
                  : item.minimum_fix_set[0]
              }
              label={
                index < evidence.candidate_hunks.length ? "AI change" : "Fix"
              }
              open={
                index === 0 || index === evidence.candidate_hunks.length
              }
            />
          ))}
          {evidence.candidate_patch_sha256 && evidence.fix_patch_sha256 ? (
            <details className="text-xs text-muted-foreground">
              <summary className="cursor-pointer">Patch fingerprints</summary>
              <p className="mt-2 break-all font-mono text-[10px] leading-5">
                Candidate {evidence.candidate_patch_sha256}
                {" · "}Fix {evidence.fix_patch_sha256}
              </p>
            </details>
          ) : null}
        </div>
      ) : !evidence ? (
        <p className="border-y border-border py-4 text-sm text-muted-foreground">
          A line-by-line code comparison has not been prepared for this case yet.
        </p>
      ) : null}

      <div className="max-w-xl border-y border-border py-5">
        <div>
          <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
            Releases
          </p>
          <dl className="mt-3 space-y-2 text-sm">
            <div className="flex justify-between gap-4">
              <dt className="text-muted-foreground">Vulnerable</dt>
              <dd className="font-mono text-right">
                {releaseLabel(item.vulnerable_release)}
              </dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-muted-foreground">Fixed</dt>
              <dd className="font-mono text-right">
                {releaseLabel(item.fixed_release)}
              </dd>
            </div>
          </dl>
        </div>
      </div>

      <div className="flex flex-wrap gap-x-5 gap-y-2 text-sm">
        {[
          ["GitHub advisory", githubAdvisoryUrl],
          ...(evidence?.advisory_url !== githubAdvisoryUrl
            ? [["Repository advisory", evidence?.advisory_url]]
            : []),
        ].map(([label, href]) =>
          href ? (
            <a
              key={label}
              href={href}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-primary hover:underline"
            >
              {label} <ExternalLink className="h-3 w-3" />
            </a>
          ) : null,
        )}
      </div>
    </section>
  );
}
