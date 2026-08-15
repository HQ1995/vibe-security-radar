"use client";

import { useState } from "react";

import { ResearchCaseTable } from "@/components/research-case-table";
import { formatMonthShort } from "@/lib/month-utils";
import {
  formatContributionClass,
  getAiToolLabel,
  getCauseCategoryLabel,
  type ResearchCase,
} from "@/lib/research-data";

export interface ResearchCaseFilters {
  readonly query: string;
  readonly cause: string;
  readonly contribution: string;
  readonly tool: string;
  readonly language: string;
  readonly repository: string;
  readonly month: string;
}

const SEARCH_EXCLUDED_KEYS = new Set(["code_evidence", "ir_chain", "description", "references"]);

function scalarValues(value: unknown): string[] {
  if (typeof value === "string" || typeof value === "number")
    return [String(value)];
  if (Array.isArray(value)) return value.flatMap(scalarValues);
  if (value && typeof value === "object") {
    return Object.entries(value).flatMap(([key, child]) =>
      SEARCH_EXCLUDED_KEYS.has(key) ? [] : scalarValues(child),
    );
  }
  return [];
}

export function filterResearchCases(
  cases: readonly ResearchCase[],
  filters: ResearchCaseFilters,
): ResearchCase[] {
  const query = filters.query.trim().toLowerCase();
  return cases.filter((item) => {
    const cause = getCauseCategoryLabel(item.cause_category);
    const contribution = formatContributionClass(item.contribution_class);
    const tool = getAiToolLabel(item);
    const searchable = [
      ...scalarValues(item),
      cause,
      contribution,
      tool,
      item.published_at ? "" : "Date unavailable",
      item.repository ? "" : "Not recorded",
    ]
      .join(" ")
      .toLowerCase();
    return (
      (!query || searchable.includes(query)) &&
      (!filters.cause || item.cause_category === filters.cause) &&
      (!filters.contribution ||
        item.contribution_class === filters.contribution) &&
      (!filters.tool || tool === filters.tool) &&
      (!filters.language ||
        item.repository_metadata.language === filters.language) &&
      (!filters.repository || item.repository === filters.repository) &&
      (!filters.month ||
        (filters.month === "undated"
          ? !item.published_at
          : item.published_at?.startsWith(filters.month) === true))
    );
  });
}

function unique(values: readonly string[]): string[] {
  return [...new Set(values.filter((v) => v != null))].sort((a, b) =>
    a.localeCompare(b),
  );
}

const EMPTY_FILTERS: ResearchCaseFilters = {
  query: "",
  cause: "",
  contribution: "",
  tool: "",
  language: "",
  repository: "",
  month: "",
};

const PAGE_SIZE = 20;

export function ResearchCaseExplorer({
  cases,
}: {
  readonly cases: readonly ResearchCase[];
}) {
  const [filters, setFilters] = useState(EMPTY_FILTERS);
  const [page, setPage] = useState(1);
  const filtered = filterResearchCases(cases, filters);
  const pageCount = Math.ceil(filtered.length / PAGE_SIZE);
  const start = (page - 1) * PAGE_SIZE;
  const visible = filtered.slice(start, start + PAGE_SIZE);
  const causes = unique(
    cases.flatMap((item) => (item.cause_category ? [item.cause_category] : [])),
  );
  const contributions = unique(cases.map((item) => item.contribution_class));
  const tools = unique(cases.map(getAiToolLabel));
  const languages = unique(
    cases.map((item) => item.repository_metadata.language),
  );
  const repositories = unique(
    cases
      .map((item) => item.repository)
      .filter((v): v is string => v != null),
  );
  const months = unique(
    cases.flatMap((item) =>
      item.published_at ? [item.published_at.slice(0, 7)] : [],
    ),
  ).reverse();
  const update = (key: keyof ResearchCaseFilters, value: string) => {
    setFilters((current) => ({ ...current, [key]: value }));
    setPage(1);
  };
  const clearFilters = () => {
    setFilters(EMPTY_FILTERS);
    setPage(1);
  };

  return (
    <section aria-label="Case search and filters">
      <div className="grid gap-3 border-y border-border py-4 sm:grid-cols-2 lg:grid-cols-4">
        <label className="text-xs text-muted-foreground lg:col-span-2">
          Search
          <input
            type="search"
            value={filters.query}
            onChange={(event) => update("query", event.target.value)}
            placeholder="CVE, GHSA, or repository"
            className="mt-1.5 h-10 w-full border border-input bg-background px-3 text-sm text-foreground outline-none focus:border-primary focus:ring-2 focus:ring-primary/15"
          />
        </label>
        <label className="text-xs text-muted-foreground">
          Root cause
          <select
            value={filters.cause}
            onChange={(event) => update("cause", event.target.value)}
            className="mt-1.5 h-10 w-full border border-input bg-background px-3 text-sm text-foreground outline-none focus:border-primary focus:ring-2 focus:ring-primary/15"
          >
            <option value="">All root causes</option>
            {causes.map((cause) => (
              <option key={cause} value={cause}>
                {getCauseCategoryLabel(cause)}
              </option>
            ))}
          </select>
        </label>
        <label className="text-xs text-muted-foreground">
          AI contribution
          <select
            value={filters.contribution}
            onChange={(event) => update("contribution", event.target.value)}
            className="mt-1.5 h-10 w-full border border-input bg-background px-3 text-sm text-foreground outline-none focus:border-primary focus:ring-2 focus:ring-primary/15"
          >
            <option value="">All contribution types</option>
            {contributions.map((contribution) => (
              <option key={contribution} value={contribution}>
                {formatContributionClass(contribution)}
              </option>
            ))}
          </select>
        </label>
        <label className="text-xs text-muted-foreground">
          AI tool
          <select
            value={filters.tool}
            onChange={(event) => update("tool", event.target.value)}
            className="mt-1.5 h-10 w-full border border-input bg-background px-3 text-sm text-foreground outline-none focus:border-primary focus:ring-2 focus:ring-primary/15"
          >
            <option value="">All tools</option>
            {tools.map((tool) => (
              <option key={tool}>{tool}</option>
            ))}
          </select>
        </label>
        <label className="text-xs text-muted-foreground">
          Language
          <select
            value={filters.language}
            onChange={(event) => update("language", event.target.value)}
            className="mt-1.5 h-10 w-full border border-input bg-background px-3 text-sm text-foreground outline-none focus:border-primary focus:ring-2 focus:ring-primary/15"
          >
            <option value="">All languages</option>
            {languages.map((language) => (
              <option key={language}>{language}</option>
            ))}
          </select>
        </label>
        <label className="text-xs text-muted-foreground">
          Repository
          <select
            value={filters.repository}
            onChange={(event) => update("repository", event.target.value)}
            className="mt-1.5 h-10 w-full border border-input bg-background px-3 text-sm text-foreground outline-none focus:border-primary focus:ring-2 focus:ring-primary/15"
          >
            <option value="">All repositories</option>
            {repositories.map((repository) => (
              <option key={repository}>{repository}</option>
            ))}
          </select>
        </label>
        <label className="text-xs text-muted-foreground">
          Advisory month
          <select
            value={filters.month}
            onChange={(event) => update("month", event.target.value)}
            className="mt-1.5 h-10 w-full border border-input bg-background px-3 text-sm text-foreground outline-none focus:border-primary focus:ring-2 focus:ring-primary/15"
          >
            <option value="">All months</option>
            {months.map((month) => (
              <option key={month} value={month}>
                {formatMonthShort(month)}
              </option>
            ))}
            <option value="undated">Date unavailable</option>
          </select>
        </label>
      </div>

      <div className="flex items-center justify-between gap-4 py-4 text-xs text-muted-foreground">
        <p>
          {filtered.length
            ? `${start + 1}–${Math.min(start + PAGE_SIZE, filtered.length)} of ${filtered.length} cases`
            : `0 of ${cases.length} cases`}
        </p>
        {Object.values(filters).some(Boolean) ? (
          <button
            type="button"
            onClick={clearFilters}
            className="text-primary hover:underline"
          >
            Clear filters
          </button>
        ) : null}
      </div>

      {filtered.length ? (
        <>
          <ResearchCaseTable cases={visible} />
          {pageCount > 1 ? (
            <nav
              aria-label="Case pages"
              className="flex items-center justify-between gap-4 border-b border-border py-4 text-sm"
            >
              <button
                type="button"
                disabled={page === 1}
                onClick={() => setPage((current) => Math.max(1, current - 1))}
                className="border border-border px-3 py-1.5 disabled:cursor-not-allowed disabled:opacity-35"
              >
                Previous
              </button>
              <span className="font-mono text-xs text-muted-foreground">
                Page {page} of {pageCount}
              </span>
              <button
                type="button"
                disabled={page === pageCount}
                onClick={() =>
                  setPage((current) => Math.min(pageCount, current + 1))
                }
                className="border border-border px-3 py-1.5 disabled:cursor-not-allowed disabled:opacity-35"
              >
                Next
              </button>
            </nav>
          ) : null}
        </>
      ) : (
        <p className="border-y border-border py-12 text-center text-sm text-muted-foreground">
          No cases match these filters.
        </p>
      )}
    </section>
  );
}
