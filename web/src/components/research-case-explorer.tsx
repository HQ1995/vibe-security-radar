"use client";

import { useEffect, useRef, useSyncExternalStore } from "react";
import { Search } from "lucide-react";

import { ResearchCaseTable } from "@/components/research-case-table";
import { rememberFindingsUrl } from "@/lib/findings-url";
import { formatMonthShort } from "@/lib/month-utils";
import {
  aiToolLabel,
  causeCategoryLabel,
  formatContributionClass,
  getCaseHeadline,
  type FindingRow,
  type ResearchLabels,
} from "@/lib/research-format";

export interface ResearchCaseFilters {
  readonly query: string;
  readonly cause: string;
  readonly contribution: string;
  readonly tool: string;
  readonly language: string;
  readonly repository: string;
  readonly month: string;
  readonly severity?: string;
}

const searchIndex = new WeakMap<FindingRow, string>();

function searchableText(item: FindingRow, labels: ResearchLabels): string {
  let text = searchIndex.get(item);
  if (text === undefined) {
    text = [
      item.case_id,
      ...item.aliases,
      ...item.candidate_set,
      ...item.carrier_set,
      ...item.minimum_fix_set,
      item.repository ?? "Not recorded",
      item.repository_metadata.language,
      item.published_at ?? "Date unavailable",
      getCaseHeadline(item),
      causeCategoryLabel(item.cause_category, labels),
      formatContributionClass(item.contribution_class),
      aiToolLabel(item, labels),
    ]
      .join(" ")
      .toLowerCase();
    searchIndex.set(item, text);
  }
  return text;
}

export function filterResearchCases<T extends FindingRow>(
  cases: readonly T[],
  filters: ResearchCaseFilters,
  labels: ResearchLabels,
): T[] {
  const terms = filters.query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  return cases.filter(
    (item) =>
      (!terms.length ||
        terms.every((term) => searchableText(item, labels).includes(term))) &&
      (!filters.cause || item.cause_category === filters.cause) &&
      (!filters.contribution ||
        item.contribution_class === filters.contribution) &&
      (!filters.tool || aiToolLabel(item, labels) === filters.tool) &&
      (!filters.language ||
        item.repository_metadata.language === filters.language) &&
      (!filters.repository || item.repository === filters.repository) &&
      (!filters.severity || (item.severity ?? "none") === filters.severity) &&
      (!filters.month ||
        (filters.month === "undated"
          ? !item.published_at
          : item.published_at?.startsWith(filters.month) === true)),
  );
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
  severity: "",
};

const URL_PARAMS: Readonly<Record<keyof ResearchCaseFilters, string>> = {
  query: "q",
  cause: "cause",
  contribution: "contribution",
  tool: "tool",
  language: "language",
  repository: "repository",
  month: "month",
  severity: "severity",
};

const FILTER_KEYS = Object.keys(URL_PARAMS) as (keyof ResearchCaseFilters)[];

const URL_EVENT = "findings-url-change";

function subscribeToUrl(callback: () => void) {
  window.addEventListener("popstate", callback);
  window.addEventListener(URL_EVENT, callback);
  return () => {
    window.removeEventListener("popstate", callback);
    window.removeEventListener(URL_EVENT, callback);
  };
}

function parseUrlState(search: string) {
  const params = new URLSearchParams(search);
  const filters = { ...EMPTY_FILTERS };
  for (const key of FILTER_KEYS) {
    filters[key as keyof typeof filters] = params.get(URL_PARAMS[key]) ?? "";
  }
  return {
    filters,
    page: Math.max(1, Math.floor(Number(params.get("page"))) || 1),
    sort: (params.get("sort") === "oldest" ? "oldest" : "newest") as SortOrder,
  };
}

type SortOrder = "newest" | "oldest";

function writeUrlState(
  filters: ResearchCaseFilters,
  page: number,
  sort: SortOrder = "newest",
) {
  const params = new URLSearchParams();
  for (const key of FILTER_KEYS) {
    if (filters[key]) params.set(URL_PARAMS[key], filters[key]);
  }
  if (sort !== "newest") params.set("sort", sort);
  if (page > 1) params.set("page", String(page));
  const query = params.toString();
  const url = `${window.location.pathname}${query ? `?${query}` : ""}`;
  if (url !== `${window.location.pathname}${window.location.search}`) {
    window.history.replaceState(null, "", url);
    window.dispatchEvent(new Event(URL_EVENT));
  }
}

const PAGE_SIZE = 20;

function pageNumbers(page: number, count: number): (number | null)[] {
  const wanted = new Set(
    [1, count, page - 1, page, page + 1].filter(
      (value) => value >= 1 && value <= count,
    ),
  );
  const sorted = [...wanted].sort((a, b) => a - b);
  const out: (number | null)[] = [];
  for (const value of sorted) {
    const previous = out.at(-1);
    if (typeof previous === "number" && value - previous === 2) {
      out.push(previous + 1);
    } else if (typeof previous === "number" && value - previous > 2) {
      out.push(null);
    }
    out.push(value);
  }
  return out;
}

export function ResearchCaseExplorer({
  cases,
  labels,
}: {
  readonly cases: readonly FindingRow[];
  readonly labels: ResearchLabels;
}) {
  const search = useSyncExternalStore(
    subscribeToUrl,
    () => window.location.search,
    () => "",
  );
  const { filters, page: requestedPage, sort } = parseUrlState(search);
  const resultsRef = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  useEffect(() => {
    const focusSearch = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      if (
        event.key !== "/" ||
        event.metaKey ||
        event.ctrlKey ||
        event.altKey ||
        target?.closest("input, textarea, select, [contenteditable='true']")
      )
        return;
      event.preventDefault();
      searchRef.current?.focus();
    };
    document.addEventListener("keydown", focusSearch);
    return () => document.removeEventListener("keydown", focusSearch);
  }, []);
  useEffect(() => {
    rememberFindingsUrl(`${window.location.pathname}${search}`);
  }, [search]);
  const matched = filterResearchCases(cases, filters, labels);
  const filtered = sort === "oldest" ? [...matched].reverse() : matched;
  const pageCount = Math.ceil(filtered.length / PAGE_SIZE);
  const page = Math.min(requestedPage, Math.max(1, pageCount));
  const start = (page - 1) * PAGE_SIZE;
  const visible = filtered.slice(start, start + PAGE_SIZE);
  const causes = unique(
    cases.flatMap((item) => (item.cause_category ? [item.cause_category] : [])),
  );
  const contributions = unique(cases.map((item) => item.contribution_class));
  const tools = unique(cases.map((item) => aiToolLabel(item, labels)));
  const languages = unique(
    cases
      .map((item) => item.repository_metadata.language)
      .filter((language) => Boolean(language)),
  );
  const repositories = unique(
    cases.map((item) => item.repository).filter((v): v is string => v != null),
  );
  const months = unique(
    cases.flatMap((item) =>
      item.published_at ? [item.published_at.slice(0, 7)] : [],
    ),
  ).reverse();
  const update = (key: keyof ResearchCaseFilters, value: string) =>
    writeUrlState({ ...filters, [key]: value }, 1, sort);
  const clearFilters = () => writeUrlState(EMPTY_FILTERS, 1, sort);
  const goToPage = (next: number) => {
    writeUrlState(filters, next, sort);
    resultsRef.current?.scrollIntoView({ block: "start" });
  };

  const selects: {
    readonly key: Exclude<keyof ResearchCaseFilters, "query">;
    readonly label: string;
    readonly all: string;
    readonly options: readonly {
      readonly value: string;
      readonly label: string;
    }[];
  }[] = [
    {
      key: "cause",
      label: "Root cause",
      all: "All root causes",
      options: causes.map((cause) => ({
        value: cause,
        label: causeCategoryLabel(cause, labels),
      })),
    },
    {
      key: "contribution",
      label: "AI contribution",
      all: "All contribution types",
      options: contributions.map((contribution) => ({
        value: contribution,
        label: formatContributionClass(contribution),
      })),
    },
    {
      key: "tool",
      label: "AI tool",
      all: "All tools",
      options: tools.map((tool) => ({ value: tool, label: tool })),
    },
    {
      key: "language",
      label: "Language",
      all: "All languages",
      options: languages.map((language) => ({
        value: language,
        label: language,
      })),
    },
    {
      key: "severity",
      label: "Severity",
      all: "All severities",
      options: [
        { value: "CRITICAL", label: "Critical" },
        { value: "HIGH", label: "High" },
        { value: "MEDIUM", label: "Medium" },
        { value: "LOW", label: "Low" },
        { value: "none", label: "Not scored" },
      ],
    },
    {
      key: "repository",
      label: "Repository",
      all: "All repositories",
      options: repositories.map((repository) => ({
        value: repository,
        label: repository,
      })),
    },
    {
      key: "month",
      label: "Advisory month",
      all: "All months",
      options: [
        ...months.map((month) => ({
          value: month,
          label: formatMonthShort(month),
        })),
        { value: "undated", label: "Date unavailable" },
      ],
    },
  ];
  const active = Object.values(filters).some(Boolean);
  const count = (pick: (item: FindingRow) => string | null) => {
    const tally = new Map<string, number>();
    for (const item of cases) {
      const value = pick(item);
      if (value) tally.set(value, (tally.get(value) ?? 0) + 1);
    }
    return tally;
  };
  const facetCounts = {
    tool: count((item) => aiToolLabel(item, labels)),
    contribution: count((item) => item.contribution_class),
    cause: count((item) => item.cause_category),
    language: count((item) => item.repository_metadata.language || null),
    severity: count((item) => item.severity ?? "none"),
  };
  const facets = selects
    .filter((select) => select.key in facetCounts)
    .map((select) => ({
      ...select,
      options: select.options
        .map((option) => ({
          ...option,
          count:
            facetCounts[select.key as keyof typeof facetCounts].get(
              option.value,
            ) ?? 0,
        }))
        .sort((a, b) =>
          select.key === "severity"
            ? 0
            : b.count - a.count || a.label.localeCompare(b.label),
        ),
    }))
    .sort(
      (a, b) =>
        ["tool", "contribution", "severity", "cause", "language"].indexOf(
          a.key,
        ) -
        ["tool", "contribution", "severity", "cause", "language"].indexOf(
          b.key,
        ),
    );
  const headerSelects = selects.filter(
    (select) => select.key === "repository" || select.key === "month",
  );
  const selectClass = (value: string) =>
    `h-8 min-w-0 max-w-full truncate rounded-md border bg-card px-2 text-[13px] outline-none focus:border-primary focus:ring-2 focus:ring-primary/15 ${
      value
        ? "border-primary/60 text-foreground"
        : "border-input text-muted-foreground"
    }`;

  return (
    <section
      aria-label="Finding search and filters"
      className="grid gap-x-10 gap-y-6 lg:grid-cols-[14rem_minmax(0,1fr)]"
    >
      <nav aria-label="Filter findings" className="hidden lg:block">
        <div className="space-y-6">
          {facets.map((facet) => (
            <div key={facet.key}>
              <h2 className="px-3 text-xs font-semibold text-muted-foreground">
                {facet.label}
              </h2>
              <ul className="mt-1.5 space-y-px text-sm">
                {facet.options.map((option) => {
                  const selected = filters[facet.key] === option.value;
                  return (
                    <li key={option.value}>
                      <button
                        type="button"
                        aria-pressed={selected}
                        onClick={() =>
                          update(facet.key, selected ? "" : option.value)
                        }
                        className={`flex w-full items-baseline justify-between gap-3 rounded-md px-3 py-1.5 text-left transition-colors ${
                          selected
                            ? "bg-primary text-primary-foreground"
                            : "hover:bg-muted"
                        }`}
                      >
                        <span className="min-w-0 leading-5">
                          {option.label}
                        </span>
                        <span
                          className={`shrink-0 text-xs tabular-nums ${
                            selected
                              ? "text-primary-foreground"
                              : "text-muted-foreground"
                          }`}
                        >
                          {option.count}
                        </span>
                      </button>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
        </div>
      </nav>

      <div className="min-w-0">
        <label className="relative block">
          <span className="sr-only">Search</span>
          <Search
            aria-hidden="true"
            className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground"
          />
          <input
            ref={searchRef}
            type="search"
            value={filters.query}
            onChange={(event) => update("query", event.target.value)}
            placeholder="CVE, GHSA, or repository"
            className="h-10 w-full rounded-md border border-input bg-card pl-9 pr-10 text-sm text-foreground outline-none focus:border-primary focus:ring-2 focus:ring-primary/15"
          />
          <kbd
            aria-hidden="true"
            className="pointer-events-none absolute right-3 top-1/2 hidden -translate-y-1/2 rounded border border-border px-1.5 font-mono text-[11px] text-muted-foreground sm:block"
          >
            /
          </kbd>
        </label>

        <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4 lg:hidden">
          {facets.map((facet) => (
            <label key={facet.key} className="min-w-0">
              <span className="sr-only">{facet.label}</span>
              <select
                value={filters[facet.key] ?? ""}
                onChange={(event) => update(facet.key, event.target.value)}
                className={`${selectClass(filters[facet.key] ?? "")} w-full`}
              >
                <option value="">{facet.all}</option>
                {facet.options.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label} ({option.count})
                  </option>
                ))}
              </select>
            </label>
          ))}
        </div>

        <div
          ref={resultsRef}
          className="mt-4 flex scroll-mt-20 flex-wrap items-center justify-between gap-x-4 gap-y-2 border-b border-border pb-3"
        >
          <p className="text-sm font-semibold">
            {filtered.length === cases.length
              ? `${cases.length} findings`
              : `${filtered.length} of ${cases.length} ${filtered.length === 1 ? "finding" : "findings"}`}
            {active ? (
              <button
                type="button"
                onClick={clearFilters}
                className="ml-3 text-sm font-normal text-primary hover:underline"
              >
                Clear filters
              </button>
            ) : null}
          </p>
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            {headerSelects.map((select) => (
              <label key={select.key} className="min-w-0">
                <span className="sr-only">{select.label}</span>
                <select
                  value={filters[select.key] ?? ""}
                  onChange={(event) => update(select.key, event.target.value)}
                  className={`${selectClass(filters[select.key] ?? "")} w-40`}
                >
                  <option value="">{select.all}</option>
                  {select.options.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </label>
            ))}
            <a
              href="/data/findings.csv"
              download
              className="px-1 text-[13px] text-muted-foreground hover:text-foreground"
            >
              CSV
            </a>
            <label className="min-w-0">
              <span className="sr-only">Sort</span>
              <select
                value={sort}
                onChange={(event) =>
                  writeUrlState(filters, 1, event.target.value as SortOrder)
                }
                className={`${selectClass("")} w-32`}
              >
                <option value="newest">Newest first</option>
                <option value="oldest">Oldest first</option>
              </select>
            </label>
          </div>
        </div>

        {filtered.length ? (
          <>
            <ResearchCaseTable cases={visible} labels={labels} />
            {pageCount > 1 ? (
              <nav
                aria-label="Finding pages"
                className="flex items-center justify-between gap-4 pt-5 text-sm"
              >
                <button
                  type="button"
                  disabled={page === 1}
                  onClick={() => goToPage(Math.max(1, page - 1))}
                  className="rounded-md border border-border bg-card px-3 py-1.5 font-medium transition-colors hover:border-foreground/40 disabled:cursor-not-allowed disabled:opacity-35"
                >
                  Previous
                </button>
                <span className="text-xs tabular-nums text-muted-foreground sm:hidden">
                  Page {page} of {pageCount}
                </span>
                <ol className="hidden items-center gap-1 sm:flex">
                  <li className="sr-only">
                    Page {page} of {pageCount}
                  </li>
                  {pageNumbers(page, pageCount).map((value, index) =>
                    value === null ? (
                      <li
                        key={`gap-${index}`}
                        aria-hidden="true"
                        className="px-1 text-muted-foreground"
                      >
                        …
                      </li>
                    ) : (
                      <li key={value}>
                        <button
                          type="button"
                          aria-current={value === page ? "page" : undefined}
                          onClick={() => goToPage(value)}
                          className={`min-w-8 rounded-md px-2 py-1 text-sm tabular-nums transition-colors ${
                            value === page
                              ? "bg-primary font-semibold text-primary-foreground"
                              : "hover:bg-muted"
                          }`}
                        >
                          {value}
                        </button>
                      </li>
                    ),
                  )}
                </ol>
                <button
                  type="button"
                  disabled={page === pageCount}
                  onClick={() => goToPage(Math.min(pageCount, page + 1))}
                  className="rounded-md border border-border bg-card px-3 py-1.5 font-medium transition-colors hover:border-foreground/40 disabled:cursor-not-allowed disabled:opacity-35"
                >
                  Next
                </button>
              </nav>
            ) : null}
          </>
        ) : (
          <div className="py-12 text-center text-sm text-muted-foreground">
            <p className="text-base font-medium text-foreground">
              No findings match these filters.
            </p>
            <p className="mt-2">
              Try a CVE or GHSA ID, a repository name, or fewer filters.
            </p>
            {active ? (
              <button
                type="button"
                onClick={clearFilters}
                className="mt-4 rounded-md border border-border bg-card px-3 py-1.5 font-medium text-foreground transition-colors hover:border-foreground/40"
              >
                Clear all filters
              </button>
            ) : null}
          </div>
        )}
      </div>
    </section>
  );
}
