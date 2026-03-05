import { buildDistributionData } from "@/lib/distribution-utils";

export interface RepoData {
  readonly repo: string;
  readonly count: number;
  readonly severities: Readonly<Record<string, number>>;
}

/**
 * Extract "owner/repo" from a GitHub URL, lowercased.
 * Mirrors `_repo_url_to_display_name` in generate_web_data.py.
 */
export function repoUrlToDisplayName(repoUrl: string): string | null {
  const m = repoUrl
    .replace(/\/+$/, "")
    .match(/^https?:\/\/github\.com\/([^/]+)\/([^/]+?)(?:\.git)?$/);
  return m ? `${m[1]}/${m[2]}`.toLowerCase() : null;
}

/**
 * Build repo distribution data sorted by count descending.
 */
export function buildRepoData(
  byRepo: Readonly<Record<string, number>>,
  cves: readonly {
    readonly fix_commits: readonly { readonly repo_url: string }[];
    readonly severity: string;
  }[],
): readonly RepoData[] {
  return buildDistributionData(byRepo, cves, (cve, key) =>
    cve.fix_commits.some((fc) => repoUrlToDisplayName(fc.repo_url) === key),
  ).map((e) => ({
    repo: e.key,
    count: e.count,
    severities: e.severities,
  }));
}

/**
 * Filter to top N entries, including all ties at the Nth position.
 */
export function topNWithTies(
  data: readonly RepoData[],
  n: number,
): readonly RepoData[] {
  if (n <= 0 || data.length <= n) return data;
  const nthCount = data[n - 1].count;
  return data.filter((r) => r.count >= nthCount);
}
