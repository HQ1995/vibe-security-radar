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
