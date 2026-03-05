export interface DistributionEntry {
  readonly key: string;
  readonly count: number;
  readonly severities: Readonly<Record<string, number>>;
}

export function buildDistributionData<
  T extends { readonly severity: string },
>(
  counts: Readonly<Record<string, number>>,
  cves: readonly T[],
  matchFn: (cve: T, key: string) => boolean,
): readonly DistributionEntry[] {
  return Object.entries(counts)
    .map(([key, count]) => {
      const matched = cves.filter((c) => matchFn(c, key));
      const severities: Record<string, number> = {};
      for (const cve of matched) {
        severities[cve.severity] = (severities[cve.severity] ?? 0) + 1;
      }
      return { key, count, severities } as const;
    })
    .sort((a, b) => b.count - a.count);
}
