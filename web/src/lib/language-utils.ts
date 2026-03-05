import { buildDistributionData } from "@/lib/distribution-utils";

export interface LanguageData {
  readonly language: string;
  readonly count: number;
  readonly severities: Readonly<Record<string, number>>;
}

export function buildLanguageData(
  byLanguage: Readonly<Record<string, number>>,
  cves: readonly {
    readonly languages: readonly string[];
    readonly severity: string;
  }[],
): readonly LanguageData[] {
  return buildDistributionData(byLanguage, cves, (c, key) =>
    c.languages.includes(key),
  ).map((e) => ({
    language: e.key,
    count: e.count,
    severities: e.severities,
  }));
}
