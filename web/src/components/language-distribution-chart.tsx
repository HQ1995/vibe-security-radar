"use client";

import { DistributionPieChart } from "@/components/distribution-pie-chart";
import { getLanguageColor } from "@/lib/constants";
import { getLanguageIconKey } from "@/lib/language-icons";

export function getLangIconKey(lang: string): string | null {
  return getLanguageIconKey(lang);
}

interface LanguageDistributionChartProps {
  readonly data: Readonly<Record<string, number>>;
  readonly totalCves?: number;
}

export function LanguageDistributionChart({
  data,
  totalCves,
}: LanguageDistributionChartProps) {
  return (
    <DistributionPieChart
      title="Languages represented on catalog pages"
      data={data}
      getColor={getLanguageColor}
      getHref={(key) => `/cves?language=${encodeURIComponent(key)}`}
      iconDir="/icons/languages"
      getIconKey={getLangIconKey}
      totalOverride={totalCves}
    />
  );
}
