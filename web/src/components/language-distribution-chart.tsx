"use client";

import { DistributionPieChart } from "@/components/distribution-pie-chart";
import { getLanguageColor } from "@/lib/constants";

interface LanguageDistributionChartProps {
  readonly data: Readonly<Record<string, number>>;
}

export function LanguageDistributionChart({
  data,
}: LanguageDistributionChartProps) {
  return (
    <DistributionPieChart
      title="Language Distribution"
      data={data}
      getColor={getLanguageColor}
    />
  );
}
