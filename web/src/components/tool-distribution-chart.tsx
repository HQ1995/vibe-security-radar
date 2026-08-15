"use client";

import { DistributionPieChart } from "@/components/distribution-pie-chart";
import { getToolDisplayName, getToolColor } from "@/lib/constants";

interface ToolDistributionChartProps {
  readonly data: Readonly<Record<string, number>>;
  readonly totalCves?: number;
}

export function ToolDistributionChart({
  data,
  totalCves,
}: ToolDistributionChartProps) {
  return (
    <DistributionPieChart
      title="Tool signals on catalog pages"
      data={data}
      getColor={getToolColor}
      getName={getToolDisplayName}
      getHref={(key) => `/cves?tool=${encodeURIComponent(key)}`}
      iconDir="/icons/tools"
      totalOverride={totalCves}
    />
  );
}
