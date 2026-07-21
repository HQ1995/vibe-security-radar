"use client";

import { DistributionPieChart } from "@/components/distribution-pie-chart";
import { THEMED_ICONS } from "@/components/tool-icon";
import { getToolDisplayName, getToolColor } from "@/lib/constants";

interface ToolDistributionChartProps {
  readonly data: Readonly<Record<string, number>>;
  readonly totalCves?: number;
}

export function ToolDistributionChart({ data, totalCves }: ToolDistributionChartProps) {
  return (
    <DistributionPieChart
      title="Tool Distribution"
      data={data}
      getColor={getToolColor}
      getName={getToolDisplayName}
      getHref={(key) => `/cves?tool=${encodeURIComponent(key)}`}
      iconDir="/icons/tools"
      themedIcons={THEMED_ICONS}
      totalOverride={totalCves}
    />
  );
}
