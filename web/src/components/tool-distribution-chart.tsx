"use client";

import { DistributionPieChart } from "@/components/distribution-pie-chart";
import { getToolDisplayName, getToolColor } from "@/lib/constants";

interface ToolDistributionChartProps {
  readonly data: Readonly<Record<string, number>>;
}

export function ToolDistributionChart({ data }: ToolDistributionChartProps) {
  return (
    <DistributionPieChart
      title="Tool Distribution"
      data={data}
      getColor={getToolColor}
      getName={getToolDisplayName}
    />
  );
}
