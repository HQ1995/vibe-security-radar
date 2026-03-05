import { buildDistributionData } from "@/lib/distribution-utils";

export interface ToolData {
  readonly tool: string;
  readonly count: number;
  readonly severities: Readonly<Record<string, number>>;
}

export function buildToolData(
  byTool: Readonly<Record<string, number>>,
  cves: readonly {
    readonly ai_tools: readonly string[];
    readonly severity: string;
  }[],
): readonly ToolData[] {
  return buildDistributionData(byTool, cves, (c, key) =>
    c.ai_tools.includes(key),
  ).map((e) => ({ tool: e.key, count: e.count, severities: e.severities }));
}
