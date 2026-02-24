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
  return Object.entries(byTool)
    .map(([tool, count]) => {
      const toolCves = cves.filter((c) => c.ai_tools.includes(tool));
      const severities: Record<string, number> = {};
      for (const cve of toolCves) {
        severities[cve.severity] = (severities[cve.severity] ?? 0) + 1;
      }
      return { tool, count, severities } as const;
    })
    .sort((a, b) => b.count - a.count);
}
