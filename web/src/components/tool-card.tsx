import { ToolIcon } from "@/components/tool-icon";
import { EntityCard } from "@/components/entity-card";
import { getToolDisplayName } from "@/lib/constants";

interface ToolCardProps {
  readonly tool: string;
  readonly count: number;
  readonly severities: Readonly<Record<string, number>>;
}

export function ToolCard({ tool, count, severities }: ToolCardProps) {
  return (
    <EntityCard
      href={`/cves?tool=${encodeURIComponent(tool)}`}
      label={getToolDisplayName(tool)}
      icon={<ToolIcon tool={tool} size={22} />}
      count={count}
      severities={severities}
    />
  );
}
