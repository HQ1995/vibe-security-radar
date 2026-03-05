import { EntityCard } from "@/components/entity-card";
import { getLanguageColor } from "@/lib/constants";

interface LanguageCardProps {
  readonly language: string;
  readonly count: number;
  readonly severities: Readonly<Record<string, number>>;
}

export function LanguageCard({
  language,
  count,
  severities,
}: LanguageCardProps) {
  return (
    <EntityCard
      href={`/cves?language=${encodeURIComponent(language)}`}
      label={language}
      icon={
        <span
          aria-hidden="true"
          className="inline-block h-3 w-3 rounded-full shrink-0"
          style={{ backgroundColor: getLanguageColor(language) }}
        />
      }
      count={count}
      severities={severities}
    />
  );
}
