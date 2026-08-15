import Image from "next/image";

import { ToolIcon } from "@/components/tool-icon";
import { getLanguageIconKey } from "@/lib/language-icons";

export interface DistributionBarItem {
  readonly label: string;
  readonly count: number;
  readonly muted?: boolean;
  readonly iconKey?: string;
}

export function DistributionBars({
  eyebrow,
  title,
  description,
  items,
  iconMode = "tool",
}: {
  readonly eyebrow: string;
  readonly title: string;
  readonly description: string;
  readonly items: readonly DistributionBarItem[];
  readonly iconMode?: "tool" | "language";
}) {
  const max = Math.max(1, ...items.map((item) => item.count));

  return (
    <section className="border-t border-border pt-4">
      <p className="section-kicker">{eyebrow}</p>
      <h3 className="mt-2 text-xl font-semibold tracking-[-0.025em]">
        {title}
      </h3>
      <p className="mt-1.5 text-xs leading-5 text-muted-foreground">
        {description}
      </p>
      <ol className="mt-4 space-y-3">
        {items.map((item) => {
          const languageIcon =
            iconMode === "language" ? getLanguageIconKey(item.label) : null;
          return (
          <li key={item.label}>
            <div className="mb-1 flex items-baseline justify-between gap-3 text-xs leading-4">
              <span className="flex min-w-0 items-center gap-2">
                {languageIcon ? (
                  <Image
                    src={`/icons/languages/${languageIcon}.svg`}
                    alt=""
                    width={16}
                    height={16}
                    className="shrink-0"
                  />
                ) : item.iconKey ? (
                  <span aria-hidden="true" className="flex w-5 justify-center">
                    <ToolIcon tool={item.iconKey} size={20} />
                  </span>
                ) : null}
                <span>{item.label}</span>
              </span>
              <span className="font-mono text-xs tabular-nums">{item.count}</span>
            </div>
            <div className="h-1.5 overflow-hidden bg-muted">
              <div
                className={item.muted ? "h-full bg-muted-foreground/45" : "h-full bg-primary"}
                style={{ width: `${(item.count / max) * 100}%` }}
                role="img"
                aria-label={`${item.label}: ${item.count} cases`}
              />
            </div>
          </li>
          );
        })}
      </ol>
    </section>
  );
}
