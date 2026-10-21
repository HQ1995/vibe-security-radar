import Image from "next/image";
import Link from "next/link";

import { ToolIcon } from "@/components/tool-icon";
import { getLanguageIconKey, languageIconClass } from "@/lib/language-icons";

export interface DistributionBarItem {
  readonly label: string;
  readonly count: number;
  readonly muted?: boolean;
  readonly iconKey?: string;
  readonly href?: string;
  readonly hint?: string;
}

export function DistributionBars({
  title,
  description,
  items,
  iconMode = "tool",
}: {
  readonly title: string;
  readonly description: string;
  readonly items: readonly DistributionBarItem[];
  readonly iconMode?: "tool" | "language";
}) {
  const max = Math.max(1, ...items.map((item) => item.count));

  return (
    <section>
      <h3 className="text-base font-semibold">{title}</h3>
      <p className="mt-1 text-sm leading-6 text-muted-foreground">
        {description}
      </p>
      <ol className="mt-3 space-y-1">
        {items.map((item) => {
          const languageIcon =
            iconMode === "language" ? getLanguageIconKey(item.label) : null;
          const body = (
            <>
              <div className="flex items-center justify-between gap-3 text-sm">
                <span className="flex min-w-0 items-center gap-2">
                  {languageIcon ? (
                    <Image
                      src={`/icons/languages/${languageIcon}.svg`}
                      alt=""
                      width={16}
                      height={16}
                      className={languageIconClass(languageIcon)}
                    />
                  ) : item.iconKey ? (
                    <span
                      aria-hidden="true"
                      className="flex w-5 justify-center"
                    >
                      <ToolIcon tool={item.iconKey} size={18} />
                    </span>
                  ) : null}
                  <span className="min-w-0 break-words group-hover:text-primary">
                    {item.label}
                  </span>
                </span>
                <span className="shrink-0 tabular-nums text-muted-foreground">
                  {item.count}
                </span>
              </div>
              <div className="mt-1.5 h-2 overflow-hidden rounded-full bg-muted">
                <div
                  className={`h-full rounded-full ${item.muted ? "bg-muted-foreground/45" : "bg-primary"}`}
                  style={{ width: `${(item.count / max) * 100}%` }}
                  role="img"
                  aria-label={`${item.label}: ${item.count} findings`}
                />
              </div>
            </>
          );
          return (
            <li key={item.label}>
              {item.href ? (
                <Link
                  href={item.href}
                  title={item.hint}
                  className="group -mx-2 block rounded-md px-2 py-1 transition-colors hover:bg-card"
                >
                  {body}
                </Link>
              ) : (
                <div className="py-1" title={item.hint}>
                  {body}
                </div>
              )}
            </li>
          );
        })}
      </ol>
    </section>
  );
}
