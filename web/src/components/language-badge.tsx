import Image from "next/image";

import { getLanguageColor } from "@/lib/constants";
import { getLanguageIconKey } from "@/lib/language-icons";

export function LanguageBadge({ language }: { readonly language: string }) {
  const iconKey = getLanguageIconKey(language);
  const color = getLanguageColor(language);
  return (
    <span className="inline-flex items-center gap-1.5 text-sm">
      {iconKey ? (
        <Image
          src={`/icons/languages/${iconKey}.svg`}
          alt=""
          width={16}
          height={16}
          className="shrink-0"
        />
      ) : (
        <span
          aria-hidden="true"
          className="inline-block h-2.5 w-2.5 rounded-full"
          style={{ backgroundColor: color }}
        />
      )}
      {language}
    </span>
  );
}
