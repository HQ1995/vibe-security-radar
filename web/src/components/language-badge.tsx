import { getLanguageColor } from "@/lib/constants";

export function LanguageBadge({ language }: { readonly language: string }) {
  const color = getLanguageColor(language);
  return (
    <span className="inline-flex items-center gap-1 rounded-md border border-border px-1.5 py-0.5 text-[10px] text-muted-foreground">
      <span
        aria-hidden="true"
        className="inline-block h-2 w-2 rounded-full"
        style={{ backgroundColor: color }}
      />
      {language}
    </span>
  );
}
