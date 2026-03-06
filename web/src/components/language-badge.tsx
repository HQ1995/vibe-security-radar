import { getLanguageColor } from "@/lib/constants";

export function LanguageBadge({ language }: { readonly language: string }) {
  const c = getLanguageColor(language);
  return (
    <span
      className="inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[10px] font-semibold"
      style={{ borderColor: `${c}40`, color: c, backgroundColor: `${c}15` }}
    >
      <span
        className="inline-block h-2 w-2 rounded-full"
        style={{ backgroundColor: c }}
      />
      {language}
    </span>
  );
}
