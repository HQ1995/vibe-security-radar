"use client";

import { DistributionPieChart } from "@/components/distribution-pie-chart";
import { getLanguageColor } from "@/lib/constants";

/** Map language display names to icon file names in /icons/languages/. */
const LANG_ICON_KEY: Readonly<Record<string, string>> = {
  Python: "python",
  JavaScript: "javascript",
  TypeScript: "typescript",
  Go: "go",
  Rust: "rust",
  Ruby: "ruby",
  Java: "java",
  Kotlin: "kotlin",
  PHP: "php",
  "C/C++": "c_cpp",
  "C#": "csharp",
  Swift: "swift",
  Vue: "vue",
  Dart: "dart",
  Scala: "scala",
  Shell: "shell",
  Perl: "perl",
};

function getLangIconKey(lang: string): string {
  return LANG_ICON_KEY[lang] ?? lang.toLowerCase();
}

interface LanguageDistributionChartProps {
  readonly data: Readonly<Record<string, number>>;
}

export function LanguageDistributionChart({
  data,
}: LanguageDistributionChartProps) {
  return (
    <DistributionPieChart
      title="Language Distribution"
      data={data}
      getColor={getLanguageColor}
      iconDir="/icons/languages"
      getIconKey={getLangIconKey}
    />
  );
}
