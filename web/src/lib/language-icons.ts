const LANGUAGE_ICON_KEYS: Readonly<Record<string, string>> = {
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

export function getLanguageIconKey(language: string): string | null {
  return LANGUAGE_ICON_KEYS[language] ?? null;
}
