/** Convert markdown-ish advisory text to plain text for cards and meta tags. */
export function stripMarkdown(text: string | null | undefined): string {
  if (!text) return "";
  const out: string[] = [];
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (/^\|[\s:|-]+\|$/.test(t)) continue;
    if (t.startsWith("|") && t.endsWith("|") && t.slice(1, -1).includes("|")) {
      const cells = t.slice(1, -1).split("|").map((c) => c.trim());
      out.push(cells.join(": "));
      continue;
    }
    out.push(t);
  }
  return out
    .join("\n")
    .replace(/^#{1,6}\s+/gm, "")
    .replace(/\x60{3}[\s\S]*?\x60{3}/g, " ")
    .replace(/\x60([^\x60]+)\x60/g, "$1")
    .replace(/\*\*([^*]+)\*\*/g, "$1")
    .replace(/!\[[^\]]*\]\([^)]*\)/g, "")
    .replace(/\[([^\]]+)\]\([^)]*\)/g, "$1")
    .replace(/^\s*[-*+]\s+/gm, "· ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}
