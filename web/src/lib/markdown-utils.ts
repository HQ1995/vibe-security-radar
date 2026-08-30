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

/** True when the text is something a visitor can read, not an internal audit note. */
export function isPublicProse(text: string | null | undefined): boolean {
  if (!text) return false;
  const value = text.trim();
  if (value.length < 24) return false;
  if (
    /cand=|fix=|ai=\['|\/tmp\/|sink=|source=|guard=|class_id|\\\\s\+|decomposed_shas|bug_semantics/i.test(
      value,
    )
  ) {
    return false;
  }
  const words = value.split(/\s+/).filter(Boolean);
  if (words.length < 5) return false;
  const slashes = (value.match(/\//g) ?? []).length;
  if (slashes >= 4 && words.length < 12 && !/[.!?]\s/.test(value)) return false;
  return /[a-z]/i.test(value);
}

