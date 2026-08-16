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

/** First plain prose paragraph of an advisory, dropping headings, tables and code blocks. */
export function getProseSummary(text: string | null | undefined): string | null {
  if (!text) return null;
  const inTable = (line: string) => line.includes("|") && !line.startsWith("```");
  const paras: string[] = [];
  let cur = "";
  let inCode = false;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (line.startsWith("```")) { inCode = !inCode; continue; }
    if (inCode) continue;
    if (line.startsWith("|") || inTable(line) || /^#{1,6}\s/.test(line) || /^\|/.test(line)) { if (cur) { paras.push(cur); cur = ""; } continue; }
    if (line === "") { if (cur) { paras.push(cur); cur = ""; } continue; }
    cur = cur ? cur + " " + line : line;
  }
  if (cur) paras.push(cur);
  const para = paras.find((p) => p.length > 40);
  if (!para) return null;
  const clean = stripMarkdown(para);
  return clean.length > 500 ? clean.slice(0, 497) + "..." : clean;
}
