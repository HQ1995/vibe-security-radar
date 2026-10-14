export function formatPublished(published: string): string {
  if (!published) return "";
  if (/^\d{4}$/.test(published)) return published;
  if (/^\d{4}-\d{2}$/.test(published)) {
    const [year, month] = published.split("-");
    const date = new Date(Number(year), Number(month) - 1);
    if (isNaN(date.getTime())) return published;
    return date.toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
    });
  }
  try {
    const dateOnly = /^\d{4}-\d{2}-\d{2}$/.test(published);
    const date = dateOnly
      ? new Date(Number(published.slice(0, 4)), Number(published.slice(5, 7)) - 1, Number(published.slice(8, 10)))
      : new Date(published);
    if (isNaN(date.getTime())) return published;
    return date.toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  } catch {
    return published;
  }
}

