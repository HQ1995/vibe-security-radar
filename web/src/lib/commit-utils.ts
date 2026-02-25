export function extractRepoName(repoUrl: string): string {
  try {
    const url = new URL(repoUrl);
    // Remove leading slash and trailing slashes, e.g. "/owner/repo/" -> "owner/repo"
    return url.pathname.replace(/^\/|\/$/g, "");
  } catch {
    return repoUrl.replace(/^https?:\/\//, "");
  }
}

export function buildCommitUrl(repoUrl: string, sha: string): string {
  const base = repoUrl.replace(/\/+$/, "");
  return `${base}/commit/${sha}`;
}

export function formatDate(dateString: string): string {
  try {
    const date = new Date(dateString);
    if (isNaN(date.getTime())) {
      return dateString;
    }
    return date.toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  } catch {
    return dateString;
  }
}

export function formatPublished(published: string): string {
  if (!published) return "";
  // Year-only (e.g., "2025")
  if (/^\d{4}$/.test(published)) return published;
  try {
    const date = new Date(published);
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

export function formatBlameConfidence(confidence: number): string {
  return `${Math.round(confidence * 100)}%`;
}

export function firstLine(message: string): string {
  const newlineIndex = message.indexOf("\n");
  if (newlineIndex === -1) return message;
  return message.slice(0, newlineIndex);
}
