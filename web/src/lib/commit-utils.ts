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

export function formatBlameConfidence(confidence: number): string {
  return `${Math.round(confidence * 100)}%`;
}

export function firstLine(message: string): string {
  const newlineIndex = message.indexOf("\n");
  if (newlineIndex === -1) return message;
  return message.slice(0, newlineIndex);
}
