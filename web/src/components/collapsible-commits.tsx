"use client";

import { useState } from "react";

interface CollapsibleNonAiCommitsProps {
  readonly count: number;
  readonly children: React.ReactNode;
}

export function CollapsibleNonAiCommits({
  count,
  children,
}: CollapsibleNonAiCommitsProps) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div>
      <button
        type="button"
        onClick={() => setExpanded((prev) => !prev)}
        className="flex items-center gap-2 rounded-md border border-dashed border-muted-foreground/30 px-4 py-2 text-sm text-muted-foreground transition-colors hover:border-muted-foreground/60 hover:text-foreground w-full"
      >
        <span className="text-xs">{expanded ? "▼" : "▶"}</span>
        {expanded ? "Hide" : "Show"} {count} non-AI commit{count !== 1 ? "s" : ""}
      </button>
      {expanded && <div className="mt-3 space-y-3">{children}</div>}
    </div>
  );
}
