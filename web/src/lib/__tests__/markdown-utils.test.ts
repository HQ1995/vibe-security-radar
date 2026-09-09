import { describe, expect, it } from "vitest";

import { stripMarkdown } from "@/lib/markdown-utils";

describe("stripMarkdown", () => {
  it("strips markdown to plain reader text", () => {
    const text = "## Summary\n\nThe `guard` can be bypassed on every call.";
    expect(stripMarkdown(text)).toBe("Summary\n\nThe guard can be bypassed on every call.");
  });
});
