import { describe, expect, it } from "vitest";

import { isPublicProse, stripMarkdown } from "@/lib/markdown-utils";

describe("reader-facing prose filter", () => {
  it("accepts a plain sentence and strips markdown", () => {
    const text = "## Summary\n\nThe `guard` can be bypassed on every call.";
    expect(stripMarkdown(text)).toBe("Summary\n\nThe guard can be bypassed on every call.");
    expect(isPublicProse(stripMarkdown(text))).toBe(true);
  });

  it("rejects machine slugs, audit markers and glued advisory dumps", () => {
    expect(isPublicProse("session_state_shared_stateless_mode_token_cross_client")).toBe(false);
    expect(isPublicProse("Node vm vm2CWE-94 /vm_sandbox.js createRequireFunction fs/os/http/https/net/crypto require run()")).toBe(false);
    expect(isPublicProse("sink=runInThisContext class_id=alias-0016")).toBe(false);
  });
});
