import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import ErrorPage from "@/app/error";
import { buildFilterQuery } from "@/components/cve-list";
import { getLangIconKey } from "@/components/language-distribution-chart";
import { getIconDimensions } from "@/components/tool-icon";
import { VerifiedBadge } from "@/components/verified-badge";

describe("CVE filter URLs", () => {
  it("omits default filters and safely encodes active filters", () => {
    expect(
      buildFilterQuery({
        search: "",
        severity: "ALL",
        tool: "ALL",
        language: "ALL",
        repo: "ALL",
      }),
    ).toBe("");

    expect(
      buildFilterQuery({
        search: "memory corruption",
        severity: "HIGH",
        tool: "claude_code",
        language: "C/C++",
        repo: "owner/repo",
      }),
    ).toBe(
      "search=memory+corruption&severity=HIGH&tool=claude_code&language=C%2FC%2B%2B&repo=owner%2Frepo",
    );
  });
});

describe("VerifiedBadge", () => {
  it("truncates the table label while retaining full tooltip context", () => {
    const html = renderToStaticMarkup(
      <VerifiedBadge
        verifiedBy="claude-opus-4-6-thinking,gpt-5.4-high"
      />,
    );

    expect(html).toContain("block truncate");
    expect(html).toContain("Claude Opus 4.6, GPT-5.4 High");
    expect(html).toContain("Verified by claude-opus-4-6-thinking");
  });
});

describe("chart icon contracts", () => {
  it("skips unavailable language assets", () => {
    expect(getLangIconKey("TypeScript")).toBe("typescript");
    expect(getLangIconKey("GitHub Actions")).toBeNull();
  });

  it("preserves non-square tool icon aspect ratios", () => {
    expect(getIconDimensions("github_copilot", 18)).toEqual({
      width: 18,
      height: 15,
    });
    expect(getIconDimensions("cursor", 18)).toEqual({
      width: 18,
      height: 21,
    });
  });
});

describe("global error page", () => {
  it("uses a stable user-safe message", () => {
    const html = renderToStaticMarkup(
      <ErrorPage
        error={new Error("database credential: secret")}
        reset={() => undefined}
      />,
    );

    expect(html).toContain(
      "An unexpected error occurred while rendering this page.",
    );
    expect(html).not.toContain("database credential");
  });
});
