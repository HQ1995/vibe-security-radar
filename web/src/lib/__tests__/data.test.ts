import { describe, it, expect } from "vitest";
import { getCves, getStats, getCveById } from "../data";

describe("getCves", () => {
  it("returns all CVEs", () => {
    const data = getCves();
    expect(data.total).toBeGreaterThanOrEqual(0);
    expect(Array.isArray(data.cves)).toBe(true);
  });

  it("cves have required fields", () => {
    const data = getCves();
    for (const cve of data.cves) {
      expect(cve.id).toMatch(/^(CVE-|GHSA-|OSV-)/);
      expect(typeof cve.confidence).toBe("number");
      expect(Array.isArray(cve.ai_tools)).toBe(true);
    }
  });
});

describe("getStats", () => {
  it("returns stats with required fields", () => {
    const stats = getStats();
    expect(typeof stats.total_cves).toBe("number");
    expect(typeof stats.by_tool).toBe("object");
    expect(typeof stats.by_severity).toBe("object");
  });
});

describe("getCveById", () => {
  it("returns null for non-existent CVE", () => {
    const cve = getCveById("CVE-9999-99999");
    expect(cve).toBeNull();
  });

  it("returns CVE for existing ID", () => {
    const data = getCves();
    if (data.cves.length > 0) {
      const first = data.cves[0];
      const found = getCveById(first.id);
      expect(found).not.toBeNull();
      expect(found!.id).toBe(first.id);
    }
  });
});
