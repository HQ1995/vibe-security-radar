import { describe, it, expect } from "vitest";
import {
  getCves,
  getStats,
  getCveById,
  getDataGenerationId,
  getDetectorInventory,
  isPublicVulnerabilityId,
} from "../data";

describe("getCves", () => {
  it("returns all CVEs", () => {
    const data = getCves();
    expect(data.total).toBeGreaterThanOrEqual(0);
    expect(Array.isArray(data.cves)).toBe(true);
  });

  it("cves have required fields", () => {
    const data = getCves();
    expect(data.generation_id).toBe(getDataGenerationId());
    expect(data.generation_id).toMatch(/^[0-9a-f]{64}$/);
    for (const cve of data.cves) {
      expect(cve.generation_id).toBe(data.generation_id);
      expect(isPublicVulnerabilityId(cve.id)).toBe(true);
      expect(typeof cve.confidence).toBe("number");
      expect(Array.isArray(cve.ai_tools)).toBe(true);
    }
  });
});

describe("isPublicVulnerabilityId", () => {
  it("accepts safe advisory families and rejects path-like values", () => {
    expect(isPublicVulnerabilityId("JLSEC-2025-60")).toBe(true);
    expect(isPublicVulnerabilityId("GO-2026-4526")).toBe(true);
    expect(isPublicVulnerabilityId("../escape")).toBe(false);
    expect(isPublicVulnerabilityId("bad id")).toBe(false);
  });
});

describe("getStats", () => {
  it("returns stats with required fields", () => {
    const stats = getStats();
    expect(stats.generation_id).toBe(getDataGenerationId());
    expect(typeof stats.total_cves).toBe("number");
    expect(typeof stats.by_tool).toBe("object");
    expect(typeof stats.by_severity).toBe("object");
  });

  it("keeps the detector inventory separate from the verified catalog", () => {
    const inventory = getDetectorInventory();
    if (inventory === null) return;
    expect(inventory.inventory_id).toMatch(/^[0-9a-f]{64}$/);
    expect(inventory.alias_class_count).toBe(inventory.rows.length);
    expect(inventory.kind).toBe("ai_vulnerability_detector_inventory");
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
