import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import {
  buildResearchTimeline,
  getAiToolDistribution,
  getCauseDistribution,
  getLanguageDistribution,
  getRepositoryDistribution,
  formatCaseLabel,
  getResearchCaseById,
  getResearchSnapshot,
  getResearchTimeline,
  preferredCaseId,
} from "@/lib/research-data";

describe("canonical research data", () => {
  it("resolves aliases and derives a timeline from the case array", () => {
    const snapshot = getResearchSnapshot();
    const timeline = getResearchTimeline();
    const caseCount = snapshot.snapshot.case_count;

    expect(snapshot.cases).toHaveLength(caseCount);
    expect(caseCount).toBeGreaterThanOrEqual(190);
    expect(snapshot.snapshot.status).toBe("PUBLISHED");
    expect(snapshot.snapshot.ledger_total).toBeGreaterThan(caseCount);
    expect(snapshot.snapshot.ledger_reviewed).toBeGreaterThan(1000);
    expect(snapshot.snapshot.ledger_not_started).toBeGreaterThan(0);
    expect(snapshot.cases.every((item) => Boolean(item.published_at))).toBe(
      true,
    );
    expect(snapshot.snapshot.unknown_publication_dates).toBe(0);
    expect(snapshot.snapshot.exact_publication_dates).toBe(caseCount);
    expect(
      (snapshot.snapshot.ledger_reviewed ?? 0) +
        (snapshot.snapshot.ledger_not_started ?? 0),
    ).toBe(snapshot.snapshot.ledger_total);
    expect(
      snapshot.snapshot.ai_root_cause! + snapshot.snapshot.ai_code_flawed!,
    ).toBe(caseCount);
    expect(getResearchCaseById("CVE-2026-34218")?.case_id).toBe(
      "GHSA-FPMV-5WGW-QHHR",
    );
    const permission = getResearchCaseById("CVE-2026-59233");
    expect(permission?.case_id).toBe("GHSA-4FXP-2M36-QV64");
    expect(permission?.contribution_class).toBe("AI_INCOMPLETE_REMEDIATION");
    expect(permission?.candidate_set[0]).toMatch(/^52e5e1938ba7/);
    expect(
      permission?.ir_chain?.attempted_remediation?.candidate_shas?.[0],
    ).toMatch(/^52e5e1938ba7/);
    expect(formatCaseLabel(permission!, "CVE-2026-59233")).toBe(
      "CVE-2026-59233 (GHSA-4FXP-2M36-QV64)",
    );
    expect(
      permission?.aliases.some(
        (alias) => alias.toUpperCase() === "GHSA-X8QQ-M4QC-RPJ5",
      ),
    ).toBe(false);
    expect(timeline.at(-1)?.month).toMatch(/^\d{4}-\d{2}$/);
    const causes = getCauseDistribution();
    expect(causes.map(({ count }) => count).reduce((a, b) => a + b, 0)).toBe(
      caseCount,
    );
    expect(causes.at(-1)?.key).toBe("other_ambiguous");
    expect(causes[0]?.label).toBe("Injection & unsafe execution");
    const tools = getAiToolDistribution();
    expect(tools.total).toBe(caseCount);
    expect(tools.coverage.partial).toBe(0);
    expect(tools.coverage.unresolved).toBe(0);
    expect(tools.items[0]).toMatchObject({ label: "Claude" });
    expect(tools.items.map(({ label }) => label)).toContain("ChatGPT/Codex");
    expect(getLanguageDistribution()[0]?.count).toBeGreaterThan(20);
    expect(getRepositoryDistribution()[0]).toMatchObject({
      label: "openclaw/openclaw",
    });
    const raw = readFileSync(
      resolve(import.meta.dirname, "../../generated/research-data.json"),
      "utf8",
    );
    expect(raw).not.toMatch(/[\u4e00-\u9fff]/);
    expect(snapshot.cases.every((item) => item.case_id)).toBe(true);
    expect(
      snapshot.cases.every(
        (item) => item.gates && Object.keys(item.gates).length > 0,
      ),
    ).toBe(true);

    const extended = buildResearchTimeline([
      ...snapshot.cases,
      { published_at: "2026-09-03" },
    ]);
    expect(extended.at(-1)).toEqual({ month: "2026-09", count: 1 });
  });

  it("keeps listing, detail, and evidence on one identity and class", () => {
    const cases = getResearchSnapshot().cases;
    const officialOwners = new Map<string, string>();
    const shaPrefix = (value: string) => value.toLowerCase().slice(0, 12);

    for (const item of cases) {
      if (item.ir_chain) {
        expect(item.contribution_class).toBe("AI_INCOMPLETE_REMEDIATION");
        const attempted =
          item.ir_chain.attempted_remediation?.candidate_shas ?? [];
        if (attempted.length) {
          expect(new Set(item.candidate_set.map(shaPrefix))).toEqual(
            new Set(attempted.map(shaPrefix)),
          );
        }
      }
      const evidenceSha = item.code_evidence?.candidate_url?.match(
        /\/commit\/([0-9a-fA-F]{7,40})/,
      )?.[1];
      if (evidenceSha && item.candidate_set.length) {
        expect(item.candidate_set.map(shaPrefix)).toContain(
          shaPrefix(evidenceSha),
        );
      }
      const ghsas = [item.case_id, ...item.aliases].filter((value) =>
        /^GHSA-/i.test(value),
      );
      expect(ghsas).toHaveLength(new Set(ghsas.map((value) => value.toUpperCase())).size);
      expect(ghsas.length).toBeLessThanOrEqual(1);
      for (const value of [item.case_id, ...item.aliases]) {
        if (!/^(GHSA-|CVE-)/i.test(value)) continue;
        const key = value.toUpperCase();
        const owner = officialOwners.get(key);
        expect(owner ?? item.case_id).toBe(item.case_id);
        officialOwners.set(key, item.case_id);
      }
    }

    expect(getResearchCaseById("GHSA-X8QQ-M4QC-RPJ5")).toBeNull();

    for (const item of cases) {
      if (item.contribution_class === "AI_INCOMPLETE_REMEDIATION") {
        expect(item.ir_chain, item.case_id).toBeTruthy();
      }
    }
    expect(getResearchCaseById("GHSA-8JQH-598V-RFXC")?.contribution_class).toBe(
      "AI_DIRECT_ROOT",
    );
    expect(getResearchCaseById("GHSA-8G7G-HMWM-6RV2")?.contribution_class).toBe(
      "AI_DIRECT_ROOT",
    );
    expect(getResearchCaseById("GHSA-8359-H9FX-J6V9")?.contribution_class).toBe(
      "AI_CODE_FLAWED",
    );
    const faraday = getResearchCaseById("GHSA-5RV5-XJ5J-3484");
    expect(faraday?.repository).toBe("lostisland/faraday");
    expect(faraday?.ir_chain?.original_advisory_ids).toContain(
      "GHSA-33MH-2634-FWR2",
    );
    expect(getResearchCaseById("GHSA-J5QP-P44G-2M49")?.ir_chain).toBeTruthy();
    expect(getResearchCaseById("CVE-2026-59221")?.case_id).toBe(
      "GHSA-FRVJ-C5QP-XJ4W",
    );
    expect(
      cases.some((item) => item.case_id.startsWith("ALIAS-4FDB")),
    ).toBe(false);

    const pmch = getResearchCaseById("GHSA-PMCH-G965-GRMR");
    expect(pmch).not.toBeNull();
    expect(preferredCaseId(pmch!)).toBe("CVE-2026-50180");
    expect(pmch?.aliases.some((alias) => alias.toUpperCase() === "CVE-2026-25879")).toBe(
      false,
    );

    const advisoryRepos = new Set(
      cases.map((item) => (item.repository || "").toLowerCase()),
    );
    expect(advisoryRepos.has("pypa/advisory-database")).toBe(false);
    expect(advisoryRepos.has("haxtheweb/issues")).toBe(false);
    expect(getResearchCaseById("GHSA-64CV-VXPR-J6VC")?.repository).toBe(
      "openedx/edx-enterprise",
    );
    expect(getResearchCaseById("GHSA-X34R-63HX-W57F")?.repository).toBe(
      "langroid/langroid",
    );
    expect(getResearchCaseById("GHSA-G2G8-95QG-V35H")?.repository).toBe(
      "haxtheweb/haxcms-nodejs",
    );
    const coolify = getResearchCaseById("CVE-2026-32718");
    expect(coolify?.candidate_set[0]).toMatch(/^62c394d3a1db/);
    expect(
      Boolean(
        coolify?.code_evidence?.comparison_hunks?.length ||
          coolify?.code_evidence?.candidate_hunks?.length,
      ),
    ).toBe(true);
    expect(coolify?.vulnerable_release?.version).toMatch(/beta\.466/);

    const noVersionRange = new Set(["GHSA-C7RR-QHWX-6Q49"]);
    for (const item of cases) {
      const hunks =
        item.code_evidence?.comparison_hunks?.length ||
        item.code_evidence?.candidate_hunks?.length;
      expect(hunks, item.case_id).toBeGreaterThan(0);
      const official = [item.case_id, ...item.aliases].filter((value) =>
        /^(GHSA-|CVE-)/i.test(value),
      );
      if (official.length && !noVersionRange.has(item.case_id.toUpperCase())) {
        expect(
          Boolean(item.vulnerable_release || item.fixed_release),
          item.case_id,
        ).toBe(true);
      }
    }
  });
});
