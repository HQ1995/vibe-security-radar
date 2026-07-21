import { afterEach, describe, expect, it } from "vitest";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { loadPublicationContract } from "../../../scripts/publication-contract.mjs";
import { verifyStaticRelease } from "../../../scripts/verify-static-release.mjs";

const roots: string[] = [];
const REPOSITORY_ROOT = resolve(import.meta.dirname, "../../../..");
const GENERATED_AT = "2026-07-18T13:00:00+00:00";

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function writeJson(path: string, value: unknown) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function canonicalSha256(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

function entry(id: string) {
  return {
    id,
    description: "A test vulnerability",
    severity: "HIGH",
    cvss: 7.5,
    cwes: [],
    ecosystem: "",
    published: "2026-06-01",
    ai_tools: ["cursor"],
    ai_involved: null,
    signal_source: "commit",
    languages: ["Python"],
    confidence: 0.85,
    verified_by: "",
    how_introduced: "",
    verdict: "CONFIRMED",
    bug_commits: [],
    fix_commits: [],
    references: [],
  };
}

function stats(total: number) {
  return {
    generated_at: GENERATED_AT,
    total_cves: total,
    total_analyzed: total,
    with_fix_commits: 0,
    coverage_from: "2026-01-01",
    coverage_to: total ? "2026-06-01" : "",
    by_tool: total ? { cursor: total } : {},
    by_severity: total ? { HIGH: total } : {},
    by_language: total ? { Python: total } : {},
    by_repo: {},
    by_month: total
      ? [{ month: "2026-06", count: total, by_tool: { cursor: total } }]
      : [],
  };
}

function detectorInventory(ids: string[]) {
  const rows = [...ids].sort().map((id) => {
    const memberIds = [id];
    return {
      class_id: id,
      component_sha256: createHash("sha256")
        .update(`${memberIds.join("\n")}\n`, "utf8")
        .digest("hex"),
      source_evidence_sha256: canonicalSha256({ class_id: id, member_ids: memberIds }),
      analysis_subject: id,
      member_ids: memberIds,
      result_subject_ids: [id],
      coverage_status: "complete",
      detector_state: "positive",
      adjudication_state: "ai_causal",
      publication_state: "published",
      recall_stratum: "detected_positive",
      reasons: [],
    };
  });
  const aliasManifestSha256 = canonicalSha256(
    rows.map((row) => ({
      analysis_subject: row.analysis_subject,
      class_id: row.class_id,
      component_sha256: row.component_sha256,
      member_ids: row.member_ids,
      source_evidence_sha256: row.source_evidence_sha256,
    })),
  );
  const preimage = {
    schema_version: 2,
    kind: "ai_vulnerability_detector_inventory",
    generated_at: GENERATED_AT,
    source_snapshot_sha256: "e".repeat(64),
    source_receipt_sha256: "f".repeat(64),
    source_alias_class_manifest_sha256: aliasManifestSha256,
    campaign_id: "b".repeat(64),
    contract_sha256: "d".repeat(64),
    campaign_mode: "formal",
    complete: true,
    coverage_to: ids.length ? "2026-06-01" : "",
    alias_class_count: rows.length,
    detector_candidate_count: rows.length,
    pending_adjudication_count: 0,
    coverage_failure_count: 0,
    counts: {
      coverage_status: rows.length ? { complete: rows.length } : {},
      detector_state: rows.length ? { positive: rows.length } : {},
      adjudication_state: rows.length ? { ai_causal: rows.length } : {},
      publication_state: rows.length ? { published: rows.length } : {},
      recall_stratum: rows.length ? { detected_positive: rows.length } : {},
    },
    rows,
  };
  return { inventory_id: canonicalSha256(preimage), ...preimage };
}

function inventorySummary(inventory: ReturnType<typeof detectorInventory>) {
  return {
    path: "inventory.json",
    inventory_id: inventory.inventory_id,
    source_snapshot_sha256: inventory.source_snapshot_sha256,
    source_alias_class_manifest_sha256: inventory.source_alias_class_manifest_sha256,
    campaign_id: inventory.campaign_id,
    campaign_mode: inventory.campaign_mode,
    complete: inventory.complete,
    coverage_to: inventory.coverage_to,
    alias_class_count: inventory.alias_class_count,
    detector_candidate_count: inventory.detector_candidate_count,
    pending_adjudication_count: inventory.pending_adjudication_count,
    coverage_failure_count: inventory.coverage_failure_count,
  };
}

function sourceRemoteCutoff(schemaVersion = 3) {
  return {
    checked_at_utc: "2026-07-18T12:00:00+00:00",
    receipt_file: {
      name: "source-remote-check-now.json",
      path: "/tmp/source-remote-check-now.json",
      sha256: "e".repeat(64),
      size_bytes: 100,
    },
    remote_parity: true,
    receipt: {
      schema_version: schemaVersion,
      checked_at_utc: "2026-07-18T12:00:00+00:00",
      git_sources: [
        {
          branch: "main",
          head: "1".repeat(40),
          name: "cvelistV5",
          origin: "https://example.invalid/cvelist.git",
          path: "/tmp/sources/cvelist",
          remote_head: "1".repeat(40),
          tree: "2".repeat(40),
        },
      ],
      nvd_feeds: [
        {
          feed_path: "/tmp/sources/nvd.json.gz",
          feed_sha256: "3".repeat(64),
          feed_size: 10,
          meta_path: "/tmp/sources/nvd.meta",
          meta_sha256: "2".repeat(64),
          remote_etag: '"etag"',
          remote_last_modified: "Sat, 18 Jul 2026 12:00:00 GMT",
          remote_meta_sha256: "2".repeat(64),
          year: 2026,
        },
      ],
      osv_ecosystem_manifest: {
        ecosystem_count: 1,
        ecosystems: ["PyPI"],
        etag: `"${"0".repeat(32)}"`,
        filename: "ecosystems.txt",
        generation: "1784376000000000",
        last_modified: "Sat, 18 Jul 2026 12:00:00 GMT",
        md5_base64: "AAAAAAAAAAAAAAAAAAAAAA==",
        path: "/tmp/sources/ecosystems.txt",
        remote_size: 5,
        sha256: "7".repeat(64),
        size: 5,
        url: "https://storage.googleapis.com/osv-vulnerabilities/ecosystems.txt",
      },
      osv_archive_count: 1,
      osv_archives: [
        {
          crc32c_base64: "AAAAAA==",
          etag: `"${"0".repeat(32)}"`,
          filename: "PyPI.zip",
          generation: "1784376000000000",
          last_modified: "Sat, 18 Jul 2026 12:00:00 GMT",
          md5_base64: "AAAAAAAAAAAAAAAAAAAAAA==",
          path: "/tmp/sources/PyPI.zip",
          remote_size: 1,
          sha256: "4".repeat(64),
          size: 1,
          url: "https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip",
        },
      ],
      remote_parity: true,
    },
  };
}

function receipt(
  generationId: string,
  bundleSha256: string,
  manifestSha256: string,
  remoteSchemaVersion = 3,
  inventory: ReturnType<typeof detectorInventory> | null = null,
) {
  const value: Record<string, unknown> = {
    schema_version: 4,
    generation_id: generationId,
    generated_at: GENERATED_AT,
    campaign_id: "b".repeat(64),
    campaign_result_manifest_sha256: "c".repeat(64),
    contract_sha256: inventory?.contract_sha256 ?? "d".repeat(64),
    campaign_mode: "formal",
    population_policy: "formal_full",
    analyzer_contract_sha256: "d".repeat(64),
    signature_sha256: "f".repeat(64),
    alias_class_manifest_sha256:
      inventory?.source_alias_class_manifest_sha256 ?? "a".repeat(64),
    source_snapshot_sha256: "e".repeat(64),
    source_remote_cutoff: sourceRemoteCutoff(remoteSchemaVersion),
    publication_bundle_sha256: bundleSha256,
    publication_manifest_sha256: manifestSha256,
    publication_curation_consistency_report_sha256: "6".repeat(64),
    publication_curation_inputs_sha256: "5".repeat(64),
    heldout_quality_report_sha256: "7".repeat(64),
    heldout_selection_sha256: "8".repeat(64),
    heldout_labels_sha256: "9".repeat(64),
    heldout_campaign_population_sha256: "4".repeat(64),
    heldout_campaign_proof_sha256: "a".repeat(64),
    heldout_campaign_result_manifest_sha256: "b".repeat(64),
    recall_selection_sha256: "1".repeat(64),
    recall_labels_sha256: "2".repeat(64),
    recall_report_sha256: "3".repeat(64),
    recall_inventory_id: inventory?.inventory_id ?? "4".repeat(64),
    recall_selection_manifest_sha256: "5".repeat(64),
    protected_census_manifest_sha256: "6".repeat(64),
    protected_overlap_class_count: 0,
    protected_census_complete: true,
    verifier_contract_sha256: "7".repeat(64),
    verifier_git_commit: "1".repeat(40),
    verifier_git_tree: "2".repeat(40),
    verifier_files_manifest_sha256: "8".repeat(64),
    verifier_dependency_lock_sha256: "9".repeat(64),
    recall_evaluation_status: "complete_end_to_end",
    recall_evaluation_complete: true,
    recall_point_estimate: 1,
    recall_interval: [1, 1],
    targets: { precision: 0.95, recall: 0.95 },
    curation_consistency_point_estimates: { precision: 1, recall: 1 },
    heldout_point_estimates: { precision: 1, recall: 1 },
    heldout_measurement_boundary: {
      precision: "final detector precision among predicted positives",
      recall: "final classifier recall in the AI-signal candidate population",
      excluded: "upstream advisory discovery and AI-signature discovery recall",
    },
    evaluation_complete: true,
    release_safe: true,
    curation_consistent: true,
    heldout_certified: true,
  };
  if (inventory !== null) {
    Object.assign(value, {
      detector_inventory_id: inventory.inventory_id,
      detector_inventory_sha256: canonicalSha256(inventory),
      detector_inventory_campaign_mode: inventory.campaign_mode,
      detector_inventory_complete: inventory.complete,
      detector_inventory_source_snapshot_sha256: inventory.source_snapshot_sha256,
      detector_inventory_alias_class_manifest_sha256:
        inventory.source_alias_class_manifest_sha256,
      detector_inventory_alias_class_count: inventory.alias_class_count,
    });
  }
  return value;
}

function page(generationId: string) {
  return `<html data-publication-generation="${generationId}"><body>page</body></html>`;
}

function writeApp(appDirectory: string, ids: string[], generationId: string) {
  const detailDirectory = join(appDirectory, "cves");
  mkdirSync(detailDirectory, { recursive: true });
  for (const id of ids) writeFileSync(join(detailDirectory, `${id}.html`), page(generationId));
  writeFileSync(join(appDirectory, "index.html"), page(generationId));
  writeFileSync(join(appDirectory, "about.html"), page(generationId));
  writeFileSync(join(appDirectory, "_global-error.html"), "no root layout here");
  const monthDirectory = join(detailDirectory, "month");
  mkdirSync(monthDirectory);
  writeFileSync(join(monthDirectory, "2026-07.html"), page(generationId));
}

function fixture(
  ids = ["CVE-2026-1"],
  builtIds = ids,
  remoteSchemaVersion = 3,
  includeInventory = true,
) {
  const root = mkdtempSync(join(tmpdir(), "static-release-"));
  roots.push(root);
  const dataDirectory = join(root, "data");
  const cvesDirectory = join(dataDirectory, "cves");
  mkdirSync(cvesDirectory, { recursive: true });
  const entryPayloads = ids.map(entry);
  const inventory = includeInventory ? detectorInventory(ids) : null;
  const statsPayload = {
    ...stats(ids.length),
    ...(inventory === null ? {} : { inventory: inventorySummary(inventory) }),
  };
  const generationId = canonicalSha256({
    schema_version: 1,
    generated_at: GENERATED_AT,
    entries: entryPayloads,
    stats: statsPayload,
  });
  const publishedEntries = entryPayloads.map((value) => ({ generation_id: generationId, ...value }));
  const publishedStats = { generation_id: generationId, ...statsPayload };
  const index = { generation_id: generationId, generated_at: GENERATED_AT, total: ids.length, ids };
  writeJson(join(dataDirectory, "index.json"), index);
  writeJson(join(dataDirectory, "stats.json"), publishedStats);
  if (inventory !== null) writeJson(join(dataDirectory, "inventory.json"), inventory);
  for (const value of publishedEntries) writeJson(join(cvesDirectory, `${value.id}.json`), value);
  const preReceipt = loadPublicationContract({ dataDirectory });
  const bundleSha256 = canonicalSha256({
    index,
    entries: publishedEntries,
    stats: publishedStats,
  });
  writeJson(
    join(dataDirectory, "release-receipt.json"),
    receipt(
      generationId,
      bundleSha256,
      preReceipt.manifestSha256,
      remoteSchemaVersion,
      inventory,
    ),
  );
  const appDirectory = join(root, "app");
  writeApp(appDirectory, builtIds, generationId);
  return { root, dataDirectory, appDirectory, generationId, inventory };
}

function verify(paths: ReturnType<typeof fixture>, overrides = {}) {
  return verifyStaticRelease({
    ...paths,
    repositoryRoot: REPOSITORY_ROOT,
    runPythonValidation: false,
    ...overrides,
  });
}

function createPythonFormalFixture(root: string) {
  const script = `
import hashlib, json, subprocess, sys
from pathlib import Path
repo = Path.cwd()
sys.path.insert(0, str(repo / "scripts"))
sys.path.insert(0, str(repo / "scripts" / "tests"))
import heldout_quality_gate as heldout
import generate_web_data as web_generator
import web_data.writer as writer
from test_release_evidence import _artifacts, _canonical_sha256, _publication_entry, _publication_file_manifest, _publication_stats
from web_data.release_evidence import archive_release_evidence, prepare_release_activation_record, write_release_activation_record
root = Path(sys.argv[1])
git_root = root / "git-proof"
git_root.mkdir()
subprocess.run(["git", "init", "-q", str(git_root)], check=True)
subprocess.run(["git", "-C", str(git_root), "config", "user.name", "fixture"], check=True)
subprocess.run(["git", "-C", str(git_root), "config", "user.email", "fixture@example.invalid"], check=True)
output_dir = root / "published"
previous = [_publication_entry("CVE-2025-10000")]
writer.write_web_data(previous, _publication_stats(previous), output_dir, generated_at="2026-01-01T00:00:00+00:00", allow_unreceipted=True)
candidate = [_publication_entry("CVE-2026-10000")]
preliminary_index_bytes = (json.dumps({
    "schema_version": 1,
    "generation_id": "0" * 64,
    "generated_at": "2026-07-18T13:00:00+00:00",
    "total": 1,
    "ids": ["CVE-2026-10000"],
}, indent=2, sort_keys=True) + "\\n").encode("utf-8")
preliminary_artifacts = _artifacts(
    "0" * 64,
    publication_index_bytes=preliminary_index_bytes,
)
inventory = preliminary_artifacts["detector-inventory.json"]
candidate_stats = _publication_stats(candidate)
candidate_stats["inventory"] = web_generator._inventory_summary(inventory)
staged = writer.stage_web_data(
    candidate,
    candidate_stats,
    output_dir,
    generated_at="2026-07-18T13:00:00+00:00",
    inventory=inventory,
)
publication = writer.load_published_web_data(staged.staging_dir)
generation_id = publication.index["generation_id"]
publication_hash = writer.publication_bundle_sha256(publication)
publication_files = _publication_file_manifest(staged.staging_dir)
artifacts = _artifacts(generation_id, publication_bundle_sha256=publication_hash, publication_files=publication_files, publication_index_bytes=(staged.staging_dir / "index.json").read_bytes(), repo_root=git_root)
assert artifacts["detector-inventory.json"] == inventory
receipt = artifacts["release-receipt.json"]
writer.write_staged_release_receipt(staged, receipt)
evidence_root = root / "release-evidence-v1"
bundle = archive_release_evidence(root=evidence_root, generation_id=generation_id, generated_at="2026-07-18T13:00:00+00:00", artifacts=artifacts, trusted_repo_root=git_root)
bindings = {
    "root": evidence_root,
    "generation_id": generation_id,
    "evidence_bundle_sha256": bundle.bundle_sha256,
    "release_receipt_sha256": _canonical_sha256(receipt),
    "publication_bundle_sha256": publication_hash,
    "publication_manifest_sha256": _canonical_sha256(publication_files),
    "output_dir": output_dir,
    "candidate_dir": staged.staging_dir,
}
prepare_release_activation_record(**bindings)
with writer.publication_promotion_transaction(staged, expected_release_receipt=receipt) as promotion:
    commit = promotion.commit()
    write_release_activation_record(**bindings, promotion_commit=commit, publication_lock=promotion.parent_lock)
print(json.dumps({"dataDirectory": str(output_dir), "evidenceRoot": str(evidence_root), "generationId": generation_id, "gitRoot": str(git_root)}))
`;
  const result = spawnSync(
    "uv",
    ["run", "--project", "cve-analyzer", "python", "-c", script, root],
    { cwd: REPOSITORY_ROOT, encoding: "utf8", timeout: 120_000 },
  );
  if (result.status !== 0) throw new Error(result.stderr || result.stdout);
  return JSON.parse(result.stdout);
}

describe("static release manifest", () => {
  it("accepts an exact raw manifest and schema-4 receipt with schema-3 cutoff", () => {
    const paths = fixture([
      "CVE-2026-1",
      "GHSA-aaaa-bbbb-cccc",
      "RUSTSEC-2026-0207",
      "GO-2026-4526",
    ]);
    expect(verify(paths)).toMatchObject({ total: 4, generation_id: paths.generationId });
  });

  it("rejects a stats inventory binding when inventory.json is absent", () => {
    const paths = fixture(["CVE-2026-1"], undefined, 3, false);
    const statsPath = join(paths.dataDirectory, "stats.json");
    const statsValue = JSON.parse(readFileSync(statsPath, "utf8"));
    statsValue.inventory = {
      path: "inventory.json",
      inventory_id: "a".repeat(64),
      source_snapshot_sha256: "b".repeat(64),
      source_alias_class_manifest_sha256: "d".repeat(64),
      campaign_id: "c".repeat(64),
      campaign_mode: "formal",
      complete: true,
      coverage_to: "2026-07-19",
      alias_class_count: 1,
      detector_candidate_count: 1,
      pending_adjudication_count: 1,
      coverage_failure_count: 0,
    };
    writeJson(statsPath, statsValue);

    expect(() => loadPublicationContract({ dataDirectory: paths.dataDirectory })).toThrow(
      /missing inventory.json/,
    );
  });

  it("rejects a formal receipt when inventory.json is absent", () => {
    const paths = fixture(["CVE-2026-1"], undefined, 3, false);

    expect(() => loadPublicationContract({ dataDirectory: paths.dataDirectory })).toThrow(
      /formal detector inventory/,
    );
  });

  it("binds the detector inventory through stats and the release receipt", () => {
    const paths = fixture(["CVE-2026-1"], undefined, 3, true);
    const publication = loadPublicationContract({ dataDirectory: paths.dataDirectory });
    expect(publication.inventory).toMatchObject({
      inventory_id: paths.inventory?.inventory_id,
      source_alias_class_manifest_sha256:
        paths.inventory?.source_alias_class_manifest_sha256,
    });

    const receiptPath = join(paths.dataDirectory, "release-receipt.json");
    const releaseReceipt = JSON.parse(readFileSync(receiptPath, "utf8"));
    releaseReceipt.detector_inventory_alias_class_manifest_sha256 = "0".repeat(64);
    writeJson(receiptPath, releaseReceipt);
    expect(() => loadPublicationContract({ dataDirectory: paths.dataDirectory })).toThrow(
      /detector inventory binding/,
    );
  });

  it.each([
    ["incomplete status", { recall_evaluation_status: "incomplete" }],
    ["incomplete flag", { recall_evaluation_complete: false }],
    ["missing point", { recall_point_estimate: null }],
    ["out-of-range interval", { recall_interval: [-0.01, 1] }],
    ["interval excluding point", { recall_point_estimate: 0.5, recall_interval: [0.6, 1] }],
    ["point below target", { recall_point_estimate: 0.01, recall_interval: [0, 0.02] }],
    ["interval lower bound below target", { recall_interval: [0.94, 1] }],
  ])("rejects %s in the end-to-end recall receipt", (_label, mutation) => {
    const paths = fixture();
    const receiptPath = join(paths.dataDirectory, "release-receipt.json");
    const releaseReceipt = JSON.parse(readFileSync(receiptPath, "utf8"));
    Object.assign(releaseReceipt, mutation);
    writeJson(receiptPath, releaseReceipt);

    expect(() => loadPublicationContract({ dataDirectory: paths.dataDirectory })).toThrow(
      /recall (proof|point)|recall_evaluation_complete/,
    );
  });

  it("rejects a recall proof bound to a different detector inventory", () => {
    const paths = fixture();
    const receiptPath = join(paths.dataDirectory, "release-receipt.json");
    const releaseReceipt = JSON.parse(readFileSync(receiptPath, "utf8"));
    releaseReceipt.recall_inventory_id = "0".repeat(64);
    writeJson(receiptPath, releaseReceipt);

    expect(() => loadPublicationContract({ dataDirectory: paths.dataDirectory })).toThrow(
      /detector inventory binding/,
    );
  });

  it("cross-checks the fixture with the formal Python publication validator", () => {
    const paths = fixture();
    expect(
      verifyStaticRelease({
        ...paths,
        repositoryRoot: REPOSITORY_ROOT,
      }),
    ).toMatchObject({
      total: 1,
      generation_id: paths.generationId,
      formal_evidence_verified: false,
    });
  });

  it("rejects the obsolete schema-2 source cutoff and accepts schema 3", () => {
    expect(() => verify(fixture(["CVE-2026-1"], undefined, 2))).toThrow(/schema-3/);
    expect(verify(fixture(["CVE-2026-1"], undefined, 3))).toMatchObject({ total: 1 });
  });

  it("fails closed when the release receipt is absent", () => {
    const paths = fixture();
    unlinkSync(join(paths.dataDirectory, "release-receipt.json"));
    expect(() => verify(paths)).toThrow(/release receipt is missing/);
  });

  it("bounds each publication artifact before reading it", () => {
    const paths = fixture();
    expect(() =>
      loadPublicationContract({
        dataDirectory: paths.dataDirectory,
        requireReceipt: true,
        limits: { entryBytes: 64 },
      }),
    ).toThrow(/size bound/);
  });

  it("bounds the aggregate publication input bytes", () => {
    const paths = fixture();
    expect(() =>
      loadPublicationContract({
        dataDirectory: paths.dataDirectory,
        requireReceipt: true,
        limits: { totalBytes: 64 },
      }),
    ).toThrow(/aggregate bound/);
  });

  it("rejects symlinked static HTML", () => {
    const paths = fixture();
    const pagePath = join(paths.appDirectory, "about.html");
    unlinkSync(pagePath);
    symlinkSync(join(paths.appDirectory, "index.html"), pagePath);
    expect(() => verify(paths)).toThrow(/static app output contains a symlink/);
  });

  it("bounds each static HTML page before reading it", () => {
    const paths = fixture();
    expect(() => verify(paths, { staticLimits: { pageBytes: 64 } })).toThrow(
      /static HTML exceeds the 64-byte size bound/,
    );
  });

  it("bounds aggregate static HTML bytes", () => {
    const paths = fixture();
    expect(() => verify(paths, { staticLimits: { totalBytes: 256 } })).toThrow(
      /static HTML exceeds the 256-byte aggregate size bound/,
    );
  });

  it("rejects a mutated entry that preserves its old generation", () => {
    const paths = fixture();
    const entryPath = join(paths.dataDirectory, "cves", "CVE-2026-1.json");
    const value = JSON.parse(readFileSync(entryPath, "utf8"));
    value.description = "mutated after receipt";
    writeJson(entryPath, value);
    expect(() => verify(paths)).toThrow(/publication_manifest_sha256/);
  });

  it("rejects a mutated entry after every local generation field is resealed", () => {
    const paths = fixture();
    const entryPath = join(paths.dataDirectory, "cves", "CVE-2026-1.json");
    const indexPath = join(paths.dataDirectory, "index.json");
    const statsPath = join(paths.dataDirectory, "stats.json");
    const receiptPath = join(paths.dataDirectory, "release-receipt.json");
    const value = JSON.parse(readFileSync(entryPath, "utf8"));
    const index = JSON.parse(readFileSync(indexPath, "utf8"));
    const statsValue = JSON.parse(readFileSync(statsPath, "utf8"));
    value.description = "joint local reseal";
    const bareEntry = { ...value };
    const bareStats = { ...statsValue };
    delete bareEntry.generation_id;
    delete bareStats.generation_id;
    const generationId = canonicalSha256({
      schema_version: 1,
      generated_at: index.generated_at,
      entries: [bareEntry],
      stats: bareStats,
    });
    value.generation_id = generationId;
    statsValue.generation_id = generationId;
    index.generation_id = generationId;
    writeJson(entryPath, value);
    writeJson(statsPath, statsValue);
    writeJson(indexPath, index);
    const releaseReceipt = JSON.parse(readFileSync(receiptPath, "utf8"));
    releaseReceipt.generation_id = generationId;
    writeJson(receiptPath, releaseReceipt);
    expect(() => verify(paths)).toThrow(/publication_manifest_sha256/);
  });

  it("has Python reject a forged receipt bundle even when success flags remain true", () => {
    const paths = fixture();
    const receiptPath = join(paths.dataDirectory, "release-receipt.json");
    const releaseReceipt = JSON.parse(readFileSync(receiptPath, "utf8"));
    releaseReceipt.publication_bundle_sha256 = "0".repeat(64);
    writeJson(receiptPath, releaseReceipt);
    expect(() =>
      verifyStaticRelease({ ...paths, repositoryRoot: REPOSITORY_ROOT }),
    ).toThrow(/Python release validator rejected|publication_bundle_sha256/);
  });

  it("requires local activation and evidence in formal mode", () => {
    const paths = fixture();
    const evidenceRoot = join(paths.root, "release-evidence-v1");
    expect(() =>
      verifyStaticRelease({
        ...paths,
        repositoryRoot: REPOSITORY_ROOT,
        evidenceRoot,
        requireFormalEvidence: true,
      }),
    ).toThrow(/release validator rejected|missing|cannot/);
  });

  it("rejects a stale activation and a missing evidence generation", () => {
    const stale = fixture();
    const staleRoot = join(stale.root, "release-evidence-v1");
    mkdirSync(join(staleRoot, "activations"), { recursive: true });
    writeJson(join(staleRoot, "activations", `${"f".repeat(64)}.json`), { stale: true });
    expect(() =>
      verifyStaticRelease({
        ...stale,
        repositoryRoot: REPOSITORY_ROOT,
        evidenceRoot: staleRoot,
        requireFormalEvidence: true,
      }),
    ).toThrow(/release validator rejected|missing|cannot/);

    const missingEvidence = fixture();
    const missingRoot = join(missingEvidence.root, "release-evidence-v1");
    mkdirSync(join(missingRoot, "activations"), { recursive: true });
    writeJson(join(missingRoot, "activations", `${missingEvidence.generationId}.json`), {
      schema_version: 5,
      state: "active",
      generation_id: missingEvidence.generationId,
    });
    expect(() =>
      verifyStaticRelease({
        ...missingEvidence,
        repositoryRoot: REPOSITORY_ROOT,
        evidenceRoot: missingRoot,
        requireFormalEvidence: true,
      }),
    ).toThrow(/release validator rejected|activation|evidence/);
  });

  it("keeps formal activation fail-closed without replayable end-to-end recall evidence", () => {
    const root = mkdtempSync(join(tmpdir(), "formal-static-release-"));
    roots.push(root);
    expect(() => createPythonFormalFixture(root)).toThrow(/recall selection path is missing/);
  });

  it("rejects a stale detail page and a missing manifest detail page", () => {
    expect(() => verify(fixture(["CVE-2026-1"], ["CVE-2026-1", "CVE-2026-2"]))).toThrow(
      /stale=.*CVE-2026-2/,
    );
    expect(() => verify(fixture(["CVE-2026-1", "OSV-2026-2"], ["CVE-2026-1"]))).toThrow(
      /missing=.*OSV-2026-2/,
    );
  });

  it("requires exactly one matching generation marker on every app page", () => {
    const paths = fixture();
    writeFileSync(join(paths.appDirectory, "about.html"), "<html><body>missing</body></html>");
    expect(() => verify(paths)).toThrow(/about\.html/);
    writeFileSync(join(paths.appDirectory, "about.html"), page(paths.generationId));
    writeFileSync(
      join(paths.appDirectory, "cves", "month", "2026-07.html"),
      page("e".repeat(64)),
    );
    expect(() => verify(paths)).toThrow(/cves\/month\/2026-07\.html/);
  });

  it("rejects path-unsafe IDs before reading detail files", () => {
    const paths = fixture();
    const indexPath = join(paths.dataDirectory, "index.json");
    const index = JSON.parse(readFileSync(indexPath, "utf8"));
    index.ids = ["../CVE-2026-1"];
    writeJson(indexPath, index);
    expect(() => verify(paths)).toThrow(/unsafe/);
  });
});
