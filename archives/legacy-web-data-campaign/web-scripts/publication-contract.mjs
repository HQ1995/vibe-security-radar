import {
  closeSync,
  constants as fsConstants,
  existsSync,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  readdirSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { TextDecoder } from "node:util";

const PUBLIC_ID = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const SHA256 = /^[0-9a-f]{64}$/;
const UTF8 = new TextDecoder("utf-8", { fatal: true });
const MAX_INDEX_BYTES = 16 * 1024 * 1024;
const MAX_STATS_BYTES = 16 * 1024 * 1024;
const MAX_INVENTORY_BYTES = 128 * 1024 * 1024;
const MAX_ENTRY_BYTES = 8 * 1024 * 1024;
const MAX_RECEIPT_BYTES = 32 * 1024 * 1024;
const MAX_PUBLICATION_INPUT_BYTES = 512 * 1024 * 1024;

function contractError(message) {
  throw new Error(`Invalid published Web data: ${message}`);
}

function statSignature(stat) {
  return [stat.dev, stat.ino, stat.mode, stat.size, stat.mtimeNs, stat.ctimeNs].join(":");
}

function readStableRegular(path, label, maxBytes) {
  const noFollow = fsConstants.O_NOFOLLOW ?? 0;
  let descriptor;
  try {
    descriptor = openSync(path, fsConstants.O_RDONLY | noFollow);
  } catch (error) {
    contractError(
      `cannot open ${label} ${path}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  try {
    const before = fstatSync(descriptor, { bigint: true });
    if ((before.mode & BigInt(fsConstants.S_IFMT)) !== BigInt(fsConstants.S_IFREG)) {
      contractError(`${label} is not a regular file: ${path}`);
    }
    if (before.size > BigInt(maxBytes)) {
      contractError(`${label} exceeds the ${maxBytes}-byte size bound: ${path}`);
    }
    const chunks = [];
    let bytesRead = 0;
    while (true) {
      const chunk = Buffer.allocUnsafe(1024 * 1024);
      const count = readSync(descriptor, chunk, 0, chunk.length, null);
      if (count === 0) break;
      bytesRead += count;
      if (bytesRead > maxBytes) {
        contractError(`${label} exceeds the ${maxBytes}-byte size bound: ${path}`);
      }
      chunks.push(chunk.subarray(0, count));
    }
    const contents = Buffer.concat(chunks);
    const after = fstatSync(descriptor, { bigint: true });
    const current = lstatSync(path, { bigint: true });
    if (
      statSignature(before) !== statSignature(after) ||
      statSignature(after) !== statSignature(current) ||
      BigInt(contents.length) !== after.size
    ) {
      contractError(`${label} changed while being read: ${path}`);
    }
    return contents;
  } finally {
    closeSync(descriptor);
  }
}

function readJsonObject(path, label, maxBytes) {
  const bytes = readStableRegular(path, label, maxBytes);
  let value;
  try {
    value = JSON.parse(UTF8.decode(bytes));
  } catch (error) {
    contractError(
      `${label} is not valid UTF-8 JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    contractError(`${label} must contain an object`);
  }
  return { bytes, value };
}

function sha256(contents) {
  return createHash("sha256").update(contents).digest("hex");
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  if (typeof value === "number" && !Number.isFinite(value)) {
    contractError("raw publication manifest contains a non-finite number");
  }
  return JSON.stringify(value);
}

function canonicalSha256(value) {
  return sha256(Buffer.from(canonicalJson(value), "utf8"));
}

function boundedLimit(value, ceiling, label) {
  if (value === undefined) return ceiling;
  if (!Number.isSafeInteger(value) || value <= 0 || value > ceiling) {
    contractError(`${label} must be a positive safe integer at most ${ceiling}`);
  }
  return value;
}

function exactKeys(value, expected, label) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.join("\0") !== wanted.join("\0")) {
    contractError(`${label} has an unexpected contract: ${actual.join(", ")}`);
  }
}

function validateIndex(index) {
  const indexBase = ["generated_at", "generation_id", "ids", "total"];
  const indexKeys = Object.keys(index).sort();
  const indexExtra = indexKeys.filter((key) => !indexBase.includes(key));
  if (indexExtra.length > 1 || (indexExtra.length === 1 && indexExtra[0] !== "legacy_catalog")) {
    contractError(`index.json has an unexpected contract: ${indexKeys.join(", ")}`);
  }
  if ("legacy_catalog" in index && index.legacy_catalog !== true) {
    contractError("index.json legacy_catalog must be true when present");
  }
  if (typeof index.generation_id !== "string" || !SHA256.test(index.generation_id)) {
    contractError("index.json generation_id must be a lowercase SHA-256");
  }
  if (typeof index.generated_at !== "string" || !Number.isFinite(Date.parse(index.generated_at))) {
    contractError("index.json generated_at must be a timestamp");
  }
  if (!Number.isSafeInteger(index.total) || index.total < 0) {
    contractError("index.json total must be a non-negative safe integer");
  }
  if (
    !Array.isArray(index.ids) ||
    index.ids.some((id) => typeof id !== "string" || !PUBLIC_ID.test(id)) ||
    new Set(index.ids).size !== index.ids.length ||
    index.total !== index.ids.length
  ) {
    contractError("index.json total/IDs are inconsistent or unsafe");
  }
}

function validateStats(stats, index) {
  if (stats.generation_id !== index.generation_id || stats.generated_at !== index.generated_at) {
    contractError("index.json and stats.json belong to different generations");
  }
  if (
    !Number.isSafeInteger(stats.total_cves) ||
    stats.total_cves !== index.total ||
    !Number.isSafeInteger(stats.total_analyzed) ||
    stats.total_analyzed < index.total ||
    !Number.isSafeInteger(stats.with_fix_commits) ||
    stats.with_fix_commits > stats.total_analyzed
  ) {
    contractError("stats.json counts are inconsistent with index.json");
  }
}

function validateInventory(inventory, stats) {
  exactKeys(
    inventory,
    [
      "alias_class_count",
      "campaign_id",
      "campaign_mode",
      "complete",
      "contract_sha256",
      "counts",
      "coverage_failure_count",
      "coverage_to",
      "detector_candidate_count",
      "generated_at",
      "inventory_id",
      "kind",
      "pending_adjudication_count",
      "rows",
      "schema_version",
      "source_receipt_sha256",
      "source_alias_class_manifest_sha256",
      "source_snapshot_sha256",
    ],
    "inventory.json",
  );
  if (
    inventory.schema_version !== 2 ||
    inventory.kind !== "ai_vulnerability_detector_inventory" ||
    !SHA256.test(inventory.inventory_id ?? "") ||
    !SHA256.test(inventory.source_snapshot_sha256 ?? "") ||
    !SHA256.test(inventory.source_receipt_sha256 ?? "") ||
    !SHA256.test(inventory.source_alias_class_manifest_sha256 ?? "") ||
    !SHA256.test(inventory.campaign_id ?? "") ||
    !SHA256.test(inventory.contract_sha256 ?? "") ||
    !["formal", "incremental"].includes(inventory.campaign_mode) ||
    typeof inventory.complete !== "boolean" ||
    !Number.isSafeInteger(inventory.alias_class_count) ||
    inventory.alias_class_count < 0 ||
    !Array.isArray(inventory.rows) ||
    inventory.alias_class_count !== inventory.rows.length
  ) {
    contractError("inventory.json identity or population contract is invalid");
  }
  const dimensions = {
    coverage_status: new Set(["complete", "incomplete", "missing", "error"]),
    detector_state: new Set([
      "positive",
      "candidate",
      "negative",
      "exhausted",
      "incomplete",
      "not_evaluated",
    ]),
    adjudication_state: new Set(["ai_causal", "not_ai_causal", "unknown", "unreviewed"]),
    publication_state: new Set(["published", "eligible", "withheld", "not_applicable"]),
    recall_stratum: new Set([
      "detected_positive",
      "coverage_failure",
      "no_current_campaign_result",
      "no_fix_commit",
      "fix_no_bic",
      "bic_no_trusted_authorship",
      "trusted_signal_classifier_negative_or_incomplete",
    ]),
  };
  const seen = new Set();
  const seenMembers = new Set();
  const counts = Object.fromEntries(Object.keys(dimensions).map((dimension) => [dimension, {}]));
  let detectorCandidateCount = 0;
  let pendingAdjudicationCount = 0;
  let coverageFailureCount = 0;
  let fullyCovered = true;
  for (const row of inventory.rows) {
    exactKeys(
      row,
      [
        "adjudication_state",
        "analysis_subject",
        "class_id",
        "component_sha256",
        "coverage_status",
        "detector_state",
        "member_ids",
        "publication_state",
        "reasons",
        "recall_stratum",
        "result_subject_ids",
        "source_evidence_sha256",
        "stage_predictions",
      ],
      "inventory.json row",
    );
    const stagePredictions = row.stage_predictions;
    if (
      stagePredictions === null ||
      typeof stagePredictions !== "object" ||
      Array.isArray(stagePredictions)
    ) {
      contractError("inventory.json row stage_predictions must be an object");
    }
    exactKeys(
      stagePredictions,
      ["final_publication", "screening", "source_matcher", "verification"],
      "inventory.json row stage_predictions",
    );
    const stageValues = new Set(["positive", "negative", "incomplete"]);
    if (Object.values(stagePredictions).some((value) => !stageValues.has(value))) {
      contractError("inventory.json row stage_predictions is invalid");
    }
    if (
      row === null ||
      typeof row !== "object" ||
      Array.isArray(row) ||
      typeof row.class_id !== "string" ||
      !PUBLIC_ID.test(row.class_id) ||
      !SHA256.test(row.component_sha256 ?? "") ||
      !SHA256.test(row.source_evidence_sha256 ?? "") ||
      typeof row.analysis_subject !== "string" ||
      !PUBLIC_ID.test(row.analysis_subject) ||
      seen.has(row.class_id) ||
      !Array.isArray(row.member_ids) ||
      row.member_ids.length === 0 ||
      row.member_ids.some((id) => typeof id !== "string" || !PUBLIC_ID.test(id)) ||
      row.member_ids.join("\0") !== [...new Set(row.member_ids)].sort().join("\0") ||
      row.member_ids.some((id) => seenMembers.has(id)) ||
      !Array.isArray(row.result_subject_ids) ||
      row.result_subject_ids.join("\0") !== [...new Set(row.result_subject_ids)].sort().join("\0") ||
      row.result_subject_ids.some((id) => !row.member_ids.includes(id)) ||
      !row.member_ids.includes(row.analysis_subject) ||
      row.component_sha256 !==
        sha256(Buffer.from(`${row.member_ids.join("\n")}\n`, "utf8")) ||
      row.result_subject_ids.join("\0") !==
        (row.coverage_status === "missing" ? "" : row.analysis_subject) ||
      !Array.isArray(row.reasons) ||
      row.reasons.some((reason) => typeof reason !== "string") ||
      row.reasons.join("\0") !== [...new Set(row.reasons)].sort().join("\0")
    ) {
      contractError("inventory.json contains an invalid alias-class row");
    }
    seen.add(row.class_id);
    row.member_ids.forEach((id) => seenMembers.add(id));
    for (const [dimension, allowed] of Object.entries(dimensions)) {
      if (!allowed.has(row[dimension])) contractError(`inventory.json ${dimension} is invalid`);
      counts[dimension][row[dimension]] = (counts[dimension][row[dimension]] ?? 0) + 1;
    }
    const coverageFailureStrata = new Set(["coverage_failure", "no_current_campaign_result"]);
    if (
      (row.coverage_status !== "complete") !== coverageFailureStrata.has(row.recall_stratum)
    ) {
      contractError("inventory.json coverage failures must remain outside negative recall strata");
    }
    detectorCandidateCount += ["positive", "candidate"].includes(row.detector_state) ? 1 : 0;
    pendingAdjudicationCount += ["unknown", "unreviewed"].includes(row.adjudication_state) ? 1 : 0;
    coverageFailureCount += row.coverage_status === "complete" ? 0 : 1;
    fullyCovered &&= row.coverage_status === "complete";
  }
  if ([...seen].join("\0") !== [...seen].sort().join("\0")) {
    contractError("inventory.json alias classes are not sorted");
  }
  if (canonicalJson(counts) !== canonicalJson(inventory.counts)) {
    contractError("inventory.json dimension counts do not match rows");
  }
  if (
    inventory.detector_candidate_count !== detectorCandidateCount ||
    inventory.pending_adjudication_count !== pendingAdjudicationCount ||
    inventory.coverage_failure_count !== coverageFailureCount ||
    inventory.complete !== fullyCovered
  ) {
    contractError("inventory.json summary counts or completeness do not match rows");
  }
  const preimage = { ...inventory };
  delete preimage.inventory_id;
  if (canonicalSha256(preimage) !== inventory.inventory_id) {
    contractError("inventory.json inventory_id does not match its contents");
  }
  const summary = stats.inventory;
  if (
    summary === null ||
    typeof summary !== "object" ||
    summary.path !== "inventory.json" ||
    summary.inventory_id !== inventory.inventory_id ||
    summary.source_snapshot_sha256 !== inventory.source_snapshot_sha256 ||
    summary.source_alias_class_manifest_sha256 !==
      inventory.source_alias_class_manifest_sha256 ||
    summary.campaign_id !== inventory.campaign_id ||
    summary.campaign_mode !== inventory.campaign_mode ||
    summary.complete !== inventory.complete ||
    summary.alias_class_count !== inventory.alias_class_count ||
    summary.detector_candidate_count !== inventory.detector_candidate_count ||
    summary.pending_adjudication_count !== inventory.pending_adjudication_count ||
    summary.coverage_failure_count !== inventory.coverage_failure_count ||
    summary.coverage_to !== inventory.coverage_to
  ) {
    contractError("stats.json inventory binding does not match inventory.json");
  }
}

function validateReceipt(receipt, publication) {
  const requiredHashes = [
    "generation_id",
    "campaign_id",
    "campaign_result_manifest_sha256",
    "analyzer_contract_sha256",
    "signature_sha256",
    "alias_class_manifest_sha256",
    "source_snapshot_sha256",
    "publication_bundle_sha256",
    "publication_manifest_sha256",
    "detector_stage_metrics_sha256",
    "detector_stage_quality_gate_sha256",
    "publication_curation_consistency_report_sha256",
    "publication_curation_inputs_sha256",
    "heldout_quality_report_sha256",
    "heldout_selection_sha256",
    "heldout_labels_sha256",
    "heldout_campaign_population_sha256",
    "heldout_campaign_proof_sha256",
    "heldout_campaign_result_manifest_sha256",
    "recall_selection_sha256",
    "recall_labels_sha256",
    "recall_report_sha256",
    "recall_inventory_id",
    "recall_selection_manifest_sha256",
    "protected_census_manifest_sha256",
    "verifier_contract_sha256",
    "verifier_files_manifest_sha256",
    "verifier_dependency_lock_sha256",
  ];
  if (receipt.schema_version !== 5) contractError("release receipt requires schema_version 5");
  for (const field of requiredHashes) {
    if (typeof receipt[field] !== "string" || !SHA256.test(receipt[field])) {
      contractError(`release receipt ${field} must be a lowercase SHA-256`);
    }
  }
  for (const field of ["verifier_git_commit", "verifier_git_tree"]) {
    if (
      typeof receipt[field] !== "string" ||
      !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(receipt[field])
    ) {
      contractError(`release receipt ${field} must be a Git object ID`);
    }
  }
  for (const field of [
    "evaluation_complete",
    "release_safe",
    "curation_consistent",
    "heldout_certified",
    "detector_stage_quality_gate_passed",
    "recall_evaluation_complete",
    "protected_census_complete",
  ]) {
    if (receipt[field] !== true) contractError(`release receipt ${field} must be true`);
  }
  const recallPoint = receipt.recall_point_estimate;
  const recallInterval = receipt.recall_interval;
  const targets = receipt.targets;
  if (
    !Number.isInteger(receipt.protected_overlap_class_count) ||
    receipt.protected_overlap_class_count < 0
  ) {
    contractError("release receipt protected census proof is invalid");
  }
  if (
    receipt.recall_evaluation_status !== "complete_end_to_end" ||
    !Number.isFinite(recallPoint) ||
    recallPoint < 0 ||
    recallPoint > 1 ||
    !Array.isArray(recallInterval) ||
    recallInterval.length !== 2 ||
    recallInterval.some((bound) => !Number.isFinite(bound) || bound < 0 || bound > 1) ||
    recallInterval[0] > recallPoint ||
    recallPoint > recallInterval[1]
  ) {
    contractError("release receipt end-to-end recall proof is invalid");
  }
  if (
    targets === null ||
    typeof targets !== "object" ||
    Array.isArray(targets) ||
    Object.keys(targets).sort().join(",") !== "precision,recall" ||
    !Number.isFinite(targets.precision) ||
    targets.precision < 0.95 ||
    targets.precision > 1 ||
    !Number.isFinite(targets.recall) ||
    targets.recall < 0.95 ||
    targets.recall > 1
  ) {
    contractError("release receipt quality targets are invalid");
  }
  if (recallPoint < targets.recall || recallInterval[0] < targets.recall) {
    contractError(
      "release receipt end-to-end recall point and interval lower bound must meet the recall target",
    );
  }
  if (receipt.campaign_mode !== "formal" || receipt.population_policy !== "formal_full") {
    contractError("release receipt requires a formal full-population campaign");
  }
  if (
    receipt.generation_id !== publication.index.generation_id ||
    receipt.generated_at !== publication.index.generated_at
  ) {
    contractError("release receipt identity does not match index.json");
  }
  if (receipt.publication_manifest_sha256 !== publication.manifestSha256) {
    contractError("release receipt publication_manifest_sha256 does not match the raw files");
  }
  if (publication.inventory === null) {
    contractError("release receipt requires a formal detector inventory");
  }
  if (
    receipt.detector_inventory_id !== publication.inventory.inventory_id ||
      receipt.detector_inventory_sha256 !== canonicalSha256(publication.inventory) ||
      receipt.detector_inventory_campaign_mode !== publication.inventory.campaign_mode ||
      receipt.detector_inventory_complete !== publication.inventory.complete ||
      receipt.detector_inventory_source_snapshot_sha256 !==
        publication.inventory.source_snapshot_sha256 ||
      receipt.detector_inventory_alias_class_manifest_sha256 !==
        publication.inventory.source_alias_class_manifest_sha256 ||
      receipt.detector_inventory_alias_class_count !== publication.inventory.alias_class_count ||
      receipt.recall_inventory_id !== publication.inventory.inventory_id
  ) {
    contractError("release receipt detector inventory binding does not match inventory.json");
  }
  const cutoff = receipt.source_remote_cutoff;
  const remote = cutoff?.receipt;
  if (
    cutoff === null ||
    typeof cutoff !== "object" ||
    cutoff.remote_parity !== true ||
    remote === null ||
    typeof remote !== "object" ||
    remote.schema_version !== 3 ||
    remote.remote_parity !== true ||
    remote.checked_at_utc !== cutoff.checked_at_utc ||
    !Array.isArray(remote.git_sources) ||
    remote.git_sources.length === 0 ||
    !Array.isArray(remote.nvd_feeds) ||
    remote.nvd_feeds.length === 0 ||
    !Array.isArray(remote.osv_archives) ||
    remote.osv_archives.length === 0 ||
    remote.osv_archive_count !== remote.osv_archives.length ||
    remote.osv_ecosystem_manifest?.filename !== "ecosystems.txt"
  ) {
    contractError("release receipt requires a schema-3 source remote cutoff proof");
  }
}

export function loadPublicationContract({
  dataDirectory,
  requireReceipt = false,
  limits = {},
}) {
  // next.config.ts traces the fixed data subtree explicitly. This annotation
  // prevents Turbopack from treating the runtime absolute path as repo-wide.
  const root = resolve(/* turbopackIgnore: true */ dataDirectory);
  const rootMetadata = lstatSync(root);
  if (rootMetadata.isSymbolicLink() || !rootMetadata.isDirectory()) {
    contractError(`publication directory is missing or unsafe: ${root}`);
  }
  const indexLimit = boundedLimit(limits.indexBytes, MAX_INDEX_BYTES, "index limit");
  const statsLimit = boundedLimit(limits.statsBytes, MAX_STATS_BYTES, "stats limit");
  const inventoryLimit = boundedLimit(
    limits.inventoryBytes,
    MAX_INVENTORY_BYTES,
    "inventory limit",
  );
  const entryLimit = boundedLimit(limits.entryBytes, MAX_ENTRY_BYTES, "entry limit");
  const receiptLimit = boundedLimit(
    limits.receiptBytes,
    MAX_RECEIPT_BYTES,
    "receipt limit",
  );
  const totalLimit = boundedLimit(
    limits.totalBytes,
    MAX_PUBLICATION_INPUT_BYTES,
    "publication total limit",
  );
  let totalBytes = 0;
  const account = (artifact, label) => {
    totalBytes += artifact.bytes.length;
    if (totalBytes > totalLimit) {
      contractError(`${label} exceeds the ${totalLimit}-byte publication aggregate bound`);
    }
    return artifact;
  };
  const indexArtifact = account(
    readJsonObject(join(root, "index.json"), "index.json", indexLimit),
    "index.json",
  );
  const statsArtifact = account(
    readJsonObject(join(root, "stats.json"), "stats.json", statsLimit),
    "stats.json",
  );
  const index = indexArtifact.value;
  const stats = statsArtifact.value;
  validateIndex(index);
  validateStats(stats, index);
  const inventoryPath = join(root, "inventory.json");
  const inventoryArtifact = existsSync(inventoryPath)
    ? account(
        readJsonObject(inventoryPath, "inventory.json", inventoryLimit),
        "inventory.json",
      )
    : null;
  const inventory = inventoryArtifact?.value ?? null;
  if (stats.inventory !== undefined && inventory === null) {
    contractError("stats.json references a missing inventory.json");
  }
  if (inventory !== null) validateInventory(inventory, stats);

  const cvesDirectory = join(root, "cves");
  const cvesMetadata = lstatSync(cvesDirectory);
  if (cvesMetadata.isSymbolicLink() || !cvesMetadata.isDirectory()) {
    contractError(`published CVE directory is missing or unsafe: ${cvesDirectory}`);
  }
  const directoryEntries = readdirSync(cvesDirectory, { withFileTypes: true });
  const actualNames = new Set();
  for (const entry of directoryEntries) {
    if (!entry.isFile() || entry.isSymbolicLink() || !entry.name.endsWith(".json")) {
      contractError(`unexpected artifact in data/cves: ${entry.name}`);
    }
    actualNames.add(entry.name);
  }
  const expectedNames = new Set(index.ids.map((id) => `${id}.json`));
  const missing = [...expectedNames].filter((name) => !actualNames.has(name)).sort();
  const unexpected = [...actualNames].filter((name) => !expectedNames.has(name)).sort();
  if (missing.length || unexpected.length) {
    contractError(`manifest/file mismatch; missing=${JSON.stringify(missing)}, unexpected=${JSON.stringify(unexpected)}`);
  }

  const entryArtifacts = new Map();
  for (const id of index.ids) {
    const entryPath = resolve(cvesDirectory, `${id}.json`);
    if (dirname(entryPath) !== resolve(cvesDirectory)) contractError(`entry path escapes data/cves: ${id}`);
    const artifact = account(
      readJsonObject(entryPath, `${id}.json`, entryLimit),
      `${id}.json`,
    );
    if (artifact.value.id !== id || artifact.value.generation_id !== index.generation_id) {
      contractError(`${id}.json has a filename, id, or generation mismatch`);
    }
    entryArtifacts.set(id, artifact);
  }
  const manifest = [
    { path: "index.json", size_bytes: indexArtifact.bytes.length, sha256: sha256(indexArtifact.bytes) },
    { path: "stats.json", size_bytes: statsArtifact.bytes.length, sha256: sha256(statsArtifact.bytes) },
    ...(inventoryArtifact === null
      ? []
      : [{ path: "inventory.json", size_bytes: inventoryArtifact.bytes.length, sha256: sha256(inventoryArtifact.bytes) }]),
    ...[...entryArtifacts]
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      .map(([id, artifact]) => ({
        path: `cves/${id}.json`,
        size_bytes: artifact.bytes.length,
        sha256: sha256(artifact.bytes),
      })),
  ];
  const manifestSha256 = canonicalSha256(manifest);
  const receiptPath = join(root, "release-receipt.json");
  const receiptArtifact = existsSync(receiptPath)
    ? account(
        readJsonObject(receiptPath, "release-receipt.json", receiptLimit),
        "release-receipt.json",
      )
    : null;
  const receipt = receiptArtifact?.value ?? null;
  if (receipt === null && requireReceipt) contractError(`release receipt is missing: ${receiptPath}`);
  const publication = {
    dataDirectory: root,
    index,
    stats,
    inventory,
    entries: index.ids.map((id) => entryArtifacts.get(id).value),
    manifest,
    manifestSha256,
    receipt,
    receiptSha256: receiptArtifact === null ? null : sha256(receiptArtifact.bytes),
  };
  if (receipt !== null) validateReceipt(receipt, publication);
  return publication;
}
