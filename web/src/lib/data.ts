import path from "node:path";
import type {
  CveEntry,
  CvesData,
  CvesIndex,
  DetectorInventory,
  StatsData,
} from "./types";
import { loadPublicationContract } from "../../scripts/publication-contract.mjs";

// Keep this path-safe contract aligned with
// scripts/web_data/schema.py::VULNERABILITY_ID_PATTERN.
const PUBLIC_ID = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const GENERATION_ID = /^[0-9a-f]{64}$/;

export function isPublicVulnerabilityId(value: unknown): value is string {
  return typeof value === "string" && PUBLIC_ID.test(value);
}

function publicationError(message: string): never {
  throw new Error(`Invalid published Web data: ${message}`);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonNegativeInteger(value: unknown): value is number {
  return Number.isInteger(value) && typeof value === "number" && value >= 0;
}

function parseIndex(value: unknown): CvesIndex {
  if (!isRecord(value)) publicationError("index.json must contain an object");
  const keys = Object.keys(value).sort();
  if (keys.join(",") !== "generated_at,generation_id,ids,total") {
    publicationError(`index.json has an unexpected contract: ${keys.join(", ")}`);
  }
  if (typeof value.generation_id !== "string" || !GENERATION_ID.test(value.generation_id)) {
    publicationError("index.json generation_id must be a lowercase SHA-256");
  }
  if (typeof value.generated_at !== "string" || !Number.isFinite(Date.parse(value.generated_at))) {
    publicationError("index.json generated_at must be a timestamp");
  }
  if (!isNonNegativeInteger(value.total)) {
    publicationError("index.json total must be a non-negative integer");
  }
  if (!Array.isArray(value.ids) || !value.ids.every(isPublicVulnerabilityId)) {
    publicationError("index.json contains an unsafe or malformed id");
  }
  if (new Set(value.ids).size !== value.ids.length) {
    publicationError("index.json contains duplicate ids");
  }
  if (value.total !== value.ids.length) {
    publicationError("index.json total does not match ids.length");
  }
  return value as unknown as CvesIndex;
}

function parseStats(value: unknown, index: CvesIndex): StatsData {
  if (!isRecord(value)) publicationError("stats.json must contain an object");
  if (value.generation_id !== index.generation_id) {
    publicationError("index.json and stats.json belong to different bundles");
  }
  if (value.generated_at !== index.generated_at) {
    publicationError("index.json and stats.json belong to different generations");
  }
  if (!isNonNegativeInteger(value.total_cves) || value.total_cves !== index.total) {
    publicationError("stats.json total_cves does not match index.json");
  }
  if (!isNonNegativeInteger(value.total_analyzed) || value.total_analyzed < index.total) {
    publicationError("stats.json total_analyzed is inconsistent");
  }
  if (
    !isNonNegativeInteger(value.with_fix_commits) ||
    value.with_fix_commits > value.total_analyzed
  ) {
    publicationError("stats.json with_fix_commits is inconsistent");
  }
  return value as unknown as StatsData;
}

function parseEntry(value: unknown, expectedId: string, generationId: string): CveEntry {
  if (!isRecord(value) || value.id !== expectedId) {
    publicationError(`${expectedId}.json has a filename/id mismatch`);
  }
  if (value.generation_id !== generationId) {
    publicationError(`${expectedId}.json belongs to a different bundle`);
  }
  return value as unknown as CveEntry;
}

function loadCves(index: CvesIndex, entries: unknown[]): CvesData {
  if (entries.length !== index.ids.length) {
    publicationError("canonical publication entries do not match index.json");
  }
  const cves = index.ids.map((id, offset) =>
    parseEntry(entries[offset], id, index.generation_id),
  );

  return {
    generation_id: index.generation_id,
    generated_at: index.generated_at,
    total: index.total,
    cves,
  };
}

const webRoot = path.resolve(/* turbopackIgnore: true */ process.cwd());
const publication = loadPublicationContract({
  dataDirectory: path.join(webRoot, "data"),
  requireReceipt: process.env.NODE_ENV === "production",
});
const index = parseIndex(publication.index);
const statsData = parseStats(publication.stats, index);
const inventoryData = publication.inventory as DetectorInventory | null;
const cvesData = loadCves(index, publication.entries);

export function getCves(): CvesData {
  return cvesData;
}

export function getStats(): StatsData {
  return statsData;
}

export function getDetectorInventory(): DetectorInventory | null {
  return inventoryData;
}

export function getDataGenerationId(): string {
  return index.generation_id;
}

export function getCveById(id: string): CveEntry | null {
  return cvesData.cves.find((cve) => cve.id === id) ?? null;
}
