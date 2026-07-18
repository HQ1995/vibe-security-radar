import fs from "node:fs";
import path from "node:path";
import type { CveEntry, CvesData, CvesIndex, StatsData } from "./types";
import indexJson from "../../data/index.json";
import statsJson from "../../data/stats.json";

// Build-time/server-only module: every page is statically generated, and
// no client component imports this file.
//
// The published data lives in the per-CVE layout (see
// scripts/web_data/writer.py for the rationale):
//   web/data/index.json      manifest — generated_at, total, ordered ids
//   web/data/cves/<ID>.json  one CveEntry per file
//   web/data/stats.json      aggregate statistics
// The manifest is imported statically; the per-CVE files are read from
// disk once at build time and assembled into the same CvesData shape the
// old monolithic cves.json provided. The Python generator validates every
// file against scripts/web_data/schema.py before writing, so the casts
// below are the sanctioned trust boundary (enforced by release-gate tests
// in scripts/tests/test_web_data_schema.py).
const index: CvesIndex = indexJson;

function loadCves(): CvesData {
  const cvesDir = path.join(process.cwd(), "data", "cves");
  const cves = index.ids.map(
    (id) =>
      JSON.parse(
        fs.readFileSync(path.join(cvesDir, `${id}.json`), "utf-8"),
      ) as CveEntry,
  );
  return { generated_at: index.generated_at, total: index.total, cves };
}

const cvesData: CvesData = loadCves();
// stats.json's heterogeneous by_month literal type doesn't unify with the
// Record<string, number> maps, hence the double cast (boundary validated
// by the schema release gates, see note above).
const statsData = statsJson as unknown as StatsData;

export function getCves(): CvesData {
  return cvesData;
}

export function getStats(): StatsData {
  return statsData;
}

export function getCveById(id: string): CveEntry | null {
  return cvesData.cves.find((cve) => cve.id === id) ?? null;
}
