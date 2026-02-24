import type { CvesData, StatsData, CveEntry } from "./types";
import cvesJson from "../../data/cves.json";
import statsJson from "../../data/stats.json";

export function getCves(): CvesData {
  return cvesJson as CvesData;
}

export function getStats(): StatsData {
  return statsJson as StatsData;
}

export function getCveById(id: string): CveEntry | null {
  const data = getCves();
  return data.cves.find((cve) => cve.id === id) ?? null;
}
