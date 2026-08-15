#!/usr/bin/env node

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
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join, relative, resolve } from "node:path";
import { TextDecoder } from "node:util";

import { loadPublicationContract } from "./publication-contract.mjs";

const VULNERABILITY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const GENERATION_MARKER = /data-publication-generation="([^"]+)"/g;
const UTF8 = new TextDecoder("utf-8", { fatal: true });
const MAX_STATIC_HTML_BYTES = 16 * 1024 * 1024;
const MAX_STATIC_HTML_TOTAL_BYTES = 512 * 1024 * 1024;

function statSignature(stat) {
  return [stat.dev, stat.ino, stat.mode, stat.size, stat.mtimeNs, stat.ctimeNs].join(":");
}

function boundedStaticLimit(value, ceiling, label) {
  if (value === undefined) return ceiling;
  if (!Number.isSafeInteger(value) || value <= 0 || value > ceiling) {
    throw new Error(`${label} must be a positive safe integer at most ${ceiling}`);
  }
  return value;
}

function readStableStaticHtml(path, maxBytes) {
  const noFollow = fsConstants.O_NOFOLLOW ?? 0;
  let descriptor;
  try {
    descriptor = openSync(path, fsConstants.O_RDONLY | noFollow);
  } catch (error) {
    throw new Error(
      `cannot open static HTML ${path}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  try {
    const before = fstatSync(descriptor, { bigint: true });
    if ((before.mode & BigInt(fsConstants.S_IFMT)) !== BigInt(fsConstants.S_IFREG)) {
      throw new Error(`static HTML is not a regular file: ${path}`);
    }
    if (before.size > BigInt(maxBytes)) {
      throw new Error(`static HTML exceeds the ${maxBytes}-byte size bound: ${path}`);
    }
    const chunks = [];
    let bytesRead = 0;
    while (true) {
      const chunk = Buffer.allocUnsafe(Math.min(1024 * 1024, maxBytes + 1 - bytesRead));
      const count = readSync(descriptor, chunk, 0, chunk.length, null);
      if (count === 0) break;
      bytesRead += count;
      if (bytesRead > maxBytes) {
        throw new Error(`static HTML exceeds the ${maxBytes}-byte size bound: ${path}`);
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
      throw new Error(`static HTML changed while being read: ${path}`);
    }
    try {
      return { bytes: contents.length, html: UTF8.decode(contents) };
    } catch (error) {
      throw new Error(
        `static HTML is not valid UTF-8 ${path}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  } finally {
    closeSync(descriptor);
  }
}

function sortedDifference(left, right) {
  return [...left].filter((value) => !right.has(value)).sort();
}

function defaultEvidenceRoot(repositoryRoot) {
  return join(
    repositoryRoot,
    ".ai-slop",
    "state",
    "data-refresh",
    "release-evidence-v1",
  );
}

function runPythonReleaseValidator({
  repositoryRoot,
  dataDirectory,
  evidenceRoot,
  requireFormalEvidence,
  trustedRepositoryRoot,
}) {
  const argumentsList = [
    "run",
    "--project",
    "cve-analyzer",
    "python",
    "-B",
    "scripts/verify_formal_release.py",
    "--data-dir",
    dataDirectory,
    "--json",
  ];
  const verifyActive = requireFormalEvidence || existsSync(evidenceRoot);
  if (verifyActive) {
    argumentsList.push("--evidence-root", evidenceRoot, "--require-active");
  }
  if (trustedRepositoryRoot) {
    argumentsList.push("--trusted-repo-root", trustedRepositoryRoot);
  }
  const result = spawnSync("uv", argumentsList, {
    cwd: repositoryRoot,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    timeout: 120_000,
  });
  if (result.error) {
    throw new Error(`formal Python release validator could not run: ${result.error.message}`);
  }
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout || `exit ${result.status}`).trim();
    throw new Error(`formal Python release validator rejected the publication: ${detail}`);
  }
  let summary;
  try {
    summary = JSON.parse(result.stdout);
  } catch (error) {
    throw new Error(
      `formal Python release validator returned invalid JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (summary.ok !== true || (requireFormalEvidence && summary.active_release_verified !== true)) {
    throw new Error("formal Python release validator returned an incomplete proof");
  }
  return summary;
}

function collectStaticHtml(appDirectory) {
  const pages = [];
  function visit(directory) {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        throw new Error(`static app output contains a symlink: ${path}`);
      }
      if (entry.isDirectory()) {
        visit(path);
      } else if (entry.isFile() && entry.name.endsWith(".html")) {
        pages.push(path);
      }
    }
  }
  visit(appDirectory);
  return pages.sort();
}

function pageGenerationMarkers(html) {
  return [...html.matchAll(GENERATION_MARKER)].map((match) => match[1]);
}

/**
 * @param {{
 *   dataDirectory?: string,
 *   indexPath?: string,
 *   appDirectory: string,
 *   evidenceRoot?: string,
 *   requireFormalEvidence?: boolean,
 *   runPythonValidation?: boolean,
 *   repositoryRoot?: string,
 *   trustedRepositoryRoot?: string,
 *   staticLimits?: { pageBytes?: number, totalBytes?: number },
 * }} options
 */
export function verifyStaticRelease(options) {
  const {
    dataDirectory,
    indexPath,
    appDirectory,
    evidenceRoot,
    requireFormalEvidence = false,
    runPythonValidation = true,
    repositoryRoot,
    trustedRepositoryRoot,
    staticLimits = {},
  } = options;
  const resolvedDataDirectory = resolve(dataDirectory ?? dirname(indexPath));
  const resolvedRepositoryRoot = resolve(
    repositoryRoot ?? join(resolvedDataDirectory, "..", ".."),
  );
  const resolvedEvidenceRoot = resolve(
    evidenceRoot ?? defaultEvidenceRoot(resolvedRepositoryRoot),
  );
  const publication = loadPublicationContract({
    dataDirectory: resolvedDataDirectory,
    requireReceipt: true,
  });

  if (requireFormalEvidence && !runPythonValidation) {
    throw new Error("formal activation/evidence verification requires the Python validator");
  }
  let pythonSummary = null;
  if (runPythonValidation) {
    pythonSummary = runPythonReleaseValidator({
      repositoryRoot: resolvedRepositoryRoot,
      dataDirectory: resolvedDataDirectory,
      evidenceRoot: resolvedEvidenceRoot,
      requireFormalEvidence,
      trustedRepositoryRoot,
    });
    const expected = {
      generation_id: publication.index.generation_id,
      publication_bundle_sha256: publication.receipt.publication_bundle_sha256,
      publication_manifest_sha256: publication.manifestSha256,
      release_receipt_sha256: publication.receiptSha256,
      raw_file_count: publication.manifest.length,
    };
    for (const [field, value] of Object.entries(expected)) {
      if (pythonSummary[field] !== value) {
        throw new Error(`Python/JavaScript release contract mismatch for ${field}`);
      }
    }
  }

  const expected = new Set(publication.index.ids);
  const detailDirectory = join(appDirectory, "cves");
  const actual = new Set(
    readdirSync(detailDirectory, { withFileTypes: true })
      .filter((entry) => entry.isFile() && entry.name.endsWith(".html"))
      .map((entry) => entry.name.slice(0, -".html".length))
      .filter((id) => VULNERABILITY_ID.test(id)),
  );
  const missing = sortedDifference(expected, actual);
  const stale = sortedDifference(actual, expected);
  if (missing.length || stale.length) {
    throw new Error(
      `static CVE release mismatch; missing=${JSON.stringify(missing)} stale=${JSON.stringify(stale)}`,
    );
  }

  const pageLimit = boundedStaticLimit(
    staticLimits.pageBytes,
    MAX_STATIC_HTML_BYTES,
    "static HTML page limit",
  );
  const totalLimit = boundedStaticLimit(
    staticLimits.totalBytes,
    MAX_STATIC_HTML_TOTAL_BYTES,
    "static HTML total limit",
  );
  let totalHtmlBytes = 0;
  const pageContents = new Map();
  for (const page of collectStaticHtml(appDirectory)) {
    const artifact = readStableStaticHtml(page, pageLimit);
    totalHtmlBytes += artifact.bytes;
    if (totalHtmlBytes > totalLimit) {
      throw new Error(`static HTML exceeds the ${totalLimit}-byte aggregate size bound`);
    }
    pageContents.set(page, artifact.html);
  }
  const pages = [...pageContents.keys()].filter(
    (page) => relative(appDirectory, page) !== "_global-error.html",
  );
  if (pages.length === 0) {
    throw new Error(`static app output contains no verifiable HTML pages: ${appDirectory}`);
  }
  const wrongGeneration = pages
    .filter((page) => {
      const markers = pageGenerationMarkers(pageContents.get(page));
      return markers.length !== 1 || markers[0] !== publication.index.generation_id;
    })
    .map((page) => relative(appDirectory, page))
    .sort();
  if (wrongGeneration.length) {
    throw new Error(
      `static app pages do not match publication generation ${publication.index.generation_id}; pages=${JSON.stringify(wrongGeneration)}`,
    );
  }
  return {
    total: expected.size,
    generation_id: publication.index.generation_id,
    publication_bundle_sha256: publication.receipt.publication_bundle_sha256,
    publication_manifest_sha256: publication.manifestSha256,
    formal_evidence_verified: pythonSummary?.active_release_verified === true,
  };
}

const scriptPath = fileURLToPath(import.meta.url);
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const webRoot = dirname(dirname(scriptPath));
  const requireFormalEvidence = process.argv.slice(2).includes("--require-formal-evidence");
  const result = verifyStaticRelease({
    dataDirectory: join(webRoot, "data"),
    appDirectory: join(webRoot, ".next", "server", "app"),
    requireFormalEvidence,
  });
  const trustBoundary = result.formal_evidence_verified
    ? "local active activation and archived evidence verified"
    : "tracked receipt is the Git/CI release authority; local activation evidence absent";
  process.stdout.write(
    `Verified ${result.total} static CVE pages, canonical publication hashes, schema-4 release receipt with end-to-end recall binding and schema-3 source cutoff, and raw file manifest (${trustBoundary}).\n`,
  );
}
