export const RESEARCH_SNAPSHOT = {
  unionUniqueGhsa: 168,
  allPass: 94,
  scopedContribution: 74,
  strictReleasedGhsa: 94,
  replayedOn: "2026-08-15",
  ledger: "canonical94",
  ledgerSha256:
    "7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096",
  summarySha256:
    "c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b",
  status: "HOLD",
  publicationReady: false,
} as const;

export const CONTRIBUTION_CLASSES = [
  {
    title: "Direct introduction",
    description: "AI-authored code creates the vulnerable mechanism.",
  },
  {
    title: "Causal contribution",
    description:
      "An AI change adds the surface or prerequisite that makes the flaw reachable.",
  },
  {
    title: "Incomplete remediation",
    description:
      "An AI security fix leaves the same released mechanism exploitable.",
  },
] as const;

export const ADMISSION_GATES = [
  ["01", "Identity", "The advisory, repository, package, and mechanism agree."],
  [
    "02",
    "AI hunk",
    "AI provenance binds to the exact atomic member and mechanism-changing hunk; carrier metadata never transfers.",
  ],
  [
    "03",
    "Topology",
    "Candidate, parent, landing carrier, and minimum-fix edge are reconstructed without Cartesian pairing.",
  ],
  [
    "04",
    "Causality",
    "The candidate delta is necessary or materially contributes to the flaw; unchanged preservation fails.",
  ],
  [
    "05",
    "Reversal",
    "The minimum fix set reverses the same mechanism; a related security patch is not enough.",
  ],
  [
    "06",
    "Release",
    "An affected artifact contains the candidate or carrier without the fix; a fixed artifact contains the fix.",
  ],
  [
    "07",
    "Uniqueness",
    "Advisory aliases and repeated mechanisms count once; distinct mechanisms remain separate.",
  ],
] as const;

export const WORKFLOW_STEPS = [
  [
    "01",
    "Advisory recall",
    "Official advisories and fix references route candidates.",
  ],
  [
    "02",
    "Atomic lineage",
    "Parent, candidate, carrier, and minimum fix are reconstructed.",
  ],
  [
    "03",
    "Mechanism replay",
    "The exact source, guard, sink, and impact are compared across Git history.",
  ],
  [
    "04",
    "Seven-gate review",
    "Identity, authorship, causality, reversal, release, and uniqueness must close.",
  ],
  [
    "05",
    "Publication boundary",
    "HOLD and UNKNOWN remain in research; aliases and duplicates are noncounting; commit-only causal rows stay outside released claims.",
  ],
] as const;
