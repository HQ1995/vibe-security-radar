export const RESEARCH_SNAPSHOT = {
  ledger: "tp-funnel",
  status: "PUBLISHED",
  publicationReady: true,
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
  {
    title: "Flawed AI-written code",
    description:
      "AI-written code was flawed, including copied vulnerable logic.",
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
    "Only confirmed true positives are published. NOT_AI, BLOCKED, and incomplete causal rows stay in the research ledger.",
  ],
] as const;
