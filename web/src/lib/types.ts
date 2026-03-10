export interface AiSignalEntry {
  readonly tool: string;
  readonly signal_type: string;
  readonly matched_text: string;
  readonly confidence: number;
}

export interface LlmVerdict {
  readonly verdict: "CONFIRMED" | "UNLIKELY" | "UNRELATED";
  readonly reasoning: string;
  readonly model: string;
  readonly vuln_type?: string;
  readonly vuln_description?: string;
  readonly vulnerable_pattern?: string;
  readonly causal_chain?: string;
}

export interface AgentVerdict {
  readonly model: string;
  readonly verdict: string;
  readonly reasoning: string;
  readonly confidence: number;
  readonly tool_calls_made: number;
  readonly evidence: readonly string[];
}

export interface TribunalVerdict {
  readonly verdict: string;
  readonly confidence: string;
  readonly models: readonly string[];
  readonly agent_verdicts?: readonly AgentVerdict[];
}

export interface BugCommit {
  readonly sha: string;
  readonly author: string;
  readonly date: string;
  readonly message: string;
  readonly ai_signals: readonly AiSignalEntry[];
  readonly blamed_file: string;
  readonly blame_confidence: number;
  readonly llm_verdict: LlmVerdict | null;
  readonly tribunal_verdict?: TribunalVerdict;
  readonly pr_url?: string;
  readonly pr_title?: string;
}

export interface FixCommit {
  readonly sha: string;
  readonly repo_url: string;
  readonly source: string;
}

export interface CveEntry {
  readonly id: string;
  readonly description: string;
  readonly severity: string;
  readonly cvss: number | null;
  readonly cwes: readonly string[];
  readonly ecosystem: string;
  readonly published: string;
  readonly ai_tools: readonly string[];
  readonly languages: readonly string[];
  readonly confidence: number;
  readonly verified_by: string;
  readonly how_introduced: string;
  readonly bug_commits: readonly BugCommit[];
  readonly fix_commits: readonly FixCommit[];
  readonly references: readonly string[];
}

export interface CvesData {
  readonly generated_at: string;
  readonly total: number;
  readonly cves: readonly CveEntry[];
}

export interface StatsData {
  readonly generated_at: string;
  readonly total_cves: number;
  readonly total_analyzed: number;
  readonly coverage_from: string;
  readonly coverage_to: string;
  readonly by_tool: Readonly<Record<string, number>>;
  readonly by_severity: Readonly<Record<string, number>>;
  readonly by_language: Readonly<Record<string, number>>;
  readonly by_repo: Readonly<Record<string, number>>;
  readonly by_month: readonly {
    readonly month: string;
    readonly count: number;
    readonly by_tool: Readonly<Record<string, number>>;
  }[];
}
