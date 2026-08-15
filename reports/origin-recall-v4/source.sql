-- Canonical report-row materialization for the v4 final result.
-- Source JSON: archives/legacy-web-data-campaign/heldout_studies/prospective-origin-heldout-20260803-v4-final/result.json
-- Source JSON SHA-256: f3ec4ccf614c61c2e397ab811e1eaf38a3d44eb68d169849cd0872da18c56f48
-- Engine: SQLite 3 with JSON1.
WITH report_rows(dataset_name, row_order, row_json) AS (
  VALUES
    ('headline', 1, json_object(
      'selected_case_count', 12,
      'root_resolved_case_count', 3,
      'root_resolution_rate', 0.25,
      'observed_ai_causal_case_count', 0,
      'conditional_recall_denominator', 0,
      'old_top10_causal_edge_count', 0,
      'old_top10_reviewed_edge_count', 34,
      'local_ancestry_retention', 1.0,
      'local_ancestor_pairs_retained', 45133
    )),
    ('workload_stages', 1, json_object(
      'stage', 'Old direct AI-only',
      'exact_edges', 550,
      'review_units', 0,
      'ancestor_pairs_excluded', 44583,
      'membership', 'observed AI attribution required',
      'relation_closed', json('false')
    )),
    ('workload_stages', 2, json_object(
      'stage', 'Old plus squash',
      'exact_edges', 8449,
      'review_units', 4542,
      'ancestor_pairs_excluded', 44583,
      'membership', 'observed AI attribution required',
      'relation_closed', json('true')
    )),
    ('workload_stages', 3, json_object(
      'stage', 'Repaired ancestry',
      'exact_edges', 45133,
      'review_units', 22912,
      'ancestor_pairs_excluded', 0,
      'membership', 'all local pre-fix ancestors',
      'relation_closed', json('false')
    )),
    ('workload_stages', 4, json_object(
      'stage', 'Repaired plus squash',
      'exact_edges', 50862,
      'review_units', 26057,
      'ancestor_pairs_excluded', 0,
      'membership', 'all local pre-fix ancestors',
      'relation_closed', json('true')
    )),
    ('case_review', 1, json_object(
      'advisory', 'CVE-2026-21531',
      'repository', 'Azure SDK for Python',
      'fixes', 2,
      'old_top10_edges', 20,
      'noncausal_edges', 20,
      'consensus_causal_history_commits', 3,
      'observed_ai_causal_commits', 0
    )),
    ('case_review', 2, json_object(
      'advisory', 'CVE-2024-41254',
      'repository', 'Litestream',
      'fixes', 1,
      'old_top10_edges', 10,
      'noncausal_edges', 10,
      'consensus_causal_history_commits', 1,
      'observed_ai_causal_commits', 0
    )),
    ('case_review', 3, json_object(
      'advisory', 'CVE-2025-68952',
      'repository', 'Eigent',
      'fixes', 2,
      'old_top10_edges', 4,
      'noncausal_edges', 4,
      'consensus_causal_history_commits', 5,
      'observed_ai_causal_commits', 0
    )),
    ('budget_recall', 1, json_object('budget_label', 'B=1', 'budget_per_fix', 1, 'review_units', 4, 'control_edges_recovered', 2, 'control_edge_denominator', 14, 'control_edge_recall', 0.14285714285714285)),
    ('budget_recall', 2, json_object('budget_label', 'B=5', 'budget_per_fix', 5, 'review_units', 21, 'control_edges_recovered', 7, 'control_edge_denominator', 14, 'control_edge_recall', 0.5)),
    ('budget_recall', 3, json_object('budget_label', 'B=10', 'budget_per_fix', 10, 'review_units', 39, 'control_edges_recovered', 9, 'control_edge_denominator', 14, 'control_edge_recall', 0.6428571428571429)),
    ('budget_recall', 4, json_object('budget_label', 'B=25', 'budget_per_fix', 25, 'review_units', 85, 'control_edges_recovered', 11, 'control_edge_denominator', 14, 'control_edge_recall', 0.7857142857142857)),
    ('budget_recall', 5, json_object('budget_label', 'B=50', 'budget_per_fix', 50, 'review_units', 166, 'control_edges_recovered', 11, 'control_edge_denominator', 14, 'control_edge_recall', 0.7857142857142857)),
    ('budget_recall', 6, json_object('budget_label', 'B=100', 'budget_per_fix', 100, 'review_units', 327, 'control_edges_recovered', 11, 'control_edge_denominator', 14, 'control_edge_recall', 0.7857142857142857)),
    ('budget_recall', 7, json_object('budget_label', 'B=200', 'budget_per_fix', 200, 'review_units', 643, 'control_edges_recovered', 12, 'control_edge_denominator', 14, 'control_edge_recall', 0.8571428571428571)),
    ('budget_recall', 8, json_object('budget_label', 'B=500', 'budget_per_fix', 500, 'review_units', 1595, 'control_edges_recovered', 12, 'control_edge_denominator', 14, 'control_edge_recall', 0.8571428571428571)),
    ('budget_recall', 9, json_object('budget_label', 'B=1k', 'budget_per_fix', 1000, 'review_units', 2425, 'control_edges_recovered', 12, 'control_edge_denominator', 14, 'control_edge_recall', 0.8571428571428571)),
    ('budget_recall', 10, json_object('budget_label', 'B=5k', 'budget_per_fix', 5000, 'review_units', 6757, 'control_edges_recovered', 14, 'control_edge_denominator', 14, 'control_edge_recall', 1.0)),
    ('budget_cost', 1, json_object('budget_label', 'B=10', 'review_units', 39, 'control_edge_recall', 0.6428571428571429, 'luna_cost', 0.031523, 'deepseek_cost', 0.056244, 'grok_cost', 0.208747)),
    ('budget_cost', 2, json_object('budget_label', 'B=25', 'review_units', 85, 'control_edge_recall', 0.7857142857142857, 'luna_cost', 0.068704, 'deepseek_cost', 0.122582, 'grok_cost', 0.454962)),
    ('budget_cost', 3, json_object('budget_label', 'B=100', 'review_units', 327, 'control_edge_recall', 0.7857142857142857, 'luna_cost', 0.264308, 'deepseek_cost', 0.471581, 'grok_cost', 1.750265)),
    ('budget_cost', 4, json_object('budget_label', 'B=1,000', 'review_units', 2425, 'control_edge_recall', 0.8571428571428571, 'luna_cost', 1.960084, 'deepseek_cost', 3.497202, 'grok_cost', 12.979796)),
    ('budget_cost', 5, json_object('budget_label', 'B=5,000', 'review_units', 6757, 'control_edge_recall', 1.0, 'luna_cost', 5.461561, 'deepseek_cost', 9.744574, 'grok_cost', 36.166795)),
    ('budget_cost', 6, json_object('budget_label', 'Full schedule', 'review_units', 26057, 'control_edge_recall', 1.0, 'luna_cost', 21.061404, 'deepseek_cost', 37.577972, 'grok_cost', 139.46991))
)
SELECT dataset_name, row_order, row_json
FROM report_rows
ORDER BY dataset_name, row_order;
