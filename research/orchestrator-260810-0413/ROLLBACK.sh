#!/bin/sh
set -eu
run=${1:-autoresearch/orchestrator-260810-0413}
for name in enrichment-overlay.jsonl summary.json; do
    if [ -f "$run/$name" ]; then
        mv "$run/$name" "$run/$name.rolled-back"
    fi
done
echo rollback_status=RESTORED
