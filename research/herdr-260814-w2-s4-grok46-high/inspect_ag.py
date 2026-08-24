import json, hashlib, os, re, subprocess, glob, textwrap, datetime from pathlib import Path

OWNED = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-w2-s4-grok46-high")
ROOT = Path("/home/hanqing/agents/ai-slop")
SLICE = ROOT / "autoresearch/orchestrator-260814-ghsa200-canvas/wave2/ag-slice-1.jsonl"
CONTRACT = ROOT / "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md"
SPECS = ROOT / "autoresearch/orchestrator-260814-ghsa200-canvas/wave2/SPEC.md"
CONES = Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones")
AD = Path("/home/hanqing/.cache/ghsa200-worker-clones/freshness-qa/advisory-database")
PRINT("ok")
