#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

MODEL="${DEMO_MODEL:-gemma3:latest}"

echo "== validate =="
promptshield validate --cases scenarios
promptshield inventory --cases scenarios

echo""
echo "== D2 check =="
python -m promptshield.d2_dev_check scenarios

echo""
echo "== D4 gate demo call =="
python -m promptshield.d4_demo

echo""
echo "== run demo cases (D0–D3, $MODEL) =="
promptshield run \
  --cases scenarios \
  --case "document-001-b-*" \
  --backend ollama \
  --model "$MODEL" \
  --defenses D0,D1,D2,D3 \
  --output runs/demo.jsonl

echo""
echo "== report =="
promptshield report --input runs/demo.jsonl

echo""
echo "== sample trace =="
python - << 'PY'
import json
for line in open("runs/demo.jsonl"):
    r = json.loads(line)
    print(r.get("scenario_id"), r.get("defense"),
          "rules=", r.get("d2_matched_rule_id") or r.get("matched_rules"),
          "gate=", r.get("gate_decision"),
          "withheld=", (r.get("scores") or {}).get("withheld"),
          "asr=", (r.get("scores") or {}).get("attack_success"))
PY

echo "Done → runs/demo.jsonl"