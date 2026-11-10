"""Run D2 rules over the DEV split only; report abstentions per kind. Never touches heldout.
Usage: python scripts/d2_dev_check.py scenarios"""
import sys
from collections import Counter
from promptshield.cases import load_cases
from promptshield.dataset import load_manifest, select_split
from promptshield.defenses import apply_defense

root = sys.argv[1] if len(sys.argv) > 1 else "scenarios"
dev = select_split(load_cases(root), load_manifest(f"{root}/manifest.json"), "dev")
hit, tot = Counter(), Counter()
for c in dev:
    r = apply_defense(c.content, "D2")
    tot[c.kind] += 1
    if r.blocked:
        hit[c.kind] += 1
        print(f"WITHHELD {c.scenario_id:<26} {c.kind:<14} {','.join(r.rule_ids)}")
    elif c.kind == "attacked":
        print(f"MISSED   {c.scenario_id:<26} {c.family}")
print()
for k in sorted(tot):
    print(f"{k:<14} withheld {hit[k]}/{tot[k]}")
