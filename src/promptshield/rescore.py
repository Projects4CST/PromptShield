"""Re-score existing trace logs with the current reply parser, without calling the model.

Why this is possible: the old parser (parse-v1) only understood a reply that was bare
JSON. When it failed (e.g. JSON inside a ```json fence) it logged the *whole* reply as
`raw_answer`, so nothing was lost. When it succeeded, its result was already correct and
the call is in `proposed_tool_call`. So re-parsing `raw_answer` with the current parser,
then re-running the D4 gate and the evaluator, gives the scores the fixed code would have
produced on exactly the same model replies.

Usage:
    python -m promptshield.rescore runs/heldout.jsonl runs/heldout-rescored.jsonl
    promptshield report --input runs/heldout-rescored.jsonl

Every record keeps its original answer, tool call, gate decision and scores under
`rescore.original` for audit. Trials withheld by D2 (model never called) are re-evaluated
unchanged. The input file is never modified.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .cases import load_cases
from .dataset import case_sha256
from .evaluator import evaluate
from .models import PARSER_VERSION, ModelOutput, _parse_output
from .tools import authorize

# trace field -> GateDecision attribute (same mapping as runner.py)
_GATE_FIELDS = {
    "policy_id": "policy_id",
    "policy_hash": "policy_hash",
    "gate_mode": "gate_mode",
    "gate_reason": "reason",
    "gate_enforced": "gate_enforced",
    "simulated_execution_status": "simulated_execution_status",
}


def _status(scores: dict) -> str:
    if scores.get("attack_success") is True:
        return "success"
    if scores.get("attack_success") is False:
        return "fail"
    return scores.get("scoring_status") or "unscored"


def _rescore_record(record: dict, case) -> dict:
    blocked = bool(record.get("d2_abstained"))
    error = record.get("d2_error")
    raw = record.get("raw_answer") or ""
    old_call = record.get("proposed_tool_call")

    if blocked or old_call:
        # Withheld (no model reply) or v1 already parsed a bare-JSON call correctly.
        output = ModelOutput(text=raw, proposed_tool_call=old_call)
    else:
        output = _parse_output(raw)

    gate = authorize(output.proposed_tool_call, case.allowed_tools, case.allowed_recipients)
    scores = evaluate(case, output, gate, blocked, error)

    new = dict(record)
    new["raw_answer"] = output.text
    new["proposed_tool_call"] = output.proposed_tool_call
    new["gate"] = asdict(gate)
    for field, attr in _GATE_FIELDS.items():
        new[field] = getattr(gate, attr)
    new["gate_decision"] = (
        None if not gate.attempted else ("allow" if gate.authorized else "deny")
    )
    new["scores"] = scores
    new["parser_version"] = PARSER_VERSION
    new["rescore"] = {
        "rescored_at": datetime.now(timezone.utc).isoformat(),
        "from_parser_version": record.get("parser_version", "parse-v1"),
        "changed": (
            output.proposed_tool_call != old_call
            or output.text != raw
            or scores != record.get("scores")
        ),
        "original": {
            "raw_answer": raw,
            "proposed_tool_call": old_call,
            "gate": record.get("gate"),
            "gate_decision": record.get("gate_decision"),
            "scores": record.get("scores"),
        },
    }
    return new


def rescore(input_path: str | Path, output_path: str | Path, cases_dir: str | Path = "scenarios") -> dict:
    src, dest = Path(input_path), Path(output_path)
    if src.resolve() == dest.resolve():
        raise ValueError("output must differ from input; the original log is kept unchanged")

    cases = {c.scenario_id: c for c in load_cases(cases_dir)}
    rows = [json.loads(line) for line in src.read_text(encoding="utf-8").splitlines() if line.strip()]

    problems = []
    for r in rows:
        case = cases.get(r.get("scenario_id"))
        if case is None:
            problems.append(f"{r.get('scenario_id')}: not in {cases_dir}")
        elif r.get("case_sha256") and r["case_sha256"] != case_sha256(case):
            problems.append(f"{r['scenario_id']}: case changed since the run (sha256 mismatch)")
    if problems:
        raise ValueError("cannot rescore safely:\n  " + "\n  ".join(sorted(set(problems))))

    out_rows = [_rescore_record(r, cases[r["scenario_id"]]) for r in rows]

    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("w", encoding="utf-8") as fh:
        for r in out_rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    transitions = Counter()
    for old, new in zip(rows, out_rows):
        if new["kind"] == "attacked":
            a, b = _status(old.get("scores") or {}), _status(new["scores"])
            if a != b:
                transitions[f"{new['defense']} {a} -> {b}"] += 1

    return {
        "input": str(src),
        "output": str(dest),
        "parser_version": PARSER_VERSION,
        "trials": len(out_rows),
        "changed_records": sum(1 for r in out_rows if r["rescore"]["changed"]),
        "tool_calls_before": sum(1 for r in rows if r.get("proposed_tool_call")),
        "tool_calls_after": sum(1 for r in out_rows if r["proposed_tool_call"]),
        "attacked_status_changes": dict(sorted(transitions.items())),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="python -m promptshield.rescore",
        description="Re-score a trace log with the current reply parser (no model calls).",
    )
    p.add_argument("input", help="existing trace log, e.g. runs/heldout.jsonl")
    p.add_argument("output", help="new log to write, e.g. runs/heldout-rescored.jsonl")
    p.add_argument("--cases", default="scenarios", help="scenario directory (default: scenarios)")
    args = p.parse_args(argv)
    try:
        result = rescore(args.input, args.output, args.cases)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
