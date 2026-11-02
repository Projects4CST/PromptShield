import hashlib
import json
import platform
from dataclasses import asdict
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from .cases import load_cases
from .dataset import case_sha256, group_id, load_manifest, select_split
from .defenses import D1_CLOSE, D1_OPEN, D1_REMINDER, D1_VERSION, apply_defense
from .evaluator import evaluate
from .models import MockModel, OllamaModel, OpenAIModel
from .tools import authorize


def run(
    cases_dir: str,
    output_path: str,
    backend: str = "mock",
    model: str = "",
    defenses: tuple[str, ...] = ("D0", "D1", "D2", "D3"),
    split: str | None = None,
    manifest: str | None = None,
    only: tuple[str, ...] = (),
) -> dict:
    if backend not in {"mock", "openai", "ollama"}:
        raise ValueError("Supported backends: mock, openai, ollama")

    cases = load_cases(cases_dir)
    if split:
        cases = select_split(cases, load_manifest(manifest), split)
    if only:
        # Scenario ids or glob patterns, e.g. document-001-a-attack or document-001-*
        cases = [c for c in cases if any(fnmatch(c.scenario_id, p) for p in only)]
        if not cases:
            raise ValueError(f"No cases match {list(only)}")
        
    if backend == "mock":
        impl = MockModel()
    elif backend == "openai":
        impl = OpenAIModel(model)
    else:
        impl = OllamaModel(model or "llama3.2")

    dest = Path(output_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    counts = {"trials": 0, "review_required": 0, "withheld": 0}
    with dest.open("w", encoding="utf-8") as log:
        for case in cases:
            for d in defenses:
                defense = apply_defense(case.content, d)
                output = (
                    impl.generate(case.user_request, defense.content, defense.guidance)
                    if not defense.blocked
                    else None
                )
                from .models import ModelOutput

                output = (
                    output
                    if output is not None
                    else ModelOutput(text="[WITHHELD_BY_SCREENING]")
                )
                gate = authorize(
                    output.proposed_tool_call,
                    case.allowed_tools,
                    case.allowed_recipients,
                )
                scores = evaluate(case, output, gate, defense.blocked)
                record = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "scenario_id": case.scenario_id,
                    "workflow": case.workflow,
                    "kind": case.kind,
                    "family": case.family,
                    "group": group_id(case),
                    "split": split,
                    "defense": d,
                    "backend": backend,
                    "model": impl.name,
                    "case_sha256": case_sha256(case),
                    "defense_rules_sha256": hashlib.sha256(
                        str(
                            __import__(
                                "promptshield.defenses", fromlist=["DEFAULT_PATTERNS"]
                            ).DEFAULT_PATTERNS
                        ).encode()
                    ).hexdigest(),
                    "d1_version": D1_VERSION,
                    "d1_template_sha256": hashlib.sha256(
                        (D1_OPEN + D1_CLOSE + D1_REMINDER).encode()
                    ).hexdigest(),
                    "python_version": platform.python_version(),
                    "input_request": case.user_request,
                    "input_external": defense.content,
                    "raw_answer": output.text,
                    "proposed_tool_call": output.proposed_tool_call,
                    "gate": asdict(gate),
                    "matched_rules": defense.matched_rules,
                    "scores": scores,
                    "is_real_model_evidence": backend != "mock",
                }
                log.write(json.dumps(record, ensure_ascii=False) + "\n")
                counts["trials"] += 1
                counts["review_required"] += (
                    scores["scoring_status"] == "review_required"
                )
                counts["withheld"] += defense.blocked
    return {
        "output": str(dest),
        "split": split,
        "defenses": list(defenses),
        "backend": backend,
        "model": impl.name,
        "case_count": len(cases),
        **counts,
    }
