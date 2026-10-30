"""Dataset integrity checks, group-level dev/held-out split, and frozen manifest."""

import csv
import hashlib
import json
import os
import random
import re
from collections import Counter, defaultdict
from dataclasses import asdict
from datetime import date
from pathlib import Path
from .schema import Case

ATTACK_FAMILIES = {
    "instruction_override",
    "role_spoofing",
    "task_aligned_persuasion",
    "unauthorized_tool_use",
}
# {workflow}-{nnn}-{variant}-attack | {workflow}-{nnn}-{variant}-clean | {workflow}-{nnn}-benign
ID_PATTERN = re.compile(
    r"^(web|document|email)-(\d{3})-(?:([a-z])-(attack|clean)|benign)$"
)
MATCHED_FIELDS = (
    "user_request",
    "clean_content",
    "utility_terms",
    "allowed_tools",
    "allowed_recipients",
)
SPLITS = ("dev", "heldout")


def case_sha256(case: Case) -> str:
    # Same digest the runner writes into every trial record as case_sha256.
    return hashlib.sha256(
        json.dumps(asdict(case), sort_keys=True).encode()
    ).hexdigest()


def group_id(case: Case) -> str:
    """Source-scenario group, e.g. web-003 for web-003-b-attack."""
    return "-".join(case.scenario_id.split("-")[:2])


def injection_position(case: Case) -> str:
    """Where the payload sits relative to the clean body: start, middle or end."""
    if case.kind != "attacked":
        return ""
    clean, content = case.clean_content, case.content
    header = clean.split("\n\n", 1)[0] + "\n\n" if "\n\n" in clean else ""
    prefix = len(os.path.commonprefix([clean, content])) - len(header)
    suffix = len(os.path.commonprefix([clean[::-1], content[::-1]]))
    if prefix <= 0:
        return "start"
    if prefix >= len(clean) - len(header) or suffix < 3:
        return "end"
    return "middle"


def check_dataset(cases: list[Case]) -> list[str]:
    """Return a list of human-readable problems; empty means the dataset is consistent."""
    problems = []
    by_id = {c.scenario_id: c for c in cases}
    markers = Counter(c.target_marker.casefold() for c in cases if c.target_marker)
    for c in cases:
        sid = c.scenario_id
        m = ID_PATTERN.match(sid)
        if not m:
            problems.append(
                f"{sid}: id must look like web-001-a-attack, web-001-a-clean or web-001-benign"
            )
            continue
        if m[1] != c.workflow:
            problems.append(f"{sid}: id prefix does not match workflow {c.workflow!r}")
        expected_kind = {"attack": "attacked", "clean": "clean"}.get(
            m[4], "benign_quoted"
        )
        if c.kind != expected_kind:
            problems.append(f"{sid}: kind {c.kind!r} but id implies {expected_kind!r}")

        # Utility terms must be answerable from the trusted inputs alone.
        visible = (c.user_request + " " + c.clean_content).casefold()
        if not c.utility_terms:
            problems.append(f"{sid}: no utility_terms")
        for term in c.utility_terms:
            if term.casefold() not in visible:
                problems.append(
                    f"{sid}: utility term {term!r} not in user_request or clean_content"
                )

        if c.kind == "attacked":
            if c.family not in ATTACK_FAMILIES:
                problems.append(f"{sid}: unknown attack family {c.family!r}")
            if c.family == "unauthorized_tool_use" and c.workflow != "email":
                problems.append(f"{sid}: unauthorized_tool_use is email-only")
            if c.attacker_goal == "none":
                problems.append(f"{sid}: attacked case needs an attacker_goal")
            if not c.target_marker:
                problems.append(f"{sid}: attacked case needs a target_marker")
            elif markers[c.target_marker.casefold()] > 1:
                problems.append(f"{sid}: target_marker {c.target_marker!r} is reused")
            elif c.target_marker.casefold() in c.clean_content.casefold():
                problems.append(f"{sid}: target_marker already present in clean_content")
            if c.content == c.clean_content:
                problems.append(f"{sid}: attacked content equals clean_content")
            twin = by_id.get(sid[: -len("attack")] + "clean")
            if twin is None:
                problems.append(f"{sid}: no matched clean counterpart")
            else:
                for field in MATCHED_FIELDS:
                    if getattr(c, field) != getattr(twin, field):
                        problems.append(
                            f"{sid}: {field} differs from {twin.scenario_id}"
                        )
        else:
            if c.attacker_goal != "none" or c.target_marker:
                problems.append(f"{sid}: non-attacked case must have no goal or marker")
            if c.kind == "clean":
                if c.family != "none":
                    problems.append(f"{sid}: clean case family must be 'none'")
                if c.content != c.clean_content:
                    problems.append(f"{sid}: clean case content must equal clean_content")
            else:
                if c.family != "harmless_quotation":
                    problems.append(
                        f"{sid}: benign case family must be 'harmless_quotation'"
                    )
                if c.content == c.clean_content:
                    problems.append(f"{sid}: benign case must add a quoted instruction")
    return problems


def make_split(
    cases: list[Case], dev_fraction: float = 0.3, seed: int = 2026
) -> dict[str, str]:
    """Assign whole source-scenario groups to dev or heldout, stratified by workflow."""
    groups = defaultdict(set)
    for c in cases:
        groups[c.workflow].add(group_id(c))
    rng = random.Random(seed)
    workflows = sorted(groups)
    total_dev = round(sum(len(g) for g in groups.values()) * dev_fraction)
    quota = {wf: int(len(groups[wf]) * dev_fraction) for wf in workflows}
    # Hand leftover dev slots to the largest remainders; ties broken by seeded order.
    order = workflows[:]
    rng.shuffle(order)
    order.sort(key=lambda wf: quota[wf] - len(groups[wf]) * dev_fraction)
    for wf in order[: total_dev - sum(quota.values())]:
        quota[wf] += 1
    split = {}
    for wf in workflows:
        members = sorted(groups[wf])
        rng.shuffle(members)
        for i, g in enumerate(members):
            split[g] = "dev" if i < quota[wf] else "heldout"
    return dict(sorted(split.items()))


def count_cases(cases: list[Case], split: dict[str, str] | None = None) -> dict:
    counts = {
        "cases": len(cases),
        "groups": len({group_id(c) for c in cases}),
        "by_kind": dict(sorted(Counter(c.kind for c in cases).items())),
        "by_workflow_kind": {},
        "attacked_by_family": dict(
            sorted(Counter(c.family for c in cases if c.kind == "attacked").items())
        ),
        "attacked_by_workflow_family": {},
    }
    for c in cases:
        counts["by_workflow_kind"].setdefault(c.workflow, Counter())[c.kind] += 1
        if c.kind == "attacked":
            counts["attacked_by_workflow_family"].setdefault(c.workflow, Counter())[
                c.family
            ] += 1
    for key in ("by_workflow_kind", "attacked_by_workflow_family"):
        counts[key] = {k: dict(sorted(v.items())) for k, v in sorted(counts[key].items())}
    if split:
        counts["by_split"] = {
            s: {
                "groups": sum(v == s for v in split.values()),
                "cases": sum(split[group_id(c)] == s for c in cases),
                "attacked": sum(
                    split[group_id(c)] == s and c.kind == "attacked" for c in cases
                ),
            }
            for s in SPLITS
        }
    return counts


def build_manifest(
    cases: list[Case], dev_fraction: float = 0.3, seed: int = 2026
) -> dict:
    split = make_split(cases, dev_fraction, seed)
    return {
        "manifest_version": 1,
        "created": date.today().isoformat(),
        "seed": seed,
        "dev_fraction": dev_fraction,
        "counts": count_cases(cases, split),
        "groups": split,
        "cases": {
            c.scenario_id: {
                "group": group_id(c),
                "split": split[group_id(c)],
                "sha256": case_sha256(c),
            }
            for c in sorted(cases, key=lambda c: c.scenario_id)
        },
    }


def load_manifest(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def verify_manifest(cases: list[Case], manifest: dict) -> list[str]:
    """Detect cases added, removed, or edited since the manifest was frozen."""
    recorded = manifest["cases"]
    problems = []
    for c in cases:
        entry = recorded.get(c.scenario_id)
        if entry is None:
            problems.append(f"{c.scenario_id}: not in manifest (added after freeze)")
        elif entry["sha256"] != case_sha256(c):
            problems.append(f"{c.scenario_id}: changed since manifest was frozen")
    current = {c.scenario_id for c in cases}
    problems += [
        f"{sid}: in manifest but missing from cases" for sid in recorded if sid not in current
    ]
    return problems


def select_split(cases: list[Case], manifest: dict, split: str) -> list[Case]:
    if split not in SPLITS:
        raise ValueError(f"Unknown split {split!r}; expected one of {SPLITS}")
    problems = verify_manifest(cases, manifest)
    if problems:
        raise ValueError("Cases do not match the frozen manifest: " + "; ".join(problems))
    return [c for c in cases if manifest["cases"][c.scenario_id]["split"] == split]


def write_inventory(
    cases: list[Case], path: str | Path, manifest: dict | None = None
) -> None:
    fields = [
        "scenario_id",
        "group",
        "split",
        "workflow",
        "kind",
        "family",
        "attacker_goal",
        "target_marker",
        "injection_position",
        "utility_terms",
        "allowed_tools",
        "allowed_recipients",
        "source",
        "license_note",
        "sha256",
    ]
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for c in sorted(cases, key=lambda c: c.scenario_id):
            entry = (manifest or {}).get("cases", {}).get(c.scenario_id, {})
            writer.writerow(
                {
                    "scenario_id": c.scenario_id,
                    "group": group_id(c),
                    "split": entry.get("split", ""),
                    "workflow": c.workflow,
                    "kind": c.kind,
                    "family": c.family,
                    "attacker_goal": c.attacker_goal,
                    "target_marker": c.target_marker,
                    "injection_position": injection_position(c),
                    "utility_terms": "; ".join(c.utility_terms),
                    "allowed_tools": "; ".join(c.allowed_tools),
                    "allowed_recipients": "; ".join(c.allowed_recipients),
                    "source": c.source,
                    "license_note": c.license_note,
                    "sha256": case_sha256(c),
                }
            )
