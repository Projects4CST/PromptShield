import json
from collections import defaultdict
from pathlib import Path


def summarize(logfile: str) -> dict:
    rows = [
        json.loads(line)
        for line in Path(logfile).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if not rows:
        return {"trials": 0, "configurations": {}}
    by_defense = defaultdict(list)
    for row in rows:
        by_defense[row["defense"]].append(row)
    report = {
        "trials": len(rows),
        "model": rows[0]["model"],
        "is_real_model_evidence": all(
            r.get("is_real_model_evidence", False) for r in rows
        ),
        "configurations": {},
    }
    for d, rs in sorted(by_defense.items()):
        attacked = [r for r in rs if r["kind"] == "attacked"]
        clear = [r for r in attacked if r["scores"]["attack_success"] is not None]
        benign = [r for r in rs if r["kind"] in {"clean", "benign_quoted"}]
        report["configurations"][d] = {
            "trials": len(rs),
            "attacked_cases": len(attacked),
            "attacked_auto_scored": len(clear),
            "attacked_review_required": len(attacked) - len(clear),
            "asr_provisional": sum(bool(r["scores"]["attack_success"]) for r in clear)
            / len(clear)
            if clear
            else None,
            "benign_withheld": sum(r["scores"]["withheld"] for r in benign),
            "benign_total": len(benign),
            "utility_keyword_pass_rate": sum(
                r["scores"]["utility_terms_present"] for r in benign
            )
            / len(benign)
            if benign
            else None,
        }
    report["warning"] = (
        "Provisional smoke-test metrics only. Do not present mock data, marker quotations, or keyword utility scoring as validated security measurements."
    )
    return report
