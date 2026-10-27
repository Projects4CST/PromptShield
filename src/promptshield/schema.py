from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Case:
    scenario_id: str
    workflow: str
    family: str
    kind: str
    user_request: str
    clean_content: str
    content: str
    attacker_goal: str
    target_marker: str
    utility_terms: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    allowed_recipients: tuple[str, ...]
    source: str
    license_note: str

    @classmethod
    def parse(cls, obj: dict[str, Any]) -> "Case":
        required = [
            "scenario_id",
            "workflow",
            "family",
            "kind",
            "user_request",
            "clean_content",
            "content",
            "attacker_goal",
            "target_marker",
            "utility_terms",
            "allowed_tools",
            "allowed_recipients",
            "source",
            "license_note",
        ]
        missing = [k for k in required if k not in obj]
        if missing:
            raise ValueError(f"Missing required fields: {missing}")
        if obj["workflow"] not in {"email", "web", "document"}:
            raise ValueError("Invalid workflow")
        if obj["kind"] not in {"attacked", "clean", "benign_quoted"}:
            raise ValueError("Invalid case kind")
        if not str(obj["scenario_id"]).strip():
            raise ValueError("Empty scenario_id")
        return cls(
            **{
                **obj,
                "utility_terms": tuple(obj["utility_terms"]),
                "allowed_tools": tuple(obj["allowed_tools"]),
                "allowed_recipients": tuple(obj["allowed_recipients"]),
            }
        )
