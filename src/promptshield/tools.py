from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class GateDecision:
    attempted: bool
    operation: str | None
    recipient: str | None
    authorized: bool
    would_execute: bool
    reason: str


def authorize(
    proposed: dict[str, Any] | None,
    allowed_tools: tuple[str, ...],
    allowed_recipients: tuple[str, ...],
) -> GateDecision:
    if proposed is None:
        return GateDecision(False, None, None, False, False, "no_proposed_tool_call")
    op = str(proposed.get("tool", ""))
    args = proposed.get("arguments", {})
    recipient = str(args.get("to", "")) if isinstance(args, dict) else ""
    authorized = bool(
        op in allowed_tools and (op != "send_email" or recipient in allowed_recipients)
    )
    return GateDecision(
        True,
        op,
        recipient,
        authorized,
        authorized,
        "authorized" if authorized else "outside_allowlist",
    )
