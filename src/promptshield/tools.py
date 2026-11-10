"""D4: task-specific authorization gate for proposed mock tool calls (email workflow).

Shadow mode: the gate records what it WOULD decide; it never blocks or executes
anything, and the simulator has no network capability.
"""

import hashlib
from dataclasses import dataclass
from typing import Any

POLICY_ID = "d4-email-allowlist-v0.1"
GATE_MODE = "shadow"
GATE_ENFORCED = False
# Hash of the policy logic version, logged in every trial (changes if you bump POLICY_ID).
POLICY_HASH = hashlib.sha256(
    f"{POLICY_ID}|tool in allowed_tools|send_email: normalized recipient in allowed_recipients".encode()
).hexdigest()
SIMULATED_STATUS = "not_executed_shadow_mode"

@dataclass(frozen=True)
class GateDecision:
    attempted: bool
    operation: str | None
    recipient: str | None
    authorized: bool  # gate decision: allow (True) / deny (False)
    would_execute: bool  # always False in shadow mode: nothing is executed
    reason: str
    policy_id: str = POLICY_ID
    policy_hash: str = POLICY_HASH
    gate_mode: str = GATE_MODE
    gate_enforced: bool = GATE_ENFORCED
    simulated_execution_status: str = SIMULATED_STATUS

def _norm(addr: Any) -> str:
    return str(addr).strip().casefold()
    
def authorize(
    proposed: dict[str, Any] | None,
    allowed_tools: tuple[str, ...],
    allowed_recipients: tuple[str, ...],
) -> GateDecision:
    if proposed is None:
        return GateDecision(
            False, None, None, False, False, "no_proposed_tool_call",
            simulated_execution_status="no_call",
        )
    if not isinstance(proposed, dict):
        return GateDecision(True, None, None, False, False, "malformed_call")

    op = str(proposed.get("tool", "")).strip()
    args = proposed.get("arguments", {})
    if not isinstance(args, dict):
        return GateDecision(True, op, "", False, False, "malformed_arguments")

    recipient = _norm(args.get("to", ""))
    allowed_ops = {str(t).strip() for t in allowed_tools}
    allowed_rcpt = {_norm(r) for r in allowed_recipients}

    if op not in allowed_ops:
        decision, reason = False, "tool_outside_allowlist"
    elif op == "send_email":
        if recipient in allowed_rcpt and recipient:
            decision, reason = True, "authorized"
        else:
            decision, reason = False, "recipient_outside_allowlist"
    else:
        # Any other allowed tool has no argument constraints in this policy version.
        decision, reason = True, "authorized_no_argument_constraints"

    return GateDecision(
        attempted=True,
        operation=op,
        recipient=recipient,
        authorized=decision,
        would_execute=False,  # shadow mode: decision only, never executed
        reason=reason,
    )
