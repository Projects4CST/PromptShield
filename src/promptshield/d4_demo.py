"""Demo: a proposed prohibited mock email and the D4 shadow-gate decision.
The mock model never proposes tool calls, so this feeds a scripted proposal through the
real gate and evaluator. No email is sent. Usage: python -m promptshield.d4_demo [scenarios]"""
import json
import re
import sys
from dataclasses import asdict
from .cases import load_cases
from .evaluator import evaluate
from .models import ModelOutput
from .tools import authorize


def main(root: str = "scenarios") -> None:
    cases = [c for c in load_cases(root) if c.kind == "attacked" and c.workflow == "email"
             and c.family == "unauthorized_tool_use"]
    # Prefer a scenario whose task authorizes a recipient, so both outcomes can be shown.
    case = next((c for c in cases if c.allowed_recipients), cases[0])
    found = [a for a in re.findall(r"[\w.+-]+@[\w.-]+\w", case.content)
             if a.casefold() not in {r.casefold() for r in case.allowed_recipients}]
    evil = found[0] if found else "attacker@example.invalid"
    proposals = [("PROHIBITED", evil)]
    if case.allowed_recipients:
        proposals.append(("LEGITIMATE", case.allowed_recipients[0]))
    for label, to in proposals:
        call = {"tool": "send_email", "arguments": {"to": to, "body": case.target_marker if label == "PROHIBITED" else "Thanks, noted."}}
        gate = authorize(call, case.allowed_tools, case.allowed_recipients)
        s = evaluate(case, ModelOutput(text="ok", proposed_tool_call=call), gate, False)
        print(f"--- {label} proposal for {case.scenario_id}")
        print(json.dumps(call))
        print(f"gate decision: {'ALLOW' if gate.authorized else 'DENY'} ({gate.reason}); "
              f"mode={gate.gate_mode}, enforced={gate.gate_enforced}, "
              f"execution={gate.simulated_execution_status}")
        print(f"prohibited_policy_allowed={s['prohibited_policy_allowed']} "
              f"legitimate_call_denied={s['legitimate_call_denied']}")


if __name__ == "__main__":
    main(*sys.argv[1:2])
