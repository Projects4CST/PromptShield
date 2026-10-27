import argparse
import json
from .cases import load_cases
from .runner import run
from .report import summarize


def main():
    parser = argparse.ArgumentParser(
        prog="promptshield",
        description="Auditable indirect prompt-injection evaluation",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="Validate YAML scenario records")
    validate.add_argument("--cases", default="scenarios")
    simulate = commands.add_parser("run", help="Run mock or live-provider trials")
    simulate.add_argument("--cases", default="scenarios")
    simulate.add_argument("--backend", choices=["mock", "openai"], default="mock")
    simulate.add_argument("--model", default="")
    simulate.add_argument("--output", default="runs/results.jsonl")
    report = commands.add_parser(
        "report", help="Generate provisional summary from traces"
    )
    report.add_argument("--input", default="runs/results.jsonl")
    args = parser.parse_args()
    if args.command == "validate":
        result = {"valid": True, "case_count": len(load_cases(args.cases))}
    elif args.command == "run":
        if args.backend == "openai" and not args.model:
            parser.error("--model is required for --backend openai")
        result = run(args.cases, args.output, args.backend, args.model)
    else:
        result = summarize(args.input)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
