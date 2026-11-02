import argparse
import json
import sys
from pathlib import Path
from .cases import load_cases
from .dataset import (
    SPLITS,
    build_manifest,
    check_dataset,
    count_cases,
    load_manifest,
    verify_manifest,
    write_inventory,
)
from .runner import run
from .report import summarize, format_report


def default_manifest(cases_dir: str) -> str:
    return str(Path(cases_dir) / "manifest.json")


def main():
    parser = argparse.ArgumentParser(
        prog="promptshield",
        description="Auditable indirect prompt-injection evaluation",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="Validate YAML scenario records")
    validate.add_argument("--cases", default="scenarios")
    validate.add_argument(
        "--manifest",
        help="Frozen manifest to check against (default: <cases>/manifest.json if present)",
    )
    simulate = commands.add_parser("run", help="Run mock or live-provider trials")
    simulate.add_argument("--cases", default="scenarios")
    simulate.add_argument(
        "--backend", choices=["mock", "openai", "ollama"], default="mock"
    )
    simulate.add_argument("--model", default="")
    simulate.add_argument("--output", default="runs/results.jsonl")
    simulate.add_argument(
        "--split", choices=SPLITS, help="Only run cases from this manifest split"
    )
    simulate.add_argument("--manifest", help="Default: <cases>/manifest.json")
    simulate.add_argument(
        "--case",
        action="append",
        default=[],
        help="Only run this scenario id or glob (repeatable), e.g. document-001-*",
    )
    simulate.add_argument(
        "--defenses",
        default="D0,D1,D2,D3",
        help="Comma-separated defense configurations to run (default: D0,D1,D2,D3)",
    )
    split = commands.add_parser(
        "split", help="Assign scenario groups to dev/heldout and freeze a manifest"
    )
    split.add_argument("--cases", default="scenarios")
    split.add_argument("--output", help="Default: <cases>/manifest.json")
    split.add_argument("--dev-fraction", type=float, default=0.3)
    split.add_argument("--seed", type=int, default=2026)
    split.add_argument(
        "--force", action="store_true", help="Overwrite an existing (frozen) manifest"
    )
    inventory = commands.add_parser(
        "inventory", help="Count cases and optionally export a CSV inventory"
    )
    inventory.add_argument("--cases", default="scenarios")
    inventory.add_argument(
        "--manifest", help="Default: <cases>/manifest.json if present"
    )
    inventory.add_argument("--csv", help="Write one row per case to this CSV file")
    report = commands.add_parser(
        "report", help="Generate provisional summary from traces"
    )
    report.add_argument("--input", default="runs/results.jsonl")
    report.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON instead of the human report",
    )
    args = parser.parse_args()
    exit_code = 0
    if args.command == "validate":
        cases = load_cases(args.cases)
        problems = check_dataset(cases)
        manifest_path = args.manifest or default_manifest(args.cases)
        if args.manifest or Path(manifest_path).exists():
            problems += verify_manifest(cases, load_manifest(manifest_path))
        result = {"valid": not problems, "case_count": len(cases), "problems": problems}
        exit_code = 1 if problems else 0
    elif args.command == "run":
        if args.backend == "openai" and not args.model:
            parser.error("--model is required for --backend openai")
        defenses = tuple(
            d.strip().upper() for d in args.defenses.split(",") if d.strip()
        )
        unknown = sorted(set(defenses) - {"D0", "D1", "D2", "D3"})
        if not defenses or unknown:
            parser.error(
                f"--defenses must be drawn from D0,D1,D2,D3 (got {unknown or 'none'})"
            )
        manifest = (
            (args.manifest or default_manifest(args.cases)) if args.split else None
        )
        try:
            result = run(
                args.cases,
                args.output,
                args.backend,
                args.model,
                defenses,
                split=args.split,
                manifest=manifest,
                only=tuple(args.case),
            )
        except ValueError as e:
            parser.error(str(e))
    elif args.command == "split":
        output = Path(args.output or default_manifest(args.cases))
        if output.exists() and not args.force:
            parser.error(
                f"{output} already exists; the split is frozen (use --force to replace it)"
            )
        cases = load_cases(args.cases)
        problems = check_dataset(cases)
        if problems:
            parser.error(
                "fix dataset problems before splitting: " + "; ".join(problems)
            )
        manifest = build_manifest(cases, args.dev_fraction, args.seed)
        output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        result = {
            "output": str(output),
            "groups": manifest["groups"],
            **manifest["counts"],
        }
    elif args.command == "inventory":
        cases = load_cases(args.cases)
        manifest_path = args.manifest or default_manifest(args.cases)
        manifest = (
            load_manifest(manifest_path)
            if args.manifest or Path(manifest_path).exists()
            else None
        )
        result = count_cases(cases, manifest["groups"] if manifest else None)
        if args.csv:
            write_inventory(cases, args.csv, manifest)
            result["csv"] = args.csv

    elif args.command == "report":
        result = summarize(args.input)

        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print(format_report(result))

    else:
        parser.print_help()
        exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
