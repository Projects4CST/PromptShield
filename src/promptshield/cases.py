from pathlib import Path
import yaml
from .schema import Case


def load_cases(directory: str | Path) -> list[Case]:
    path = Path(directory)

    if path.is_file() and path.suffix in {".yaml", ".yml"}:
        files = [path]
    elif path.is_dir():
        files = sorted(path.glob("**/*.yaml")) + sorted(path.glob("**/*.yml"))
    else:
        raise ValueError(f"No YAML cases found in {directory}")

    if not files:
        raise ValueError(f"No YAML cases found in {directory}")

    cases = []
    ids = set()

    for file in files:
        data = yaml.safe_load(file.read_text(encoding="utf-8"))
        entries = data if isinstance(data, list) else [data]

        for entry in entries:
            case = Case.parse(entry)
            if case.scenario_id in ids:
                raise ValueError(f"Duplicate scenario_id: {case.scenario_id}")
            ids.add(case.scenario_id)
            cases.append(case)

    return cases