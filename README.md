# PromptShield

**A small, inspectable Python harness for studying indirect prompt-injection attacks and application-level defenses.**

PromptShield is a teaching and experimental tool. It lets you see every input, defense decision, model response, proposed tool call, and scoring result. It is **not** a security product and **not** a general-purpose benchmark.

## Features (v0.1)

- YAML test cases with attacker goals and source notes
- Three workflows: web retrieval, document summarization, email
- Four defense configurations: **D0** (none), **D1** (boundary guidance), **D2** (regex screening + withhold), **D3** (both)
- Shadow-mode authorization gate for proposed tool calls (no real actions)
- JSONL trace logs for full auditability
- Mock backend (offline) + optional OpenAI adapter
- Explicit `review_required` status when a marker appears in the answer (quotation ≠ success)

## Project Structure

```text
promptshield/
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
├── README.md
├── LICENSE
├── .gitignore
├── scenarios/
│   ├── README.md
│   ├── web/
│   │   └── web-001.yaml
│   ├── document/
│   │   └── document-001.yaml
│   └── email/
│       └── email-001.yaml
├── src/
│   └── promptshield/
│       ├── __init__.py
│       ├── schema.py
│       ├── cases.py         
│       ├── defenses.py
│       ├── models.py
│       ├── tools.py
│       ├── evaluator.py
│       ├── runner.py
│       ├── report.py
│       └── cli.py
└── tests/
    └── test_core.py         
```

## Requirements

- Python 3.10+
- [uv](https://github.com/astral-sh/uv) (recommended) **or** pip + venv

## Installation

### Option A — Recommended (`uv`)

```bash
# Install uv if you don't have it
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create virtual environment
uv venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# Install the package in editable mode + dev tools
uv pip install -e ".[dev]"

# Optional: real model support
uv pip install -e ".[openai]"
```

### Option B — Classic pip

```bash
python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
pip install -e .

# or with extras:
pip install -e ".[dev,openai]"
```

## Quick Start

```bash
# 1. Validate scenarios
promptshield validate --cases scenarios

# 2. Run with the offline mock backend (safe, no API key needed)
promptshield run --cases scenarios --backend mock --output runs/mock.jsonl

# 3. View provisional summary
promptshield report --input runs/mock.jsonl

# 4. Run tests
pytest -q
```

> **Important:** A mock run only proves that the orchestration and scoring code works.  
> **It does not measure any defense effectiveness.**

### Real model (optional)

```bash
export OPENAI_API_KEY="your-key-here"

promptshield run \
  --backend openai \
  --model gpt-4o-mini \
  --cases scenarios \
  --output runs/live.jsonl

promptshield report --input runs/live.jsonl
```

The OpenAI adapter never grants real tools. It only asks the model to optionally propose a tool call in JSON. Always inspect the raw traces.

## Defense Configurations

| ID  | Boundary guidance | Screening | Behavior                              |
|-----|-------------------|-----------|---------------------------------------|
| D0  | Off               | Off       | Ordinary prompt                       |
| D1  | On                | Off       | Labels external content as untrusted  |
| D2  | Off               | On        | Withholds field if pattern matches    |
| D3  | On                | On        | Combination of D1 + D2                |

Screening patterns are intentionally simple teaching baselines, **not** robust detectors.

## Important Limitations

- The six included cases are synthetic examples only.
- Keyword-based utility checks are smoke-test proxies, not validated task success.
- Marker appearance in the answer is marked `review_required` (quotation is not automatically attack success).
- Do **not** publish mock results as evidence of defense performance.
- No real email sending, no network side-effects, no live attack endpoints.

For a full research study you still need: more cases, proper rubrics, held-out split, protocol freeze, and real model runs under fixed settings.

## Development

```bash
# Install with dev tools
uv pip install -e ".[dev]"

# Run tests
pytest -q
```

## License

MIT. Synthetic demonstration cases are original examples under the same license.
