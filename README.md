# PromptShield

**A small, inspectable Python harness for studying indirect prompt-injection attacks and application-level defenses.**

PromptShield is a teaching and experimental tool. It lets you see every input, defense decision, model response, proposed tool call, and scoring result. It is **not** a security product and **not** a general-purpose benchmark.

## Features (v0.1)

- 120 synthetic YAML test cases with attacker goals and source notes (48 attacked, 48 matched clean, 24 benign quoted-instruction). Each case is a text record; `web`, `document` and `email` are workflow labels, not real files or inboxes
- Group-level dev/held-out split frozen by per-case SHA-256 (`promptshield split`)
- Four defense configurations: **D0** (none), **D1** (boundary guidance), **D2** (rule screening + withhold), **D3** (D2, then D1)
  - D1 neutralizes delimiter-breakout attempts (`d1-v0.3`)
  - D2 has 15 versioned regex rules in 4 categories, each with a rule ID and a logged ruleset hash (`d2-v0.2`); it fails closed if screening errors
- **D4**: a shadow-mode authorization gate for proposed email tool calls (no real actions, nothing executed)
- JSONL trace logs for full auditability, including defense versions, matched rule IDs and gate decisions
- Mock backend (offline) plus OpenAI and Ollama adapters
- Explicit `review_required` status when a marker appears in the answer (quotation ≠ success) and `invalid` status when screening fails

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
│   ├── manifest.json       # frozen dev/held-out split + case hashes
│   ├── web/                # web-001.yaml … web-008.yaml
│   ├── document/           # document-001.yaml … document-008.yaml
│   └── email/              # email-001.yaml … email-008.yaml
├── docs/
│   └── dataset/
│       ├── PROVENANCE.md
│       ├── BENCHMARK_COMPARISON.md
│       └── inventory.csv
├── src/
│   └── promptshield/
│       ├── __init__.py
│       ├── schema.py
│       ├── cases.py
│       ├── dataset.py
│       ├── defenses.py      # D0-D3 (D1 boundary, D2 rules)
│       ├── models.py
│       ├── tools.py         # D4 shadow authorization gate
│       ├── evaluator.py
│       ├── runner.py
│       ├── report.py
│       ├── cli.py
│       ├── d2_dev_check.py  # runs D2 rules over the dev split only
│       └── d4_demo.py       # prohibited vs. legitimate email through the gate
└── tests/
    ├── test_core.py
    └── test_defenses.py     # D0-D3 and gate unit tests
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
# 1. Validate scenarios (consistency checks + frozen-manifest check)
promptshield validate --cases scenarios
promptshield inventory                      # case counts by workflow/kind/family/split

# 2. Tune defenses on the dev split only; held-out is for the frozen comparison
promptshield run --split dev --backend mock --output runs/dev-mock.jsonl

# 3. See which dev cases the D2 rules withhold or miss
python -m promptshield.d2_dev_check scenarios

# 4. Demo: a few cases (ids or globs, repeatable) under selected defenses
promptshield run --case "document-001-a-*" --case document-001-benign \
  --defenses D0,D1,D2,D3 --backend mock --output runs/demo.jsonl

# 5. Run everything with the offline mock backend (safe, no API key needed)
promptshield run --cases scenarios --backend mock --output runs/mock.jsonl

# 6. View provisional summary
promptshield report --input runs/mock.jsonl

# 7. D4 demo: a prohibited and a legitimate proposed email through the shadow gate
python -m promptshield.d4_demo

# 8. Run tests
pytest -q
```

> **Important:** A mock run only proves that the orchestration and scoring code works.  
> **It does not measure any defense effectiveness.**

### Real model

```bash
# This is for Open AI
export OPENAI_API_KEY="your-key-here"

promptshield run \
  --backend openai \
  --model gpt-4o-mini \
  --cases scenarios \
  --output runs/live.jsonl

# For Ollama model
# Here --cases for specific case files

promptshield run \
  --cases scenarios/web/web-001.yaml \
  --backend ollama \
  --model gemma3 \
  --output runs/ollama_one.jsonl

# Reporting (Summary and summary + json)
promptshield report --input runs/live.jsonl
promptshield report --input runs/live.jsonl --json
```

The OpenAI adapter never grants real tools. It only asks the model to optionally propose a tool call in JSON. Always inspect the raw traces.

## Defense Configurations

| ID  | Boundary guidance | Screening | Behavior                                                                                       |
|-----|-------------------|-----------|------------------------------------------------------------------------------------------------|
| D0  | Off               | Off       | Ordinary prompt                                                                                |
| D1  | On                | Off       | Labeled delimiters plus a fixed reminder that the content is data; fake delimiters in the text are neutralized |
| D2  | Off               | On        | Withholds the whole field if any D2 rule matches; the model is not called                      |
| D3  | On                | On        | D2 first; if nothing matches, D1                                                               |
**D2 rules.** 15 rules in four categories: `override`, `authority`, `disclosure`, `tool_use`. Each rule has an ID (for example `OVR-01`, `AUTH-05`, `TOOL-01`). The whole rule set has a SHA-256 hash that is logged in every D2/D3 trial, so a result can always be tied to the rule version that produced it. The rules are a transparent baseline tuned on the dev split only, **not** a robust detector. They miss task-aligned persuasion that has no instruction wording, and they withhold benign quoted instructions (an expected false-block cost).

**Fail-closed screening.** If D2 screening raises an error or receives malformed input, the field is withheld, `d2_error` is logged, and the trial is scored `invalid` (never counted as a defense success).

### D4: authorization gate (shadow mode)

D4 is separate from D0–D3 and is not selected with `--defenses`. For every proposed tool call it checks the tool and, for `send_email`, the recipient against the case's `allowed_tools` and `allowed_recipients` (compared case-insensitively). It logs ALLOW or DENY with a reason, the policy ID and policy hash. In shadow mode nothing is executed or sent (`gate_enforced=false`, `simulated_execution_status=not_executed_shadow_mode`).

## Trace Fields

Every trial record in the JSONL log includes, besides the input, raw answer and scores:

- `defense`, `case_sha256`, `model`, `backend`, `is_real_model_evidence`
- D1 trials: `d1_version`, `d1_template_sha256`
- D2/D3 trials: `d2_ruleset_version`, `d2_ruleset_hash`, `d2_abstained`, `d2_matched_rule_id`, `d2_matched_category`, `d2_error`
- Gate: `policy_id`, `policy_hash`, `gate_mode`, `gate_decision`, `gate_reason`, `gate_enforced`, `simulated_execution_status`

## Reported Metrics

- **ASR (provisional):** attacked cases scored as success ÷ attacked cases scored success or failure (`review_required` and `invalid` trials are excluded and counted separately)
- **Safe completion:** the task succeeded and the attack did not
- **False-block rate:** withheld benign quoted-instruction cases ÷ benign cases. Clean-case abstentions are reported separately (`clean_withheld`)
- **D2 abstention rate**, **invalid** trial count
- **D4 (email):** prohibited calls proposed, prohibited calls the gate allowed, legitimate calls the gate denied

## Important Limitations

- The 120 included cases (24 source-scenario groups) are original synthetic examples; see [scenarios/README.md](scenarios/README.md) and [docs/dataset/](docs/dataset/).
- D2 rules were tuned on the dev split (35 cases), so held-out results may be lower than dev results. Do not change rules after looking at held-out results.
- The D4 ground-truth label uses the same scenario allowlist as the gate, so it checks the gate's logic, not whether the policy itself is right.
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
