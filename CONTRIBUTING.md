# Contributing to PromptShield

Thanks for helping improve this evaluation platform. The goal is **reproducible measurement** of indirect prompt injection and simple application-level defenses—not marketing a “perfect” defense.

## Before you start

1. Use a virtual environment (`uv` or `python -m venv`).
2. Install in editable mode with dev deps, e.g. `uv pip install -e ".[dev]"` or `pip install -e ".[dev]"`.
3. From the repo root:

```bash
promptshield validate --cases scenarios
pytest -q
```

## Development vs held-out (important)

| Split | Use for |
|-------|---------|
| **Dev** | Designing scenarios, refining D1 text, adjusting D2 rules, debugging |
| **Held-out** | Formal comparison only **after** defenses are frozen |

**Do not** change D1/D2 rules, thresholds, or prompts to improve scores on the **held-out** split. That invalidates the evaluation protocol.

If you need new cases for measuring a gap:

- Prefer adding **dev** groups while iterating, or
- Add **new** held-out groups only with a clear note that they were not used to tune the current rule set.

## Adding scenarios

1. Place YAML under `scenarios/web/`, `scenarios/document/`, or `scenarios/email/`.
2. Prefer **source-scenario groups** of five related cases when possible:
   - task A attacked + clean  
   - task B attacked + clean  
   - one benign quoted (false-block probe)  
3. Required ideas to cover in each case (see existing files for the exact schema):
   - `scenario_id`, `workflow`, `kind`, `family`
   - `user_request`, `content` (and clean content where applicable)
   - `attacker_goal` / `target_marker` for attacks  
   - `utility_terms` for keyword utility checks  
   - email: `allowed_tools` / `allowed_recipients` when relevant  
4. Keep content **synthetic**. Use reserved domains such as `example.org` and `.invalid` only.
5. Validate:

```bash
promptshield validate --cases scenarios
promptshield inventory --cases scenarios
```

6. Do **not** regenerate or overwrite `scenarios/manifest.json` unless the maintainers agree to a new frozen split.

## Changing defenses (D1 / D2)

- Edit on **dev** evidence only.
- Bump version identifiers and ensure rule/template hashes are logged in trials.
- Add or update unit tests under `tests/`.
- Document the change in the PR (what changed, why, dev-only).

## Code style

- Python 3.10+ (match `requires-python` in `pyproject.toml`).
- Prefer clear names and small functions over clever one-liners.
- Keep the email gate in **shadow mode** (log decisions; never send real mail).
- Do not commit API keys, `.env`, or large `runs/*.jsonl` files.
- Before opening a PR:

```bash
pytest -q
promptshield validate --cases scenarios
```

Optional: run a small mock demo:

```bash
promptshield run --cases scenarios --backend mock --defenses D0 --output runs/smoke.jsonl
```

## Pull requests

- One focused change per PR when possible.
- Describe: problem, approach, how you tested, effect on **dev** vs **held-out**.
- Never claim held-out gains from rules tuned on held-out data.

## Security and ethics

This project is for **lab evaluation** with synthetic scenarios. Do not use it to attack real users, inboxes, or production systems. Report suspected vulnerabilities in tooling privately to the maintainers if a security contact is listed in `SECURITY.md` or the README.
