# Scenarios

This folder contains the test cases used by PromptShield.

## Structure

```text
scenarios/
├── README.md                 # This file
├── web/
│   └── web-001.yaml          # Attack + clean + benign
├── document/
│   └── document-001.yaml     # Attack
└── email/
    └── email-001.yaml        # Attack + clean
```

Related cases (attack / clean / benign) that share the same underlying task are kept together. This matches the **source-scenario group** idea used in the research protocol.

## Case Schema

Every case must contain the following fields:

| Field                | Type     | Description |
|----------------------|----------|-------------|
| `scenario_id`        | string   | Unique ID (e.g. `web-001-attack`) |
| `workflow`           | string   | One of: `web`, `document`, `email` |
| `family`             | string   | Attack family (or `none`) |
| `kind`               | string   | `attacked`, `clean`, or `benign_quoted` |
| `user_request`       | string   | The legitimate user task |
| `clean_content`      | string   | The clean version of the external content |
| `content`            | string   | The actual content sent to the model (may contain payload) |
| `attacker_goal`      | string   | What the attacker is trying to achieve |
| `target_marker`      | string   | Synthetic marker used to detect success (can be empty) |
| `utility_terms`      | list     | Keywords that should appear for basic utility check |
| `allowed_tools`      | list     | Tools the authorization gate is allowed to approve |
| `allowed_recipients` | list     | Allowed email recipients (for email workflow) |
| `source`             | string   | Provenance of the case |
| `license_note`       | string   | License / usage note |

## Current Cases (v0.1)

| scenario_id            | Workflow  | Kind            | Attack Family              |
|------------------------|-----------|-----------------|----------------------------|
| `web-001-attack`       | web       | attacked        | instruction_override       |
| `web-001-clean`        | web       | clean           | —                          |
| `web-001-benign`       | web       | benign_quoted   | harmless_quotation         |
| `document-001-attack`  | document  | attacked        | role_spoofing              |
| `email-001-attack`     | email     | attacked        | synthetic_exfiltration     |
| `email-001-clean`      | email     | clean           | —                          |

## Adding New Cases

1. Create a new YAML file under the appropriate workflow folder.
2. Keep related cases (attack + clean + benign) in the same file when possible.
3. Use a clear `scenario_id` pattern: `{workflow}-{number}-{kind}`.
4. Always provide a matched clean version for attacked cases.
5. Document the `source` and `license_note`.
