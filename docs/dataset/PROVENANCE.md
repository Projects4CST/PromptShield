# Licensing and Provenance Register

Owner: Member 3 (Dataset, scenarios, and benchmark research)
Dataset version: v0.2 (120 cases, 24 source-scenario groups)
Last checked: 2026-10-30

This register records where every case comes from and under what terms it may be used, as required by proposal §4 and §10 ("any imported benchmark item must have its source, license, and modification recorded before use").

## 1. Cases in this repository

| Groups | Cases | `source` | Author | License | Modified from external material? |
|--------|------:|----------|--------|---------|----------------------------------|
| web-001 … web-008 | 40 | `original_synthetic` | PromptShield team | MIT (repository license) | No |
| document-001 … document-008 | 40 | `original_synthetic` | PromptShield team | MIT (repository license) | No |
| email-001 … email-008 | 40 | `original_synthetic` | PromptShield team | MIT (repository license) | No |

All 120 cases are original synthetic text written for this project. **No case is copied or adapted from a public benchmark.** Groups web-001, document-001, and email-001 extend the three v0.1 fixtures. Their original wording is kept, except the document-001 marker, which was renamed from `ORANGE_MOON_99` to `COBALT_MOON_99` so every marker is unique.

Content safety properties (checked when authoring):

- All people, organisations, places, and products are fictional (e.g. "Northgate Library", "Tallyboard 3.6", "Mount Varenna").
- Email addresses use only reserved domains: `example.org` for legitimate parties and `.invalid` for attacker addresses (RFC 2606 / RFC 6761). The simulator cannot send mail.
- Secrets and markers (`*_SECRET_*`, `WORD_WORD_NN`) are synthetic strings with no meaning outside this dataset.
- No payload names or targets a real third-party service, model provider, or product.

## 2. External sources considered (not imported)

Licenses were read from the GitHub repository metadata API on 2026-10-30. "Not verified" means the lookup failed or the repository reports no license; check manually before any reuse.

| Source | Ref. | Repository | Code license | Data terms | Status in PromptShield |
|--------|------|------------|--------------|------------|------------------------|
| BIPIA | [1] | `microsoft/BIPIA` (archived, last push 2024-04) | **Not verified**: GitHub reports `NOASSERTION` | Contexts are built from third-party datasets; each source has its own terms | Concepts only (task types, border-string defense idea). No text reused. |
| AgentDojo | [2] | `ethz-spylab/agentdojo` | MIT | Shipped with code | Concepts only (clean-task baseline, tool-state checks) |
| Open-Prompt-Injection | [3] | `liu00222/Open-Prompt-Injection` | MIT | Task data comes from public NLP datasets with their own terms | Concepts only (attack-style taxonomy, e.g. context ignoring, fake completion) |
| InjecAgent | [7] | `uiuc-kang-lab/InjecAgent` | MIT | Shipped with code | Concepts only (user-tool vs attacker-tool structure for email cases) |
| Tensor Trust | [6] | `HumanCompatibleAI/tensor-trust` / `tensor-trust-data` | BSD-2-Clause (game code) | **Not verified**: the data repository reports no license | Not used. Informs the family taxonomy only. |
| PyRIT | [9] | `Azure/PyRIT` | MIT | — | Not used |
| garak | [10] | `NVIDIA/garak` | **Not verified** (lookup failed) | — | Not used |
| CaMeL | [12] | `google-research/camel-prompt-injection` | Apache-2.0 | — | Not used (background only) |

Using an *idea* from a paper (for example "task-aligned persuasion" as a family) is cited in the report. It is not a reuse of licensed material.

## 3. Procedure for importing a case later

1. Confirm the license of both the **code repository** and the **underlying data source**. Many benchmarks wrap third-party corpora whose terms differ from the code license.
2. Add a row to §1 with `source: <benchmark>:<original-id>`, the license, and the URL plus commit hash you copied from.
3. Set `license_note` in the YAML to the license and a one-line description of any modification (e.g. "adapted: payload moved to email body, marker added").
4. Keep adapted cases in their own groups. Never mix them with original groups, so results can be reported separately (proposal §4, "adapted cases will be labeled separately").
5. Regenerate the manifest **before** the protocol freeze; imported cases cannot enter after it.

## 4. Open items

- [ ] Manually confirm BIPIA's license file and per-dataset terms if any BIPIA content is considered.
- [ ] Confirm the garak license (expected Apache-2.0, not verified on 2026-10-30).
- [ ] Project lead to sign off that no imported material is needed for v0.2.
