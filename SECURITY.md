# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| `main` / latest release | Yes |
| Older tags | Best effort only |

## What this project is

PromptShield is a **research evaluation harness** for indirect prompt-injection experiments in controlled lab settings. Scenarios are synthetic. The email authorization path runs in **shadow mode** and is not intended to send real messages.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security-sensitive reports.

Instead, report privately to the maintainers using one of:

1. **GitHub Private Vulnerability Reporting** (Security tab → “Report a vulnerability”), if enabled on this repository  
2. **Email** the contacts listed in the project README / repository owner profile  

Include, if possible:

- A short description of the issue  
- Steps to reproduce  
- Affected version or commit  
- Impact (e.g. unexpected code execution in tooling, secret leakage in logs, unsafe defaults)

You should receive an acknowledgement within **7 days**. We will discuss a fix timeline and whether a public advisory is appropriate.

## Scope

**In scope (examples)**

- Flaws in the CLI, adapters, or scripts that could exfiltrate secrets from the developer environment  
- Unsafe handling of untrusted scenario files when validating or running locally  
- Accidental logging of API keys or credentials into traces/reports  
- Dependency issues that clearly affect this package’s recommended install path  

**Out of scope (examples)**

- Model providers producing harmful or incorrect text (expected research subject matter)  
- Attacks against third-party services, real inboxes, or production LLM apps  
- “Bypassing” D1/D2 on benchmark cases as a vulnerability report (that is evaluation signal, not a product exploit)  
- Social engineering of maintainers  

## Safe use

- Do not point this tool at real user data or live mail systems.  
- Do not commit `.env` files or API keys.  
- Treat `runs/*.jsonl` as potentially sensitive if you ever embed real content; default scenarios are synthetic.  

## Preferred public discussion

Non-sensitive bugs, scenario fixes, and feature requests belong in **GitHub Issues** or pull requests, following `CONTRIBUTING.md`.
