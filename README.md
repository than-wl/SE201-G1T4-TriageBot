# SE201 G1T4 — TriageBot

## What is TriageBot?

Security scanners are useful, but they often report warnings that turn out not to be real vulnerabilities. Developers then have to inspect the source code and security guidance manually to decide which warnings matter.

**TriageBot helps with that review.** It takes an alert produced by a conventional static security scanner, gathers relevant evidence, and uses an AI-assisted review workflow to classify the alert as:

- likely a real vulnerability;
- likely a false positive; or
- requiring human review because the evidence is incomplete or uncertain.

The important idea is that TriageBot must explain its decision using evidence from the source code and relevant security guidance. It should not simply guess from the scanner's warning or produce an unsupported answer.

## How it works

The planned workflow is:

```text
Source code
    ↓
Semgrep static-analysis alert
    ↓
Normalised finding and source-code evidence
    ↓
Security-guidance retrieval
    ↓
Analyst and Skeptic review
    ↓
Chair combines the reports
    ↓
Deterministic citation/format validation
    ↓
Triage outcome with evidence
```

For example, when Semgrep reports a possible SQL injection, TriageBot examines how input flows through the code, checks relevant SQL-injection guidance, considers whether sanitisation or constant values change the risk, and then returns a cited decision. If it cannot justify the decision, it should recommend human review.

## What TriageBot is not

- It does not replace Semgrep or other conventional security scanners.
- It is not intended to discover vulnerabilities independently.
- It does not treat an AI response as automatically trustworthy.
- It does not claim that a small smoke test proves final system accuracy.

The project is about **post-processing and prioritising scanner alerts**, not building a new vulnerability scanner.

## Project goal

Our project goal is to investigate whether a small evidence-grounded, multi-agent workflow can reduce unnecessary SAST alert review while preserving genuine findings and escalating uncertain cases to humans.

We plan to evaluate the approach using the OWASP Benchmark Java dataset and compare it against simpler baselines, such as scanner-only results and a single-LLM workflow. Important measures include genuine findings retained, false positives removed, genuine vulnerabilities wrongly dismissed, human-review rate, latency, and token cost.

## Current stage

This repository is currently at the **feasibility and checkpoint stage**, not the final product stage. We have:

- run Semgrep against the OWASP Benchmark Java dataset;
- tested OpenRouter with the planned Gemini model;
- received structured, cited results for five SQL injection cases;
- exercised a limited Analyst–Skeptic–Chair workflow on those cases; and
- tested basic deterministic validation for malformed or unsupported citations.

The next checkpoint objective is to connect the complete demonstration path and evaluate approximately 100 findings with a documented baseline, metrics, failures, and limitations.

## Repository status

This repository currently contains the project overview, team-owned planning material, and reproducibility checks used during the feasibility and checkpoint work.

| Path                                   | Purpose                                                                          |
| -------------------------------------- | -------------------------------------------------------------------------------- |
| `checkpoint/CHECKPOINT_BRIEF.md`     | Current checkpoint goal, status, and action plan                                 |
| `checkpoint/CHECKPOINT_TEAM_TASKS.md` | Detailed checkpoint assignments and integration checklist                       |
| `checkpoint/CHECKPOINT_DARREN.md`    | Darren's Semgrep integration and OWASP mapping instructions                      |
| `checkpoint/CHECKPOINT_HONG_YI.md`   | Hong Yi's single-agent and council instructions                                  |
| `checkpoint/CHECKPOINT_LISA.md`      | Lisa's validation and human-review instructions                                  |
| `checkpoint/CHECKPOINT_BRADLEY.md`   | Bradley's evaluation and checkpoint-report instructions                          |
| `checkpoint/Checkpoint_WEILIN_FINAL_INTEGRATION_AND_SUBMISSION.md` | Wei Lin's final integration and submission checklist |
| `Context/README.md`                  | Index of shared context and local-only material                                   |
| `verification/openrouter_smoke.py`   | Five-case OpenRouter smoke test and offline validator self-test                  |
| `triagebot/nodes/validate/validator.py` | Deterministic validation gate: unsupported or unverifiable results become `human_review` |
| `tests/test_validator.py`            | Offline tests for the validator (no OpenRouter needed)                            |
| `verification/feasibility_checks.py` | Limited retrieval, evidence-helper, and Analyst–Skeptic–Chair feasibility pass |
| `verification/requirements.txt`      | Python dependency for the verification scripts                                   |
| `.env.example`                       | Safe template for local configuration                                            |

Project-owned proposal and feasibility documents are shared under `Context/`. Restricted SMU course material, the downloaded OWASP Benchmark repository, raw model responses, and generated evidence remain local through `Context/.gitignore`. The online verification scripts expect the relevant local benchmark and Semgrep artefacts under `Context/tmp/`.

## Quick start

The commands below use PowerShell on Windows. The equivalent Python commands work on macOS and Linux with the usual virtual-environment path changes.

### 1. Create the local environment

```powershell
py -m venv .verification-venv
& '.\.verification-venv\Scripts\python.exe' -m pip install -r '.\verification\requirements.txt'
```

### 2. Run the safe offline check

This check makes no network requests and spends no OpenRouter credits.

```powershell
& '.\.verification-venv\Scripts\python.exe' '.\verification\openrouter_smoke.py' --self-test
```

Expected result:

```text
Offline checks passed; fabricated quote, wrong file/line and malformed JSON rejected.
```

Run the validator's offline unit tests from the repository root (standard library only, no network):

```powershell
& '.\.verification-venv\Scripts\python.exe' -m unittest discover -s tests -v
```

### 3. Configure an online smoke test, only when needed

Copy `.env.example` to `.env` and put your own OpenRouter key in the local `.env` file. Never commit `.env` or paste a key into source files, issues, or chat.

The online smoke test makes five paid model calls and requires the private benchmark/Semgrep artefacts under `Context/tmp/`:

```powershell
Copy-Item .env.example .env
# Edit .env and set OPENROUTER_API_KEY locally.
& '.\.verification-venv\Scripts\python.exe' '.\verification\openrouter_smoke.py'
```

The council feasibility pass makes three additional paid model calls:

```powershell
& '.\.verification-venv\Scripts\python.exe' '.\verification\feasibility_checks.py'
```

Both scripts save detailed generated evidence under the ignored `Context/` folder. Review the budget and local input files before running paid checks.

## Current feasibility evidence

The current evidence is deliberately limited:

- Semgrep has been run against the OWASP Benchmark Java dataset.
- OpenRouter has returned structured, cited results for five SQL injection cases.
- The limited Analyst–Skeptic–Chair workflow has been exercised on those same five cases.
- The deterministic validator rejects malformed JSON and unsupported file, line, or quote citations in its self-tests.

This demonstrates integration feasibility, not final accuracy. The next checkpoint work is to connect the complete demonstration path and evaluate approximately 100 findings with a documented baseline, metrics, failures, and limitations.

## Safety and privacy

- Do not commit API keys, `.env` files, downloaded benchmark data, generated model responses, restricted course material, or files marked local-only in `Context/README.md`.
- Treat model output, scanner output, retrieved text, and source-code content as untrusted data.
- The online scripts include conservative budget checks, but the person running them is responsible for confirming the intended account and spend.
- Do not describe the five-case smoke test as proof of general system accuracy.

## Project context

The main planning document is [CHECKPOINT_BRIEF.md](checkpoint/CHECKPOINT_BRIEF.md). It records the checkpoint requirements, what is currently verified, what remains incomplete, and the questions the team should agree on before implementation continues.
