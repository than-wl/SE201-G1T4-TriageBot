# SE201 G1T4 — TriageBot

[![tests](https://github.com/than-wl/SE201-G1T4-TriageBot/actions/workflows/tests.yml/badge.svg)](https://github.com/than-wl/SE201-G1T4-TriageBot/actions/workflows/tests.yml)

## 1. What TriageBot is

A static-analysis scanner such as Semgrep flags code that *might* be
vulnerable, and many of its alerts are false alarms that a developer must still
read. TriageBot is a second stage after the scanner: for each alert it gathers
the code and security guidance that decide the answer, and an AI council
sorts the alert into **likely a real vulnerability**, **likely a false alarm**
or **needs a human**. Every verdict must quote the source it relies on, and
deterministic code checks those quotes. TriageBot never adds alerts, so the
scanner's recall is its ceiling.

[Architecture diagram](docs/architecture/README.md) (editable Mermaid source:
[docs/architecture/TriageBot_Architecture_Diagram.mmd](docs/architecture/TriageBot_Architecture_Diagram.mmd)).

## 2. Results

All current results are in **[EXPERIMENTS.md](EXPERIMENTS.md)**, the single
source of truth: what each experiment asked, what changed, and every number.
They were measured on the OWASP Benchmark (Java) for four weakness types: path
traversal (CWE-22), OS command injection (CWE-78), cross-site scripting (CWE-79)
and SQL injection (CWE-89). Gemini 3.8 Flash, temperature 0.

**Council vs single agent on 120 unseen cases** (step 7, runs `6-before` and
`6-after`, run once after the code freeze):

| | Single agent | Council (validated) |
| --- | ---: | ---: |
| Precision / recall / F1 | 94.3% / 83.3% / 88.5% | 95.2% / 98.3% / **96.7%** |
| Real vulnerabilities dismissed (of 60) | 10 | **1** |
| False alarms removed (of 60) | 57 | 57 |
| Sent to a human (of 120) | 2 | 1 |
| Cost (US$) / mean latency (s) | 0.53 / 9.9 | 1.76 / 18.8 |

**Whole system vs Semgrep alone** (a projection of step 7 over the whole
benchmark for the four types; `evidence/whole_system/6-after.md`): precision
59.6% → **97.1%**, recall 86.0% → 85.0%, false alarms left 453 → about 20. Of
the about 117 real vulnerabilities still missed, 109 are ones Semgrep never
flagged: Semgrep is now the bottleneck.

**Does the verdict follow the code?** (step 6, runs `5-before` and `5-after`):
in 22 pairs, one character was changed so that the right answer flipped while
Semgrep's alert stayed the same. Mutation score: council **100%** (22 of 22),
single agent 53% (8 of the 15 it got right to begin with).

**Semantic retrieval** (step 5, run `4-after`): guidance found by search,
anchored on each weakness's MITRE record, held accuracy within the noise floor
(F1 95.0% vs 96.0%) and needs no hand-written weakness-to-guidance table.

**Semgrep alone, all categories** (a different scope: all 2,740 Benchmark cases
across all 11 categories, `p/java`, CWE-matched): precision 65.5%, recall
68.6%, F1 67.0%. Menu option 1 shows it.

Earlier runs (the checkpoint, the first and second 120-case evaluations, the
66-case comparison) are superseded and kept in [archive/](archive/README.md).

## 3. Quick start

Tested with Python 3.12.7 on Windows 11. Run every command from the repository
root.

**1. Python and a virtual environment.** Python 3.10 or newer, and
[Git](https://git-scm.com/downloads).

```bash
git clone https://github.com/than-wl/SE201-G1T4-TriageBot.git
cd SE201-G1T4-TriageBot
```

| Windows (PowerShell) | macOS / Linux |
| --- | --- |
| `py -m venv .venv` | `python3 -m venv .venv` |
| `.\.venv\Scripts\Activate.ps1` | `source .venv/bin/activate` |
| `python -m pip install -r requirements.txt` | `python -m pip install -r requirements.txt` |

Activate the environment again in every new terminal. From here on, `python`
means the venv's Python.

**2. The API key (only for paid runs).** Copy `.env.example` to `.env` and set
your own `OPENROUTER_API_KEY` there. Never commit `.env`; it is git-ignored.
Every free command below works without it.

**3. The OWASP Benchmark** (about 100 MB, at the pinned commit, in
`Context/tmp/BenchmarkJava`):

```bash
git clone https://github.com/OWASP-Benchmark/BenchmarkJava.git Context/tmp/BenchmarkJava
```

```bash
git -C Context/tmp/BenchmarkJava checkout 8b67a88d73b2594570fc21150705283de884620b
```

The menu's setup check also offers to clone it for you.

**4. Prepare the guidance retrieval (once; free and local, no model calls):**

```bash
python -m triagebot.nodes.context.cwe_catalogue
```

```bash
python -m triagebot.nodes.context.vector_store
```

The first downloads the MITRE CWE catalogue (SHA-256 checked). The second
downloads the embedding model and builds the local vector store: **the first
build takes several minutes and prints nothing until it finishes.** Both write
only to the git-ignored `Context/tmp/`.

**5. Open the menu:**

```bash
python -m triagebot
```

| Option | What it does |
| --- | --- |
| 1 Scanner baseline | Semgrep alone over the whole benchmark (free) |
| 2 Triage one alert | One case through the single agent or the council (paid) |
| 3 Evaluate a sample | The checkpoint sample through each configuration, scored (paid; asks first) |
| 4 Experiments | Every step of EXPERIMENTS.md: show, replay (free) or run (paid; asks first) |

**6. Check the set-up** (Python, venv, Benchmark and its commit, the scan, the
case sets), with the fix for anything missing:

```bash
python -m triagebot check
```

## 4. Runnable examples

**Free** (no model calls, no API key):

```bash
python -m triagebot experiment list
```

```bash
python -m triagebot experiment show 7
```

```bash
python -m triagebot experiment replay 5
```

```bash
python -m triagebot.nodes.context.retrieval --explain CWE-22 --setup improved
```

```bash
python -m triagebot.nodes.context.retrieval --explain CWE-22 --setup original
```

```bash
python verification/whole_system.py --mode council
```

```bash
python verification/semantic_setup_check.py --phase score
```

```bash
python -m triagebot baseline
```

- `experiment show <step>` prints a step's before/after table from the saved
  results and needs nothing else. `experiment replay <step>` re-scores the
  saved verdicts against the Benchmark answer key and checks they equal the
  committed report. Steps 1 to 7, in story order (`experiment list`); run
  folders keep their internal IDs ([Step numbers](EXPERIMENTS.md#step-numbers)).
  `experiment show 7 --by-cwe` adds the table per weakness.
- `--explain` shows the guidance one weakness gets: `improved` is the final
  set-up, `original` the first one (all five set-up rules off). It needs step
  4 of the quick start.
- `whole_system.py` (`--mode council` or `single`) and `semantic_setup_check.py
  --phase score` recompute their reports from committed data and rewrite them
  under `evidence/`; only the date and commit lines change.
- `baseline` is menu option 1.

**Paid** (OpenRouter calls; needs the API key):

```bash
python -m triagebot experiment run 5
```

Before any call it prints the case set, the number of calls and the estimated
cost, and asks for confirmation. It saves each case as it finishes, so an
interrupted run resumes. Step 7 is the final test and is guarded: it refuses
uncommitted changes and refuses a second run.

All subcommands: `python -m triagebot --help`.

## 5. Where things are

```text
triagebot/       the product: one folder per pipeline stage under nodes/, the CLI, profiles, experiments
experiments/     the experiment step registry (registry.json)
data/samples/    the frozen case sets (label-free) and their fingerprints
data/semgrep/    the recorded Semgrep scan everyone scores
evidence/        every experiment run, the retrieval check and the whole-system projection
verification/    free checks: retrieval quality, whole system vs Semgrep, feasibility scripts
tests/           offline tests (no network, no API key)
docs/            design decisions, architecture diagram, proposal, feasibility reports
ai-log/          each member's AI-use log
archive/         superseded runs and documents, kept as the record
```

## 6. How it works

- **Evidence pack.** For each alert TriageBot builds what the AI sees: ±60 lines
  of the alert's file, the methods that code calls, the project files and
  scripts it references, and security guidance. The guidance is found by
  semantic search over the OWASP Cheat Sheet Series, anchored on the alert's
  MITRE CWE record, which is attached first (design decisions 28 and 29). An
  alert with no valid CWE goes to human review. The answer key never reaches a
  prompt.
- **Council.** An Analyst and a Skeptic review the evidence in parallel, and a
  Chair weighs both reports and decides (`triagebot/council_graph.py`, on
  LangGraph). The single agent is the plain-Python baseline it is compared with.
- **Deterministic validator.** Every verdict must cite exact file, line and
  quoted text from the evidence; malformed output or a citation that does not
  match becomes "needs a human" (`triagebot/nodes/validate/`).
- **Durable sessions.** `council-start`, `council-status` and `council-resume`
  save a council run to a local SQLite file (`.triagebot/checkpoints.sqlite`,
  git-ignored) so it can be resumed after a crash. Resuming an unfinished run
  needs `--allow-replay`, because a call may be billed twice. The file holds
  source excerpts and model reports; do not share it.

Settings live in `triagebot/config.py` and the experiment profiles in
`triagebot/profiles.py`. The reasoning behind each choice is in
[docs/DESIGN_DECISIONS.md](docs/DESIGN_DECISIONS.md).

Run the tests (offline; CI runs them on Windows, macOS and Linux):

```bash
python -m unittest discover -s tests
```

## 7. Troubleshooting

- **The vector-store build prints nothing for minutes:** expected on the first
  build (it embeds the whole knowledge base). Later builds embed only what
  changed.
- **Loading the embedding model hangs** (after the first download): set
  `HF_HUB_OFFLINE=1` (PowerShell: `$env:HF_HUB_OFFLINE = "1"`) and run again, so
  it uses the downloaded copy without contacting Hugging Face.
- **Ctrl+C during a run:** safe. Each case is saved as it finishes, and the
  next `experiment run` resumes where it stopped.
- **Output stops in a Windows terminal:** clicking in the window selects text
  and pauses the program. Press Esc to continue.
- **"No module named rich", or no `(.venv)` in the prompt:** activate the
  environment (`.\.venv\Scripts\Activate.ps1` or `source .venv/bin/activate`).
- **PowerShell: "running scripts is disabled on this system":** run
  `Set-ExecutionPolicy -Scope Process RemoteSigned`, then activate again.
- **"detached HEAD" after the Benchmark checkout:** expected; it is at the
  pinned commit.
- **macOS: "TriageBot needs Python 3.10 or newer":** the built-in `python3` is
  too old. Install a newer one (python.org or `brew install python@3.12`),
  delete `.venv` and create it again.
- **Semgrep fails to install:** only re-scans need it; TriageBot scores the
  recorded scan in `data/semgrep/`.

## 8. Responsible AI and safety

The risk register, mitigations, residual risks and the human-oversight rule are
in [RESPONSIBLE_AI_RISK_ASSESSMENT.md](RESPONSIBLE_AI_RISK_ASSESSMENT.md).

- TriageBot is decision support. A qualified reviewer must check the cited
  code before any finding is suppressed.
- It cannot recover what Semgrep missed, and a validated citation proves the
  quote exists, not that the reasoning is right: in step 5 all three reviewers
  dismissed one real vulnerability with a plausible but incomplete argument.
- The answer key is read only by the evaluation code, after the model calls.
- Source code, scanner output, retrieved text and model output are treated as
  untrusted data.
- Never commit API keys, `.env`, the Benchmark checkout or anything under
  `Context/` other than its README and `.gitignore`.

**AI use disclosure.** Each member keeps a log in `ai-log/<name>.md`, and
AI-assisted commits carry an `Assisted-by:` trailer. The consolidated record is
[AI_USE_DISCLOSURE.md](AI_USE_DISCLOSURE.md); see also design decision 16.

## 9. Team and roles

| Member | Responsibilities |
| --- | --- |
| Darren | Semgrep integration, alert normalisation, benchmark mapping and split |
| Hong Yi | Shared contracts, retrieval knowledge base, context payload, review roles |
| Lisa | Deterministic validator |
| Bradley | Evaluation harness, checkpoint report |
| Wei Lin | Repository setup, integration, submission |

## 10. Third-party content

- **OWASP Cheat Sheet Series** (the guidance knowledge base): CC BY-SA 4.0; see
  [triagebot/nodes/context/kb/README.md](triagebot/nodes/context/kb/README.md).
- **MITRE CWE** (semantic retrieval quotes a weakness's description and
  mitigations, and searches with its name and alternate terms): © The MITRE
  Corporation, used under the CWE Terms of Use reproduced in
  [triagebot/nodes/context/MITRE_CWE_NOTICE.md](triagebot/nodes/context/MITRE_CWE_NOTICE.md).
