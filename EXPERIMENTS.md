# TriageBot experiments

This is the single source of truth for TriageBot's evaluation. Each experiment
below asks one question, changes one group of settings, and is measured on
one frozen set of cases. Every run is saved with a record of exactly what
produced it, and can be shown and re-scored from the terminal for free.

Earlier results (`FINAL_RESULTS.md`, `IMPROVEMENT_EXPERIMENT_LOG.md`) record
runs made before this plan. They are kept for the record and are superseded by
this document (see [Earlier runs](#earlier-runs)).

## Framing

Scoped to the OWASP Benchmark's categories for this proof of concept; built to
generalise, measured on four injection categories.

The four categories are path traversal (CWE-22), command injection (CWE-78),
cross-site scripting (CWE-79) and SQL injection (CWE-89). Nothing in TriageBot
is specific to them: the scanner, the evidence builder, the prompts and the
validator work the same way for any alert. They were chosen because the
Benchmark has enough cases of each to measure on.

## Why we split the cases

TriageBot trains no model, but people tune it: we read the cases it gets wrong
and change its prompts, evidence and settings. A change made after reading a
case tends to fix that case. Measured on the same cases, it then looks better
than it really is. This is the same overfitting that a held-out test set
prevents in machine learning, caused by human tuning instead of training. So
the cases we read and tune on are kept apart from the cases we report.

## The case sets

All sets come from the recorded Semgrep scan and the fixed development/test
split (seed 201; half of each category and label in each part). Each case has
exactly one Semgrep alert that names the case's weakness, and each set is half
real vulnerabilities and half safe code. The files and their build rules are in
[data/samples/](data/samples/README.md).

| Set | Half | Cases | Composition | Rule | Fingerprint (SHA-256) |
| --- | --- | ---: | --- | --- | --- |
| `pilot` | development | 100 | CWE-89: 50 real, 50 safe | Exactly the checkpoint sample; the builder checks it against `evidence/checkpoint-100/` | `2b633145f724…` |
| `comparison` | development | 96 | CWE-22, 78, 79, 89: 24 each (12 real, 12 safe) | Excludes every pilot case | `311c5e73b3e9…` |
| `final-test` | test | 120 | CWE-22, 78, 79, 89: 30 each (15 real, 15 safe) | Excludes every retired case | `3182ce45723d…` |
| retired | both | 407 | Case IDs only | Every case used by an earlier run | — |
| mutation | — | — | — | Planned (step 5, later task) | — |

- The **exploration set** is the pilot plus any other development case. This
  is where we read failures and try ideas.
- The **comparison set** is frozen and only measured, never tuned on.
- The **final test** is run once, after the code freeze.
- **Retired** cases were used by earlier runs and are kept only as a record.

Full fingerprints are in each `data/samples/<set>.manifest.json` and in
[data/samples/README.md](data/samples/README.md). A run refuses to start if its
set no longer matches its fingerprint.

## The profiles

A profile is one named group of settings (`triagebot/profiles.py`). Each step
switches from one profile to the next, so exactly one group changes.

| Setting | `base` | `evidence` | `worksheet` | `semantic` |
| --- | --- | --- | --- | --- |
| Source window, lines either side of the alert | 25 | 60 | 60 | 60 |
| Related source (other files, called methods, referenced scripts) | off | on | on | on |
| Reasoning worksheet (`analysis` field) and consistency repair | off | off | on | on |
| Guidance retrieval | `map` | `map` | `map` | `semantic` |

What each setting means:

- **Source window:** how many lines of the alert's own file, either side of
  the flagged line, the AI is shown.
- **Related source:** with it on, TriageBot also shows the bodies of methods
  the window calls, project files the code references, and scripts those files
  name. With it off, the AI sees the window only.
- **Reasoning worksheet:** with it on, the AI must fill in a short structured
  analysis (where the input comes from, the dangerous operation, whether the
  input reaches it, any protection, whether that protection works) and its
  verdict must agree with it. A verdict that contradicts it gets one repair
  call; a repair that still contradicts it becomes "needs a human". With it
  off, the field is neither asked for nor allowed, and no repair happens.
- **Guidance retrieval:** `map` picks OWASP cheat-sheet sections through a
  hand-made table from weakness (CWE) to cheat sheet. `semantic` ranks every
  section by meaning against the official MITRE description of the alert's
  weakness (design decision 21).

**On in every profile** (engineering fixes, not experiments): strict JSON
schema output; guidance-label normalisation in the validator; the LangGraph
council. The per-type checklists are **off in every profile** (removed; see
[What we removed and why](#what-we-removed-and-why)).

## How a run is recorded

`python -m triagebot experiment run <step>` prints the case set, profile,
modes, number of model calls and an estimated cost, and asks before making
any paid call. It saves each case as soon as it finishes, so an interrupted
run resumes where it stopped. Each run writes
`evidence/experiments/<step>-<side>[-repeat-N]/`:

| File | What it holds |
| --- | --- |
| `results.jsonl` | One line per finished case: every role's report and the final verdict (no labels) |
| `B-single-agent.json`, `C-council.json`, `D-validated-council.json` | The saved verdicts in the evaluator's format (B single agent, C raw council, D council after the deterministic validator) |
| `evaluation.json`, `evaluation_by_cwe.json` | The scores, overall and per weakness |
| `run_manifest.json` | Profile and every setting, case set and fingerprint, model, temperature, Git commit and whether the code had uncommitted changes, start and end time, total cost and tokens, failed calls |
| `report.md` | A short plain-English report with the results table and the commands to replay it |

Three commands, for any step:

| Command | Cost | Needs |
| --- | --- | --- |
| `python -m triagebot experiment show <step>` | free | nothing (offline; no API key, no answer key) |
| `python -m triagebot experiment replay <step>` | free | the Benchmark answer key; makes no model calls |
| `python -m triagebot experiment run <step>` | paid | API key, Benchmark; asks first |

The same is in the menu (`python -m triagebot`, option 4). `--limit N` runs
only the first N cases (a smoke test); a later run without `--limit` continues
the same folder. To start a run again from nothing, delete its folder.

**Reading the numbers.** Precision is the share of the cases TriageBot keeps
that are real vulnerabilities; recall is the share of real vulnerabilities it
keeps. A case sent to a human counts as kept, because a human still sees it.
"Real vulnerabilities dismissed" is the most serious failure: a real problem
marked as a false alarm. Costs are the provider's reported cost in US dollars.

## The six steps

| Step | Question | Before | After | Case set |
| --- | --- | --- | --- | --- |
| 1 | Does a council beat one agent? | `base` profile, single agent | `base` profile, council (run twice to measure the noise between identical runs) | comparison |
| 2 | Does showing the AI more of the code help? | step 1 council | `evidence` profile, council | comparison |
| 3 | Does a reasoning worksheet with a consistency check help? | step 2 | `worksheet` profile, council | comparison |
| 4 | Does semantic retrieval hold up? | step 3 | `semantic` profile, council | comparison |
| 5 | Does the verdict follow the code? | rebuilt mutation test (later task) | | mutation |
| 6 | Headline result | final profile, single agent and council, run once (later task) | | final test |

Cost estimates use US$0.004 per case for the single agent and US$0.016 per
case for the council (`config.EXPERIMENT_COST_PER_CASE`). The real spend is
recorded in each run manifest.

### Step 1: Does a council beat one agent?

- **Question:** with the same evidence, does the Analyst / Skeptic / Chair
  council make better decisions than one agent?
- **Before:** `base` profile, single agent (run `1-before`).
- **After:** `base` profile, council (runs `1-after` and `1-after-repeat-2`).
  The council is run twice with identical settings; the difference between the
  two runs is the noise between identical runs, the yardstick for every later
  difference.
- **Case set:** comparison (96 cases).
- **Cost estimate:** before 96 calls, about US$0.38; after 288 calls per run,
  about US$1.54, twice: about US$3.46 in all.
- **Status:** not run yet.
- **Commands:**
  - show: `python -m triagebot experiment show 1`
  - replay: `python -m triagebot experiment replay 1`
  - re-run: `python -m triagebot experiment run 1` (both sides), then
    `python -m triagebot experiment run 1 --side after --repeat 2`
- **Result:** _to be filled in after the run._
- **Finding:** _to be filled in after the run._

### Step 2: Does showing the AI more of the code help?

- **Question:** does a wider source window, plus the code the alert's code
  calls or refers to, lead to better decisions?
- **Before:** step 1's council run `1-after`, reused at no cost.
- **After:** `evidence` profile, council (run `2-after`).
- **Case set:** comparison (96 cases).
- **Cost estimate:** 288 calls, about US$1.54.
- **Status:** not run yet.
- **Commands:**
  - show: `python -m triagebot experiment show 2`
  - replay: `python -m triagebot experiment replay 2`
  - re-run: `python -m triagebot experiment run 2`
- **Result:** _to be filled in after the run._
- **Finding:** _to be filled in after the run._

### Step 3: Does a reasoning worksheet with a consistency check help?

- **Question:** does asking for a structured analysis, and repairing verdicts
  that contradict it, lead to better decisions?
- **Before:** step 2's run `2-after`, reused.
- **After:** `worksheet` profile, council (run `3-after`).
- **Case set:** comparison (96 cases).
- **Cost estimate:** 288 calls, about US$1.54, plus up to 96 repair calls.
- **Status:** not run yet.
- **Commands:**
  - show: `python -m triagebot experiment show 3`
  - replay: `python -m triagebot experiment replay 3`
  - re-run: `python -m triagebot experiment run 3`
- **Result:** _to be filled in after the run._
- **Finding:** _to be filled in after the run._

### Step 4: Does semantic retrieval hold up?

- **Question:** can semantic retrieval from the official CWE text replace the
  hand-made weakness-to-cheat-sheet table without losing accuracy?
- **Before:** step 3's run `3-after`, reused.
- **After:** `semantic` profile, council (run `4-after`).
- **Case set:** comparison (96 cases).
- **Cost estimate:** 288 calls, about US$1.54, plus up to 96 repair calls.
  Preparation is free and local, once:
  `python -m triagebot.nodes.context.cwe_catalogue` (MITRE catalogue) and
  `python -m triagebot.nodes.context.vector_store` (embeds the knowledge base).
  The run stops with these commands if either is missing.
- **Status:** not run yet.
- **Commands:**
  - show: `python -m triagebot experiment show 4`
  - replay: `python -m triagebot experiment replay 4`
  - re-run: `python -m triagebot experiment run 4`
- **Result:** _to be filled in after the run._
- **Finding:** _to be filled in after the run._

#### The step 4 rule, agreed in advance

If semantic retrieval holds or improves accuracy on the comparison set, it is
reported as an improvement. If not, it remains the design choice, argued on
scalability and maintainability, and the slide states the accuracy difference
plainly. Any tuning of its set-up happens on exploration cases only, followed
by one measurement on the comparison set.

### Step 5: Does the verdict follow the code?

- **Question:** when a case's code is changed so that its answer should flip
  (safe becomes vulnerable, or the reverse), does TriageBot's verdict flip too?
- **Before / after:** a rebuilt mutation test; built in a later task.
- **Case set:** mutation (planned).
- **Cost estimate:** set when the mutation set is built.
- **Status:** not run yet (planned; not runnable until the mutation set exists).
- **Commands:** `python -m triagebot experiment show 5` lists it as planned.
- **Result:** _to be filled in after the run._
- **Finding:** _to be filled in after the run._

### Step 6: Headline result

- **Question:** how well does the final system do on cases it has never seen?
- **Run:** the final profile chosen by steps 1 to 4, single agent and council,
  run once after the code freeze; nothing is changed after it.
- **Case set:** final test (120 cases).
- **Cost estimate:** 480 calls, about US$2.40.
- **Status:** not run yet (planned; runnable in a later task).
- **Commands:** `python -m triagebot experiment show 6` lists it as planned.
- **Result:** _to be filled in after the run._
- **Finding:** _to be filled in after the run._

## What we removed and why

**The per-type checklists.** Until this plan, the prompt added a short
checklist for command injection (CWE-78) and LDAP injection (CWE-90). Both
were written after reading specific cases the system had got wrong. That
tunes the prompt to the cases it is measured on, which is exactly what the
case split is meant to prevent, and a checklist per weakness would not scale
to the hundreds of weaknesses outside the Benchmark. They are removed in every
profile (design decision 25). Any later per-type guidance has to come from the
retrieved OWASP material, not from hand-written notes about failed cases.

## Earlier runs

The old samples and results under `evidence/` are archived:

- `checkpoint-100/`: the checkpoint run (the pilot's 100 SQL-injection cases);
- `original-final-120/`: the first frozen 120-case final evaluation;
- `comparison-66/`: the 66-case improvement comparison and its re-runs;
- `fresh-120/`: the second 120-case evaluation.

They changed several things at once and were not recorded as one change per
run. Their cases are retired (`data/samples/retired_cases.json`, 407 cases),
and they are not used for any new claim. `FINAL_RESULTS.md` and
`IMPROVEMENT_EXPERIMENT_LOG.md` describe them and stay unchanged apart from a
note at the top.
