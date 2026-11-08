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

## Results so far, in story order

This section is the narrative for the presentation. The step numbers are the
order the experiments were defined in; the story below reads them in the order
that explains them best. All results are on the frozen 96-case comparison set
(4 types × 24, half real, half safe), Gemini 3.8 Flash at temperature 0.

**The noise floor.** The base council was run twice with identical settings.
The two runs differed on 1 case of 96 (sent to a human: 31 vs 32) and on
nothing else. A difference of 2 or more cases, especially in real
vulnerabilities dismissed, is therefore more than run-to-run noise.

| Run | Reviewer | Evidence | F1 | Real vulnerabilities dismissed (of 48) | False alarms removed (of 48) | Sent to a human (of 96) | Cost (US$) | Mean latency (s) |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `1-before` | single agent | ±25 lines | 81.1% | 3 | 30 | 32 | 0.35 | 11.0 |
| `1-after` | council | ±25 lines | 82.9% | 2 | 31 | 31 | 1.07 | 20.2 |
| `1-after-repeat-2` | council (identical rerun) | ±25 lines | 82.9% | 2 | 31 | 32 | 1.07 | 21.0 |
| `1b-before` | single agent | ±60 lines + related code | 93.8% | 3 | 45 | 4 | 0.41 | 11.1 |
| `2-after` | council | ±60 lines + related code | 96.0% | 0 | 44 | 4 | 1.37 | 20.9 |
| `1c-before` | single agent | + worksheet | 91.5% | 5 | 45 | 3 | 0.47 | 11.4 |
| `3-after` | council | + worksheet | 96.0% | 0 | 44 | 3 | 1.48 | 21.4 |

Precision, recall and F1 count a case sent to a human as kept. Council figures
are the same before and after the deterministic validator, except one answer
the validator rejected in `2-after` (sent to a human either way).

**1. With little code, the reviewer design makes no difference (step 1).** At
±25 lines the council and the single agent reached the same verdict on 94 of 96
cases. Both sent about a third of all cases to a human, and path traversal was
worst: 15 of 24 cases escalated by either reviewer. The AI could not see the
code that decides the answer, and three reviewers cannot make up for that.

**2. Showing the AI the code it needs is the largest gain (step 2).** With ±60
lines plus the methods, files and scripts the code refers to, the council's F1
rose from 82.9% to 96.0%, cases sent to a human fell from 31 to 4, and false
alarms removed rose from 31 to 44 of 48. The single agent improved the same way
(81.1% to 93.8%). The extra evidence cost about 29% more per run.

**3. Once the AI has the code, the council's value is safety (step 1b).** With
the same evidence, both reviewers removed about the same number of false alarms
(44 vs 45), but the council dismissed 0 real vulnerabilities against the single
agent's 3. In the cases where they differed, the Analyst and Skeptic disagreed
and the Chair kept the alert, or the Chair overruled two specialists who both
called a real vulnerability a false alarm. The Chair leans towards keeping an
alert when in doubt, which once kept a safe case too. The Analyst and Skeptic
disagreed on only 2 to 4 cases per run, so the council matters on few cases,
but those are the dangerous ones. The price is about 3× the cost and 2× the
latency of a single agent.

**4. The reasoning worksheet adds nothing measurable (steps 3 and 1c).** For the
council nothing changed beyond the noise floor (sent to a human 4 to 3). For the
single agent, real vulnerabilities dismissed went from 3 to 5. The worksheet
worked as designed: every answer filled in all of its fields, and every verdict
agreed with its worksheet, so the consistency repair never fired. It had
nothing to catch. The "reasoned right, labelled wrong" problem it was built for
was seen in earlier runs with less code; with enough evidence it did not occur.
The worksheet was therefore dropped from the final version (design decision 27).

**Next:** step 4 replaces the hand-made guidance table with semantic retrieval,
on top of step 2's version; step 5 rebuilds the mutation test; step 6 runs the
final version once on the unseen final test, and reports the whole system next
to Semgrep alone to show how far Semgrep's recall limits it.

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
| Reasoning worksheet (`analysis` field) and consistency repair | off | off | on | off |
| Guidance retrieval | `map` | `map` | `map` | `semantic` |
| Semantic set-up (rules R1 to R5) | — | — | — | improved: all five on |

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
  hand-made table from weakness (CWE) to cheat sheet. `semantic` ranks
  sections by meaning against the official MITRE description of the alert's
  weakness (design decision 21).
- **Semantic set-up:** five rules that decide how semantic retrieval builds
  the guidance (design decision 28; see
  [step 4](#semantic-retrieval-set-up-fixed-before-measuring)). The `semantic`
  profile turns all five on. The other profiles use `map`, which ignores them.

**On in every profile** (engineering fixes, not experiments): strict JSON
schema output; guidance-label normalisation in the validator; the LangGraph
council; an output token limit of 2,000. The limit was raised from 900 after the
step 1 smoke test: the model's hidden reasoning counts against it, and one call
spent 746 of 900 tokens reasoning, so its answer was cut off and became a failed
call. Only tokens actually generated are billed. The per-type checklists are **off in every profile** (removed; see
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
| 4 | Does semantic retrieval hold up? | step 2 (the worksheet was dropped after step 3) | `semantic` profile, council | comparison |
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
- **Status:** run on 8 Nov 2026.
- **Commands:**
  - show: `python -m triagebot experiment show 1`
  - replay: `python -m triagebot experiment replay 1`
  - re-run: `python -m triagebot experiment run 1` (both sides), then
    `python -m triagebot experiment run 1 --side after --repeat 2`
- **Result:** single agent F1 81.1%, 3 real vulnerabilities dismissed, 30 of 48 false alarms removed, 32 of 96 sent to a human; council 82.9%, 2, 31, 31; council rerun 82.9%, 2, 31, 32. Same verdict on 94 of 96 cases.
- **Finding:** with ±25 lines the reviewer design makes no difference; both lack the code that decides the answer. The two identical council runs differ by 1 case: the noise floor.

### Steps 1b and 1c: does the council's value depend on the evidence?

Added after step 1's first council run (8 Nov). At the `base` profile the
council and the single agent reached the same verdict on 94 of 96 cases, while
an earlier run with 60 lines of code had shown a clear council advantage. So
the council-versus-single comparison is repeated at the next two profiles,
reusing the council runs of steps 2 and 3 and adding only a single-agent run
for each.

| Step | Before (new run) | After (reused) |
| --- | --- | --- |
| 1b | `evidence` profile, single agent (run `1b-before`) | step 2 council (`2-after`) |
| 1c | `worksheet` profile, single agent (run `1c-before`) | step 3 council (`3-after`) |

- **Question:** does the council beat one agent once the AI sees more of the
  code, and once it also fills in the reasoning worksheet?
- **Case set:** comparison (96 cases).
- **Cost estimate:** 96 single-agent calls each, about US$0.38 each.
- **Status:** run on 8 Nov 2026.
- **Commands:** `python -m triagebot experiment show 1b` (or `1c`);
  `python -m triagebot experiment run 1b --side before` (or `1c`).
- **Result:** with more code, single agent F1 93.8% with 3 real vulnerabilities dismissed vs council 96.0% with 0; with the worksheet too, single agent 91.5% with 5 dismissed vs council 96.0% with 0. False alarms removed: 45 vs 44 in both.
- **Finding:** once the AI has the code, the council removes no more false alarms than one agent, but it stops real vulnerabilities being dismissed, for about 3× the cost and 2× the latency.

### Step 2: Does showing the AI more of the code help?

- **Question:** does a wider source window, plus the code the alert's code
  calls or refers to, lead to better decisions?
- **Before:** step 1's council run `1-after`, reused at no cost.
- **After:** `evidence` profile, council (run `2-after`).
- **Case set:** comparison (96 cases).
- **Cost estimate:** 288 calls, about US$1.54.
- **Status:** run on 8 Nov 2026.
- **Commands:**
  - show: `python -m triagebot experiment show 2`
  - replay: `python -m triagebot experiment replay 2`
  - re-run: `python -m triagebot experiment run 2`
- **Result:** council F1 82.9% → 96.0%; real vulnerabilities dismissed 2 → 0; false alarms removed 31 → 44 of 48; sent to a human 31 → 4 of 96; cost US$1.07 → 1.37.
- **Finding:** the largest gain of any step. Most uncertainty came from missing code, not weak reasoning.

### Step 3: Does a reasoning worksheet with a consistency check help?

- **Question:** does asking for a structured analysis, and repairing verdicts
  that contradict it, lead to better decisions?
- **Before:** step 2's run `2-after`, reused.
- **After:** `worksheet` profile, council (run `3-after`).
- **Case set:** comparison (96 cases).
- **Cost estimate:** 288 calls, about US$1.54, plus up to 96 repair calls.
- **Status:** run on 8 Nov 2026.
- **Commands:**
  - show: `python -m triagebot experiment show 3`
  - replay: `python -m triagebot experiment replay 3`
  - re-run: `python -m triagebot experiment run 3`
- **Result:** council unchanged (F1 96.0%, 0 dismissed, 44 removed; sent to a human 4 → 3). Every answer filled in the worksheet and agreed with it; the repair never fired.
- **Finding:** no measurable benefit once the AI has enough code, and the single agent dismissed more real vulnerabilities with it (3 → 5). Dropped from the final version (design decision 27).

### Step 4: Does semantic retrieval hold up?

- **Question:** can semantic retrieval from the official CWE text replace the
  hand-made weakness-to-cheat-sheet table without losing accuracy?
- **Before:** step 2's run `2-after`, reused. The worksheet from step 3 is not
  carried forward (design decision 27), so step 4 changes only the retrieval.
- **After:** `semantic` profile, council (run `4-after`).
- **Case set:** comparison (96 cases).
- **Cost estimate:** 288 calls, about US$1.40.
  Preparation is free and local, once:
  `python -m triagebot.nodes.context.cwe_catalogue` (MITRE catalogue) and
  `python -m triagebot.nodes.context.vector_store` (embeds the knowledge base).
  The run stops with these commands if either is missing.
- **Status:** set-up fixed; not yet measured.
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

#### Semantic retrieval set-up (fixed before measuring)

Step 4 asks whether semantic retrieval can replace the hand-made table. The
case for it is scale: the table covers only the weaknesses someone wrote down,
while the MITRE catalogue covers every CWE. Because the comparison set is
measured once per configuration (design decision 26), the set-up was fixed
first, by rules stated in advance and without looking at any comparison-set or
final-test case. The rules come from the team's investigation of decision 21's
set-up (design decision 28).

| Setting | Before (decision 21) | Now | Why |
| --- | --- | --- | --- |
| R1 Query | MITRE name and description | Name, alternate terms ("Also known as: …"), description | The official name misses the words the cheat sheets use, such as "XSS" or "path traversal" |
| R2 MITRE text | Used only as the query | MITRE description and mitigations attached first, looked up by CWE ID (at most 1,500 characters) | Every known CWE gets authoritative guidance, even one the OWASP sheets do not cover |
| R3 Sheets searched | All 137 | 116: retired sheets, the attack-string catalogue and sheets for other platforms left out | These outranked guidance that applies to Java; one setting, `KB_TARGET_PLATFORM`, switches platform |
| R4 Chunk size | Up to 11,744 characters | Chunks over 1,800 characters split into pieces | The embedding model reads only about the first 512 tokens; one huge chunk could fill the whole budget |
| R5 Grounding gate | A chunk scores at least 0.0 (always true) | The CWE has a valid, non-deprecated MITRE record | A score threshold cannot separate relevant from irrelevant chunks here; a record either exists or not |

The guidance budget is unchanged (4,000 characters, at most 6 chunks), because
step 4 is compared with `2-after`. In numbers: R3 leaves out 21 sheets (4
retired, 1 attack catalogue, 16 for other platforms; 533 chunks); R4 splits 214
chunks into 447 pieces. The improved set-up searches 2,886 chunks.

**How a guidance pack is built**

1. Look up the alert's CWE in MITRE; with no valid record, the alert goes to
   human review.
2. Put the MITRE summary and mitigations first.
3. Search the in-scope OWASP sheets using the name, alternate terms and
   description.
4. Fill up to 4,000 characters.

**See it for one CWE** (no model calls; only the local embedder):

```bash
python -m triagebot.nodes.context.retrieval --explain CWE-89 --setup improved
python -m triagebot.nodes.context.retrieval --explain CWE-89 --setup original
```

It prints the query, whether the CWE is grounded and why, the start of the
MITRE chunk, the guidance returned (rank, chunk, cosine score, characters,
running total) and the next five results that did not fit. `original` is all
five rules off (decision 21); `improved` is the `semantic` profile.

In semantic mode the prompt labels the guidance block "Retrieved guidance
(MITRE CWE and OWASP Cheat Sheet Series)"; map-mode prompts are unchanged,
byte for byte.

**What the set-up changes** (`--explain`, 9 Nov; CWE catalogue 5.0):

| CWE | Original set-up | Improved set-up |
| --- | --- | --- |
| 89, SQL injection | 2 chunks, 2,256 of 4,000 chars: Injection Prevention, Query Parameterization | MITRE record (1,343 chars) + Injection Prevention: 2,965 chars. FastAPI (Python) no longer in the next five |
| 22, path traversal | 3 chunks, 3,357 chars: File Upload + **two Laravel (PHP) chunks**; Symfony and C toolchain next | MITRE record (1,290 chars) + File Upload ×2 + XML Security: 3,969 chars. Laravel, Symfony and C toolchain gone |

The knowledge base has no path-traversal sheet, so for CWE-22 the MITRE record
is the only guidance that is about path traversal itself.

Alternate terms (R1): 6 of the scan's 9 CWEs have them.

| CWE | Alternate terms |
| --- | --- |
| 22 | Path traversal, Directory traversal, Path transversal |
| 78 | Shell injection, Shell metacharacters, OS Command Injection |
| 79 | Cross-site Scripting, XSS, HTML Injection, three named XSS types, CSS |
| 89 | SQL Injection, SQLi |
| 90 | LDAP Injection |
| 643 | XPath Injection |
| 326, 328, 501 | none (and CWE-501 has no MITRE mitigations, so its MITRE chunk is the description only) |

**Known limits, left unchanged** so that step 4 differs from `2-after` in
retrieval only:

- *Filling stops at the first chunk that does not fit.* CWE-89 stops at 2,965
  of 4,000 characters: the next chunk (1,785 chars) does not fit, although the
  three after it (470, 57 and 624 chars) would have.
- *The MITRE chunk is capped at 1,500 characters.* For CWE-22 only the first
  mitigation fits ("accept known good" input validation); MITRE's later
  mitigations are cut.

**For the next item (the retrieval-quality check):**

- Split chunks have new IDs (`<chunk_id>.1`, `.2`, …), so any that reach the
  top results need grading; chunks within 1,800 characters keep their IDs and
  grades.
- CWE-79's alternate terms include "CSS" (MITRE's old abbreviation for
  cross-site scripting). Check whether it pulls in chunks about CSS styling.

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
