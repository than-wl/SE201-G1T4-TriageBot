# TriageBot experiments

This is the single source of truth for TriageBot's evaluation. Each experiment
below asks one question, changes one group of settings, and is measured on
one frozen set of cases. Every run is saved with a record of exactly what
produced it, and can be shown and re-scored from the terminal for free.

Earlier results ([archive/FINAL_RESULTS.md](archive/FINAL_RESULTS.md),
[archive/IMPROVEMENT_EXPERIMENT_LOG.md](archive/IMPROVEMENT_EXPERIMENT_LOG.md)) record
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
| `4-after` | council | ±60 lines + related code, semantic guidance | 95.0% | 1 | 44 | 4 | 1.40 | 21.9 |

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

**5. Semantic retrieval replaces the hand-made table without losing accuracy
(step 4).** The guidance now comes from search over the OWASP sheets, anchored
on the alert's MITRE record, with the set-up fixed in advance. On the
comparison set it matched step 2 within the noise floor (F1 96.0% vs 95.0%; one
real path traversal dismissed by all three reviewers with a plausible but
incomplete argument). The free check showed why it scales: for 10 weaknesses
outside the benchmark, the right sheet reached the guidance in all 10, with no
hand-written entries, and 5 of the 10 have no row in the old table. It also
showed that a relevance score is a proxy: the set-up that scored best on it
returned the most wrong-language advice.

Semantic retrieval is therefore the default and the final version (design
decision 29).

**6. On 120 unseen cases the final version holds, and the council is the safe
choice (step 6).** The council scored F1 96.7% (95.0% on the comparison set),
removed 57 of 60 false alarms and dismissed 1 of 60 real vulnerabilities; the
single agent removed the same 57 but dismissed 10. Projected over the whole
benchmark for the four types, Semgrep plus the council keeps precision at
97.1% against Semgrep's 59.6%, while recall moves only from 86.0% to 85.0%:
almost every remaining miss is one Semgrep never flagged. Semgrep is now the
bottleneck.

**7. The council's verdicts follow the code; the single agent's often do not
(step 5).** In 22 pairs, one character was changed so that the right answer
flipped while Semgrep's alert stayed the same. The council flipped its verdict
correctly in all 22 (mutation score 100%); the single agent in 8 of the 15
pairs it got right to begin with (53%), mostly by calling real cases safe. It
is the clearest evidence of what the council's extra cost buys.

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
| `pilot` | development | 100 | CWE-89: 50 real, 50 safe | Exactly the checkpoint sample; the builder checks it against `archive/checkpoint/checkpoint-100/` | `2b633145f724…` |
| `comparison` | development | 96 | CWE-22, 78, 79, 89: 24 each (12 real, 12 safe) | Excludes every pilot case | `311c5e73b3e9…` |
| `final-test` | test | 120 | CWE-22, 78, 79, 89: 30 each (15 real, 15 safe) | Excludes every retired case | `3182ce45723d…` |
| retired | both | 407 | Case IDs only | Every case used by an earlier run | — |
| `mutation` | development | 22 pairs | CWE-22: 2 real→safe, 3 safe→real; CWE-78: 3+3; CWE-79: 3+3; CWE-89: 3+2 | Step 5: one constant condition decides the answer; excludes pilot, comparison and retired cases ([step 5](#step-5-does-the-verdict-follow-the-code)) | `bbaee0f17903…` |

- The **exploration set** is the pilot plus any other development case. This
  is where we read failures and try ideas.
- The **comparison set** is frozen and only measured, never tuned on.
- The **final test** is run once, after the code freeze.
- **Retired** cases were used by earlier runs and are kept only as a record.
- The **mutation set** pairs each original with its one-character mutant. It
  holds no labels; the evaluation side takes each original's answer from the
  answer key and each mutant's as its flip.

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
  weakness (design decision 21). Outside experiments, `semantic` with the
  improved set-up is the default (design decision 29); every profile sets its
  own retrieval, so the default does not change any profile.
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
| 5 | Does the verdict follow the code? | `semantic` profile, single agent and council, on the originals | the same, on their mutants | mutation |
| 6 | Headline result | `semantic` profile, single agent (run once) | `semantic` profile, council (run once) | final test |

Cost estimates use US$0.004 per case for the single agent and US$0.016 per
case for the council (`config.EXPERIMENT_COST_PER_CASE`), except steps 5 and 6,
which use the per-case costs recorded in steps 1b and 4. The real spend is recorded
in each run manifest.

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
- **Status:** run on 9 Nov 2026.
- **Commands:**
  - show: `python -m triagebot experiment show 4`
  - replay: `python -m triagebot experiment replay 4`
  - re-run: `python -m triagebot experiment run 4`
- **Result:** council F1 96.0% → 95.0%; real vulnerabilities dismissed 0 → 1 of 48; false alarms removed 44 → 44 of 48; sent to a human 4 → 4 of 96; cost US$1.37 → 1.40; failed model calls 1 → 4 of 288.
- **Finding:** accuracy holds, within the noise floor. Only two cases changed
  outcome, both path traversal (CWE-22):
  - `BenchmarkTest00001`, a real vulnerability, went from kept to sent to a
    human because the Chair's answer could not be parsed. Both specialists had
    called it real. This is a model-call failure, not a retrieval effect.
  - `BenchmarkTest01983`, a real vulnerability, was dismissed. In `2-after`
    both specialists had already called it a false alarm and the Chair
    overruled them. In `4-after` all three agreed it was safe, arguing that an
    HTTP header *name* cannot contain `/` or `\`. The argument sounds right
    but is incomplete: `..` is a legal header name and still climbs one
    directory. One case cannot be traced to the guidance; it is the Chair's
    safety net not firing.

  By the rule agreed in advance, semantic retrieval holds accuracy (one case of
  96, inside the noise floor of two or more) while removing the hand-made table
  and covering any CWE MITRE knows. Failed model calls rose from 1 to 4 of 288
  (a parse failure, a cut-off answer and an HTTP 400 among them); only one
  changed an outcome. Too few to call a trend; watched in step 6.

  The hand-made table has rows for 6 of the 9 CWE numbers in the recorded scan;
  adding rows would fix this scan, but every new CWE needs a new row, which is
  the maintenance cost semantic retrieval removes.
- **Decision:** semantic retrieval with this set-up is now the default and the
  final version (design decision 29). The map remains available as
  `RETRIEVAL_MODE = "map"` and in the step 1 to 3 profiles.
- **Dropped for time:** the planned guidance-off run ("does guidance matter at
  all?": the same council with no retrieved guidance) was not run. It is listed
  under [Future work](#future-work).

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

#### Retrieval-quality check (free, no model calls)

Did the set-up rules make semantic search return better guidance, and does it
find the right guidance for weaknesses outside the benchmark? This uses only
the local embedder. It does not measure verdict accuracy; that is the paid run.
Each configuration runs through the same code as `retrieve()` and `--explain`:
`original` is all five rules off (decision 21), `+R1` to `+R5` add one rule
each, and `improved` is the `semantic` profile.

- **Search ranking:** the top 6 searched chunks by cosine, ignoring the budget
  (the MITRE chunk is attached by ID, never searched).
- **Pack:** what `retrieve()` returns (4,000 characters, at most 6 chunks).
- **Grades:** 2 = guidance about this weakness, 1 = adjacent, 0 = not relevant;
  precision counts grade 2 only. The 129 original labels (CWE, chunk) were
  extended by 24 chunks graded blind (`verification/relevance_labels_added.json`), listed by
  `--phase list` without configuration, rank or score. The MITRE chunk is not
  graded, so grade counts and grade-2 characters cover OWASP chunks only.
- **Wrong platform:** chunks from sheets `scope.json` tags with a platform
  other than Java, or excludes as retired or the attack catalogue. The rubric
  grades topic, not platform (a FastAPI chunk about SQL injection is a 2), so
  rule R3's effect shows in this column, not in precision.

**Part A: the 9 scan CWEs, macro average** (wrong platform: total over the 9)

| Configuration | P@3 | P@6 | Mean grade | MITRE in pack | OWASP chunks | Grade 2 | Grade ≥1 | Pack chars | Grade-2 chars | Wrong platform, search | Wrong platform, pack |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `original` | 0.63 | 0.54 | 1.33 | 0 of 9 | 4.1 | 2.4 | 3.4 | 3,203 | 2,173 | 5 | 3 |
| `+R1` | 0.70 | 0.69 | 1.59 | 0 of 9 | 4.2 | 3.2 | 4.0 | 3,281 | 2,598 | 8 | 6 |
| `+R2` | 0.63 | 0.54 | 1.33 | 9 of 9 | 2.9 | 1.6 | 2.6 | 3,392 | 1,475 | 5 | 2 |
| `+R3` | 0.56 | 0.48 | 1.24 | 0 of 9 | 4.2 | 2.2 | 3.4 | 3,208 | 1,958 | 0 | 0 |
| `+R4` | 0.63 | 0.56 | 1.39 | 0 of 9 | 4.3 | 2.6 | 3.7 | 3,373 | 2,202 | 6 | 4 |
| `+R5` | 0.63 | 0.54 | 1.33 | 0 of 9 | 4.1 | 2.4 | 3.4 | 3,203 | 2,173 | 5 | 3 |
| `improved` | 0.67 | 0.57 | 1.44 | 9 of 9 | 3.1 | 1.8 | 2.9 | 3,172 | 1,135 | 0 | 0 |

`+R5` returns exactly what `original` returns (all 9 CWEs have valid MITRE
records), as expected.

**Part A per CWE, original → improved**

| CWE | P@3 | P@6 | Mean grade | MITRE chars | Grade-2 / OWASP chunks in pack | Pack chars | Grade-2 chars | Wrong platform, search / pack |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 22 | 0.67 → 0.00 | 0.50 → 0.00 | 1.33 → 0.50 | 0 → 1,290 | 2/3 → 0/3 | 3,357 → 3,969 | 1,928 → 0 | 3/2 → 0/0 |
| 78 | 0.67 → 1.00 | 0.50 → 0.83 | 1.00 → 1.83 | 0 → 1,376 | 3/5 → 2/2 | 3,765 → 2,740 | 2,665 → 1,364 | 0/0 → 0/0 |
| 79 | 0.33 → 1.00 | 0.33 → 1.00 | 0.83 → 2.00 | 0 → 1,458 | 2/6 → 5/5 | 2,061 → 3,776 | 1,361 → 2,318 | 1/1 → 0/0 |
| 89 | 0.67 → 0.67 | 0.67 → 0.67 | 1.67 → 1.67 | 0 → 1,343 | 1/2 → 0/1 | 2,256 → 2,965 | 634 → 0 | 1/0 → 0/0 |
| 90 | 1.00 → 1.00 | 1.00 → 1.00 | 2.00 → 2.00 | 0 → 1,444 | 3/3 → 2/2 | 3,731 → 3,976 | 3,731 → 2,532 | 0/0 → 0/0 |
| 326 | 0.33 → 0.33 | 0.33 → 0.33 | 1.00 → 1.00 | 0 → 309 | 2/5 → 2/5 | 2,525 → 2,834 | 1,653 → 1,653 | 0/0 → 0/0 |
| 328 | 1.00 → 1.00 | 0.50 → 0.50 | 1.33 → 1.33 | 0 → 1,468 | 3/3 → 1/1 | 3,881 → 3,256 | 3,881 → 1,788 | 0/0 → 0/0 |
| 501 | 0.00 → 0.00 | 0.00 → 0.00 | 0.83 → 0.83 | 0 → 94 | 0/4 → 0/4 | 3,554 → 3,648 | 0 → 0 | 0/0 → 0/0 |
| 643 | 1.00 → 1.00 | 1.00 → 0.83 | 2.00 → 1.83 | 0 → 564 | 6/6 → 4/5 | 3,700 → 1,383 | 3,700 → 559 | 0/0 → 0/0 |

**CWE-79 "CSS" check:** no chunk about CSS styling appears under `+R1` or
`improved`. Three CWE-79 chunks mention CSS, all as an XSS output context and
all graded 2: `DOM_based_XSS_Prevention_Cheat_Sheet#001` (`+R1`) and its piece
`#001.1` (`improved`), and `Java_Security_Cheat_Sheet#018`, which `original`
also returns.

**Part B: weaknesses outside the benchmark** (no grading needed). The list was
fixed in advance: CWEs not in the scan for which the knowledge base has a sheet
dedicated to that one weakness. All 10 have valid MITRE 5.0 records.

**Expected sheet in pack: 9 of 10 (original) vs 10 of 10 (improved).**

| CWE | Expected sheet | In the map? | Original: in pack (first rank; chunks from it) | Improved: in pack (first rank; chunks from it) |
| --- | --- | --- | --- | --- |
| 918 | `Server_Side_Request_Forgery_Prevention_Cheat_Sheet` | yes | no (6; 0 of 3) | yes (2; 1 of 2) |
| 611 | `XML_External_Entity_Prevention_Cheat_Sheet` | yes | yes (2; 1 of 4) | yes (2; 3 of 5) |
| 502 | `Deserialization_Cheat_Sheet` | no | yes (1; 4 of 6) | yes (1; 4 of 5) |
| 352 | `Cross-Site_Request_Forgery_Prevention_Cheat_Sheet` | no | yes (1; 1 of 4) | yes (1; 1 of 3) |
| 601 | `Unvalidated_Redirects_and_Forwards_Cheat_Sheet` | no | yes (1; 3 of 4) | yes (1; 4 of 4) |
| 1336 | `Server_Side_Template_Injection_Prevention_Cheat_Sheet` | yes | yes (1; 4 of 4) | yes (1; 4 of 5) |
| 915 | `Mass_Assignment_Cheat_Sheet` | yes | yes (4; 1 of 6) | yes (1; 3 of 4) |
| 1021 | `Clickjacking_Defense_Cheat_Sheet` | no | yes (1; 3 of 4) | yes (1; 2 of 2) |
| 434 | `File_Upload_Cheat_Sheet` | yes | yes (2; 5 of 6) | yes (1; 4 of 4) |
| 943 | `NoSQL_Security_Cheat_Sheet` | no | yes (3; 1 of 4) | yes (1; 1 of 5) |

None of these needed a hand-written entry; 5 of the 10 are not in
`cwe_map.json` at all.

**Rerun** (no model calls; the catalogue and vector store must be prepared):

```bash
python verification/semantic_setup_check.py --phase score
```

Full tables, every configuration per CWE, and provenance (catalogue, embedding
model, `scope.json` and label-file hashes, git commit):
`evidence/retrieval/semantic_setup_check.md` and `.json`.

**Caveats**

- The grades are AI-produced and unreviewed: the original set by Hong Yi's AI
  run, the added set by Claude, done blind.
- There is one grader per label.
- There are only 9 CWEs in part A.
- This measures topic relevance, not whether the guidance changes verdicts
  (that is the paid run, item 3).

**Finding:** overall search quality barely moves (P@6 0.54 → 0.57), but the
rules pull in different directions, and the measure decides what you see.

- *Alternate terms (R1) are the strongest single rule* (P@6 0.54 → 0.69). The
  common names ("XSS", "OS command injection") are the words the sheets use:
  CWE-79 goes from 2 to 5 on-topic passages in the pack.
- *The platform rule (R3) lowers precision* (0.54 → 0.48), because the PHP and
  Python passages it removes are on-topic. It is also the only rule that
  removes wrong-platform advice (5 → 0 in search). The relevance grade is a
  proxy: it cannot see that Laravel advice does not apply to Java. On that
  measure alone, `+R1` would win while returning the most wrong-platform
  passages (6 in the pack).
- *The MITRE record (R2) costs budget.* Every CWE gets an authoritative
  passage, but OWASP passages in the pack fall from 4.1 to 3.1 and grade-2
  OWASP characters from 2,173 to 1,135. Combined with the filling rule, the
  SQL injection pack is the MITRE record plus one "how to test" passage, and
  the XPath pack shrinks to 1,383 characters.
- *Beyond the benchmark, it scales.* For 10 weaknesses outside the scan, the
  dedicated sheet reached the pack for 10 of 10 (9 of 10 before), with no
  hand-written entries; 5 of the 10 have no row in the hand-made table.

The set-up was not changed after seeing these results (design decisions 26
and 28). Whether trading OWASP passages for applicability and coverage changes
verdicts is what the paid run measures.

### Step 5: Does the verdict follow the code?

- **Question:** when a case's code is changed so that its right answer flips
  (safe becomes vulnerable, or the reverse), does TriageBot's verdict flip too?
  A reviewer that reads the code should follow the change; one that answers
  from surface cues (the file name, the sink, the guidance) will not.
- **What was wrong before.** The old test (`archive/verification/mutation_check.py`,
  kept as a record) could not answer this:
  1. *Different baselines.* The originals were not judged the same way for
     each reviewer: the council's "original" results came from a version of the
     script that did not support council mode.
  2. *Missing related code.* Each case ran from a temporary folder holding only
     the mutated file, so the related source the `evidence` profile reads
     (helper classes, scripts) was missing. Mutants were judged on less evidence
     than real runs.
  3. *Too few cases, one direction only.* Five hand-picked cases, all safe
     becoming vulnerable.
- **The pattern.** Many Benchmark cases decide their answer with one constant
  condition, for example
  `bar = (7 * 42) - num > 200 ? "This should never happen" : param;`, where
  `num` is a constant set a few lines above. If the condition is true, `bar` is
  the constant (safe); if false, it is the user input (vulnerable). The mutation
  swaps `>` for `<` in that one expression and changes nothing else. It is the
  same length, so no line number moves, and it flips which branch runs, so the
  right verdict flips. `BenchmarkTest01983`, which the council dismissed in
  step 4, is this pattern (it is a comparison case, so it is not in this set).
- **Eligibility** (all must hold; `triagebot/nodes/ingest/mutation_set.py`):
  - the case is in the development half and not in the pilot, the comparison
    set or the retired list (so never in the final test);
  - its type is CWE-22, 78, 79 or 89, with a CWE-matching Semgrep alert in the
    recorded scan (the same alert rule as the other sets);
  - its file, with comments stripped, holds exactly one ternary of the form
    `(<int> * <int>) <+|-> num > 200 ? "<string>" : <identifier>` and exactly
    one `int num = <int>;`, declared before it;
  - *the flip proof:* evaluated in Python with the file's own constants, the
    condition really flips and is not tied at exactly 200 (at 200, neither `>`
    nor `<` holds, so nothing would flip);
  - *the condition decides the answer* (checked against the answer key, on the
    evaluation side only): real cases whose condition is false, so the input
    flows through, and safe cases whose condition is true, so the constant is
    used. Cases whose label does not match the branch are left out: they are
    safe or vulnerable for another reason, and flipping the branch would not
    flip the answer.
- **Selection:** 3 per direction (real → safe, safe → real) per type, drawn
  with seed 201: 24 pairs planned. Two strata have only 2 eligible cases
  (CWE-22 real → safe, CWE-89 safe → real), so the set has **22 pairs**; the
  rules were not widened. See [the case sets](#the-case-sets).
- **Same evidence for both.** Before: the 22 originals, from the Benchmark
  checkout. After: the 22 mutants, each from its own *overlay root*: a copy of
  the checkout's `src/main/java` and `src/main/resources` (the trees the
  evidence code reads) with only the mutated file replaced, built under
  `Context/tmp/mutation-overlay/` (git-ignored, about 18 MB per case) before
  any call. Related source, helpers and scripts resolve exactly as in normal
  runs. A test builds the evidence pack of an original and its mutant and
  checks that they differ only on the mutated line. The same check on all 22
  real pairs (free) found the mutated line and its `int num` in every pack.
  Comments are stripped (`strip_comments`), so giveaway comments such as
  "assigns param to bar on false condition" never reach the AI; nothing that
  exists only in a comment reached any of the 22 prompts. The string literals
  stay, because they are code: a real → safe mutant uses the constant
  `"This should never happen"`.
- **Both sides:** the final version (the `semantic` profile), single agent and
  council, on one commit. `experiment run 5` refuses uncommitted changes to
  tracked files, and a commit other than the one a saved step 5 run recorded.
  Each case's record holds the SHA-256 of the file it was judged on.
- **Scoring** (as in Week 10). A pair counts only if the reviewer got the
  original right (the precondition). Then the mutant is
  - *killed* if its verdict is the flipped right answer;
  - *survived* if its verdict is unchanged;
  - *escalated* if it was sent to a human (reported separately; not a kill).

  Mutation score = killed / pairs that meet the precondition, per
  configuration (B single agent, C council, D validated council) and per
  direction. Pairs excluded because the original was wrong are reported too.
  The after side's own table scores the mutants against the flipped answers;
  the mutation score is in `5-after/mutation_score.json` and in
  `experiment show 5`.
- **Cost estimate:** 4 runs of 22 cases (both sides, both modes), 176 calls
  (88 per side: 22 single + 66 council), about US$0.83, from the per-case
  costs recorded for step 6 (US$0.0043 single, US$0.0146 council; registry
  `cost_per_case`).
- **Status:** run on 9 Nov 2026.
- **Commands:**
  - rebuild the set (free; needs the Benchmark):
    `python -m triagebot.nodes.ingest.eval_sets mutation`
  - build the overlay roots (free; `run` also does it):
    `python -m triagebot.mutants build` (and `clean` to remove them)
  - run (paid, asks first; commit first): `python -m triagebot experiment run 5`
  - show: `python -m triagebot experiment show 5`
  - replay: `python -m triagebot experiment replay 5`
- **Result:** mutation score (killed / pairs whose original was judged right),
  22 pairs, US$0.83 in total:

  | | Single agent | Council (raw and validated) |
  | --- | ---: | ---: |
  | Originals judged right | 15 of 22 | 22 of 22 |
  | Killed (verdict flipped correctly) | 8 | 22 |
  | Survived (verdict unchanged) | 6 | 0 |
  | Escalated to a human | 1 | 0 |
  | **Mutation score** | **53.3%** | **100%** |
  | real → safe / safe → real | 4 of 4 / 4 of 11 | 11 of 11 / 11 of 11 |

  Before any mutation, the single agent already dismissed 7 of the 11 real
  originals; on the mutants that became real, it dismissed 6 of 11.
- **Finding:** on this pattern, the council follows the code and the single
  agent does not.
  - *The council killed all 22 mutants.* One changed character flipped its
    verdict every time, in both directions, with the same alert from Semgrep.
  - *The single agent leans towards "safe" on this pattern.* It called 7 of 11
    real originals safe, and when a mutation made a safe case real it kept
    calling it safe in 6 of 11 pairs. Its verdict did not follow the condition
    that decides the answer. This matches step 6, where it dismissed 10 of 60
    real vulnerabilities.
  - *100% here is not a guarantee.* In step 4 the council dismissed
    `BenchmarkTest01983`, a real case with this same pattern, with a plausible
    but incomplete argument. 22 pairs show the council usually evaluates the
    condition, not that it always does.
  - *The old mutation test's conclusion survived a fair rebuild; its numbers
    did not.* It reported 0 of 5 against 5 of 5 on mismatched baselines. With
    the same commit, evidence and settings on both sides and both directions,
    the gap is 53% against 100%.

### Step 6: Headline result

- **Question:** how well does the final system do on cases it has never seen?
- **Run:** the final version, the `semantic` profile (design decision 29), with
  the single agent (run `6-before`) and the council (run `6-after`), run once
  after the code freeze; nothing is changed after it. `experiment show 6` puts
  them side by side (columns "Single B", "Council C", "Council D") and adds a
  table per weakness (CWE).
- **Case set:** final test (120 cases: 30 per type, 15 real and 15 safe).
- **Cost estimate:** 480 calls (120 single + 360 council), about US$2.27:
  US$0.52 single + US$1.75 council. Taken from the recorded per-case costs on
  the comparison set: the council's US$1.3955 for 96 cases in `4-after`, and
  the single agent's US$0.4146 for 96 cases in `1b-before` (the same evidence;
  step 4 ran the council only). The registry holds them as `cost_per_case`
  (US$0.0043 and US$0.0146).
- **Status:** run on 9 Nov 2026 (commit `e39e415`), once.
- **Two guards** protect the final test, which is run once. They apply to any
  step whose case set is the final test, before any question or model call:
  1. *A dirty tree is refused.* With uncommitted changes to tracked files,
     `experiment run 6` stops: commit first, because the final test records
     the commit it ran on.
  2. *A second run is refused.* Once a run has results, a fresh run does not
     start. Resuming an interrupted run still works (it is the same run), and
     so does extending a `--limit` run. Starting over needs
     `--i-know-this-reruns-the-final-test`; the old results are then moved to
     `<run>-superseded-<time>/`, not deleted.
- **Commands:**
  - run (paid, asks first; commit first): `python -m triagebot experiment run 6`
  - show: `python -m triagebot experiment show 6`
  - replay: `python -m triagebot experiment replay 6`
- **Whole system vs Semgrep alone** (free, after the run):
  `python verification/whole_system.py --mode council` and
  `python verification/whole_system.py --mode single`. The script reads the
  recorded scan, the answer key and the finished run's evaluation, and makes
  no model calls. Semgrep alone, over the whole benchmark for the four types
  (CWE-matched): 668 real vulnerabilities with a matching alert, 453 safe cases
  with one, 109 real vulnerabilities with none, so precision 59.6%, recall
  86.0%, F1 70.4%. The whole system is a projection: for each type, the final
  test's share of real cases kept (a case sent to a human counts as kept) and
  share of safe cases removed are applied to Semgrep's counts. Kept real =
  TP × keep rate; kept safe = FP × (1 − removal rate); missed = FN + TP ×
  (1 − keep rate). Recall can only fall: TriageBot never sees what Semgrep
  missed (FN), so Semgrep's recall is its ceiling. Output:
  `evidence/whole_system/<run>.json` and `.md`. Before step 6 has run, the
  script prints Semgrep alone and says to run step 6 first.
- **Result:**

  | Measure | Single agent (`6-before`) | Council, validated (`6-after`) |
  | --- | ---: | ---: |
  | Precision | 94.3% | 95.2% |
  | Recall | 83.3% | 98.3% |
  | F1 | 88.5% | 96.7% |
  | Real vulnerabilities dismissed (of 60) | 10 | 1 |
  | False alarms removed (of 60) | 57 | 57 |
  | Sent to a human (of 120) | 2 | 1 |
  | Invalid answers | 0 | 0 |
  | Cost (US$) / mean latency (s) | 0.53 / 9.9 | 1.76 / 18.8 |

  Per type, the council's F1 is 96.8% (path traversal), 90.3% (OS command
  injection; its one dismissal), 100% (XSS) and 100% (SQL injection).

  Whole system vs Semgrep alone (projection, council):

  | | Semgrep alone | Semgrep + TriageBot council | Semgrep + single agent |
  | --- | ---: | ---: | ---: |
  | Precision | 59.6% | 97.1% | 96.6% |
  | Recall | 86.0% | 85.0% | 73.2% |
  | F1 | 70.4% | 90.6% | 83.3% |
  | False alarms left (of 453) | 453 | ≈20 | ≈20 |
  | Real vulnerabilities missed (of 777) | 109 | ≈117 | ≈208 |
- **Finding:** the design holds on cases nobody looked at, and the council's
  value is safety.
  - *No sign of tuning to the comparison set.* The council scored F1 96.7% on
    the final test against 95.0% (step 4) and 96.0% (step 2) on the
    comparison set.
  - *The council's safety advantage grows on unseen cases.* Both reviewers
    removed 57 of 60 false alarms, but the single agent dismissed 10 of 60
    real vulnerabilities against the council's 1. On the comparison set the
    gap was 3 against 0. The single agent is cheaper (US$0.53 vs US$1.76) and
    faster (9.9 s vs 18.8 s), but every dismissed real vulnerability is a
    silent miss.
  - *Semgrep is now the bottleneck.* Adding the council would cut false alarms
    from 453 to about 20 (precision 59.6% → 97.1%) while recall falls only
    from 86.0% to 85.0%. Of the about 117 real vulnerabilities the whole system
    misses, 109 are ones Semgrep never flagged. The next gain is in the first
    stage (rules that catch more), not the second.

## Future work

- **Does guidance matter at all?** The same council with no retrieved guidance,
  on the comparison set. Planned for step 4 and dropped for time. It would show
  how much of the accuracy comes from the guidance and how much from the code
  the AI is shown.

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

The old samples and results are archived in [archive/](archive/README.md):

- `archive/checkpoint/checkpoint-100/`: the checkpoint run (the pilot's 100
  SQL-injection cases), with the checkpoint report;
- `archive/evidence/original-final-120/`: the first frozen 120-case final evaluation;
- `archive/evidence/comparison-66/`: the 66-case improvement comparison and its re-runs;
- `archive/evidence/fresh-120/`: the second 120-case evaluation.

They changed several things at once and were not recorded as one change per
run. Their cases are retired (`data/samples/retired_cases.json`, 407 cases),
and they are not used for any new claim. `archive/FINAL_RESULTS.md` and
`archive/IMPROVEMENT_EXPERIMENT_LOG.md` describe them and stay unchanged apart
from a note at the top.
