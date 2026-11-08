# Frozen case sets

These files fix *which* OWASP Benchmark cases each experiment is measured on.
They are built once, committed, and never edited by hand. The experiments that
use them are described in [EXPERIMENTS.md](../../EXPERIMENTS.md).

## Why we split the cases at all

TriageBot trains no model, but we tune it: we read the cases it gets wrong
and change prompts, evidence and settings. A change made after reading a
case tends to fix *that* case. Measured on the same cases, the change then
looks better than it really is. So the cases we read and tune on are kept
apart from the cases we report.

## The sets

| Set | Half of the split | Cases | Composition | What it is for |
| --- | --- | ---: | --- | --- |
| `pilot` | development | 100 | SQL injection (CWE-89): 50 real, 50 safe | The start of the **exploration set**. It is exactly the checkpoint sample (`archive/checkpoint/checkpoint-100/`). |
| `comparison` | development | 96 | CWE-22, CWE-78, CWE-79, CWE-89: 24 each (12 real, 12 safe) | The **comparison set**. Frozen. Steps 1 to 4 are measured on it, and nobody tunes on it. |
| `final-test` | test | 120 | CWE-22, CWE-78, CWE-79, CWE-89: 30 each (15 real, 15 safe) | The **final test**. Run once, after the code freeze (step 6). |
| `retired_cases.json` | both | 407 | Case IDs only | **Retired** cases: used by earlier runs, kept only as a record. |
| `mutation` | development | 22 pairs | CWE-22: 2 real→safe, 3 safe→real; CWE-78: 3+3; CWE-79: 3+3; CWE-89: 3+2 | The **mutation set** (step 5): each original with its one-character mutant (`num > 200` to `num < 200`), which flips the right answer. No pilot, comparison or retired case. |

- **Exploration set:** the pilot plus any other development case that is in no
  frozen set. This is where we read failures and try ideas.
- **Comparison set:** only measured. If a failure here suggests an idea, the
  idea is tried on exploration cases first.
- **Final test:** run once. It shares no case with the retired list (the
  builder checks this and stops if it ever does).
- **Retired cases:** every case in a `selected_alerts.json` under `archive/checkpoint/`
  or `archive/evidence/` (where the earlier runs were moved from `evidence/`),
  plus the 287-case audit list in `archive/evidence/fresh-120/prior_case_audit.json`
  (which adds the one OpenRouter smoke-test case). They are never used for a
  new claim.
- **Mutation set:** 3 pairs per direction per type were planned (24); two
  strata have only 2 eligible cases, so it holds 22. The rules were not
  widened (EXPERIMENTS.md, step 5).

## Files

Each set has two files:

- `<set>.json`: the alerts the model sees, in the same shape as
  `selected_alerts.json`. Each alert has only the scanner's fields (case ID,
  file, rule, CWE, lines, message). There are **no labels**: the answer key
  never reaches a model-side file (design decision 7). Tests check this.
- `<set>.manifest.json`: how the set was built: the rule, the seed (201), the
  test fraction (0.5), the scan file and its SHA-256, the answer key's SHA-256,
  the sample file's own SHA-256, the case count, and the count of real and
  safe cases per CWE. These totals are evaluation-side; there is no per-case
  label.

`mutation.json` also holds, per pair, the file, the line, the original and
mutated expression, the evaluated values (the constants, the value of the
expression, the condition before and after) and the SHA-256 of the original
and mutated Java file. It holds no label either: the evaluation side takes each
original's answer from the answer key and each mutant's as its flip. Its
manifest counts the eligible and selected pairs per type and direction.

Fingerprints are SHA-256 hashes of the file **with LF line endings**, so they
are the same on Windows and macOS even if Git checks a file out with CRLF.
`.gitattributes` keeps these files LF on checkout as well.

| Set | SHA-256 |
| --- | --- |
| `pilot` | `2b633145f724df28b6fffb112bbcce8304fbfa73d14aaa4100f4c8e7bebc578d` |
| `comparison` | `311c5e73b3e909af005711a03a1aa04be69b060a13fe1923dc16dee615d7e91a` |
| `final-test` | `3182ce45723df68a6932c2dfbf747811cf60a5fee3170c172a1222b575f7c543` |
| `mutation` | `bbaee0f179038a4fccdae520f45ab885df812d69b0a984e822b57b1880d0f7cc` |

## How they are built

```bash
python -m triagebot.nodes.ingest.eval_sets build
```

The builder needs the OWASP Benchmark answer key (it balances the draw) and
reads the recorded Semgrep scan `data/semgrep/semgrep-owasp-p-java-1.178.0.json`.
It uses the fixed development/test split (seed 201, half of each category and
label in each part, design decision 18) and picks **one CWE-matching Semgrep
alert per case**: the alert with the lowest start line, then rule ID. Cases
are drawn with seed 201, half real and half safe. It makes no model calls.

The builder stops with an error, and writes nothing, if:

- the pilot differs from `archive/checkpoint/checkpoint-100/selected_alerts.json`;
- a category has too few eligible cases;
- the final test, or the comparison set, would contain a retired case.

Running it twice gives byte-identical files. Rebuilding should never be needed;
if the scan, the answer key or the split ever changed, the fingerprints would
change too, and every earlier result would stop being comparable.

The mutation set has its own command, because it also reads the Benchmark
source (only the development-half candidates' files, after the split filter, so
no final-test case is opened):

```bash
python -m triagebot.nodes.ingest.eval_sets mutation
```

It reads the pilot and comparison sets from this folder to exclude them, and
writes only `mutation.json` and `mutation.manifest.json`.
